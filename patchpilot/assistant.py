"""Evidence-only assistant. OWNER: Person 3.

Flow: retrieve(question) -> list[Evidence] -> LLM (JSON) -> verify_citations -> Answer.
Rule: no evidence => refuse. Every cited id must have been retrieved.
"""
from __future__ import annotations

import re
import sqlite3

from .contracts import Answer, Evidence

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


STOP_WORDS = {
    "a", "about", "an", "and", "are", "as", "at", "be", "by", "can",
    "do", "for", "from", "how", "in", "is", "it", "me", "my", "no", "not",
    "of", "on", "or", "our", "tell", "the", "there", "to", "was", "we",
    "what", "where", "which", "who", "why", "will", "with", "would",
}


def _sanitize_fts_query(text: str) -> str:
    """Sanitise free-text for SQLite FTS5 query."""
    words = re.findall(r"[a-zA-Z0-9]+", text)
    filtered = [w for w in words if w.lower() not in STOP_WORDS and len(w) > 1]
    if not filtered:
        return ""
    return " AND ".join(f'"{w}"' for w in filtered)


def _build_cve_evidence(conn: sqlite3.Connection, cve_id: str, kind_filter: set[str] | None = None) -> list[Evidence]:
    """Gather evidence items for a known CVE."""
    from . import scoring

    evs: list[Evidence] = []
    row = conn.execute("SELECT description, cvss, cwe FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()
    if not row:
        return evs

    if not kind_filter or "desc" in kind_filter:
        if row["description"]:
            evs.append(Evidence(
                id=f"{cve_id}:desc",
                cve_id=cve_id,
                kind="desc",
                text=f"{cve_id}: {row['description']}",
                source="cve",
            ))

    if not kind_filter or "score" in kind_filter:
        try:
            ex = scoring.explain(conn, cve_id)
            comp_strs = [
                f"{c['factor'].upper()}={c['raw']} (contrib {c['contribution']:.4f})"
                for c in ex["components"]
            ]
            text = f"{cve_id} is in tier {ex['tier']} with risk score {ex['score']:.4f}. Factors: {', '.join(comp_strs)}."
            if ex["kev_override"]:
                text += " Forced to Critical tier due to CISA KEV listing."
            evs.append(Evidence(
                id=f"{cve_id}:score",
                cve_id=cve_id,
                kind="score",
                text=text,
                source="scoring",
            ))
        except Exception:
            pass

    if not kind_filter or "kev" in kind_filter:
        k_row = conn.execute("SELECT date_added, due_date FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
        if k_row:
            evs.append(Evidence(
                id=f"{cve_id}:kev",
                cve_id=cve_id,
                kind="kev",
                text=f"{cve_id} is in CISA KEV (date added: {k_row['date_added']}, due: {k_row['due_date']}).",
                source="kev",
            ))

    if not kind_filter or "epss" in kind_filter:
        e_row = conn.execute("SELECT score, percentile FROM epss WHERE cve_id = ?", (cve_id,)).fetchone()
        if e_row:
            evs.append(Evidence(
                id=f"{cve_id}:epss",
                cve_id=cve_id,
                kind="epss",
                text=f"{cve_id} EPSS probability score is {e_row['score']:.4f} ({e_row['percentile']*100:.1f}th percentile).",
                source="epss",
            ))

    if not kind_filter or "fix" in kind_filter:
        fixes = conn.execute("SELECT url, kind FROM fix WHERE cve_id = ?", (cve_id,)).fetchall()
        if fixes:
            fix_items = [f"{f['kind']}: {f['url']}" for f in fixes]
            evs.append(Evidence(
                id=f"{cve_id}:fix",
                cve_id=cve_id,
                kind="fix",
                text=f"Fix links for {cve_id}: " + "; ".join(fix_items),
                source=fixes[0]["url"] or "fix",
            ))
        else:
            evs.append(Evidence(
                id=f"{cve_id}:fix",
                cve_id=cve_id,
                kind="fix",
                text=f"No fix link recorded for {cve_id}.",
                source="fix",
            ))

    if not kind_filter or "cwe" in kind_filter:
        if row["cwe"]:
            evs.append(Evidence(
                id=f"{cve_id}:cwe",
                cve_id=cve_id,
                kind="cwe",
                text=f"{cve_id} weakness type: {row['cwe']}.",
                source="cve",
            ))

    if not kind_filter or "asset" in kind_filter:
        matched = conn.execute(
            """SELECT a.name, a.criticality
               FROM asset a
               JOIN cve_product cp ON lower(a.vendor) = lower(cp.vendor) AND lower(a.product) = lower(cp.product)
               WHERE cp.cve_id = ?""",
            (cve_id,),
        ).fetchall()
        if matched:
            names = [f"'{m['name']}' (crit {m['criticality']})" for m in matched]
            evs.append(Evidence(
                id=f"{cve_id}:asset",
                cve_id=cve_id,
                kind="asset",
                text=f"{cve_id} affects assets: {', '.join(names)}.",
                source="asset",
            ))

    return evs


def retrieve(conn: sqlite3.Connection, question: str) -> list[Evidence]:
    """Build evidence from SQL (+ FTS5 for free text). (issue P3-1)"""
    from . import scoring

    q_clean = question.strip()
    q_lower = q_clean.lower()
    cve_matches = [m.upper() for m in CVE_RE.findall(q_clean)]

    # Intent 1: Explicit CVE(s) in question
    if cve_matches:
        known_cves = [
            cid for cid in cve_matches
            if conn.execute("SELECT 1 FROM cve WHERE cve_id = ?", (cid,)).fetchone()
        ]
        if not known_cves:
            return []

        evs: list[Evidence] = []
        is_fix_question = bool(re.search(r"\b(fix|patch|solution|remediation)\b", q_lower))
        is_why_question = bool(re.search(r"\b(why|ranked|ranking|score|priority|where)\b", q_lower))

        for cid in known_cves:
            if is_fix_question:
                evs.extend(_build_cve_evidence(conn, cid, kind_filter={"fix", "desc", "score"}))
            elif is_why_question:
                evs.extend(_build_cve_evidence(conn, cid, kind_filter={"score", "kev", "epss", "desc", "asset"}))
            else:
                evs.extend(_build_cve_evidence(conn, cid))
        return evs

    # Intent 2: Priority questions ("patch first", "priority", "top", "rank")
    if re.search(r"\b(patch first|priority|top|what to patch|what should we patch|rank|order)\b", q_lower):
        queue = scoring.ranked_queue(conn)
        top_n = queue.head(3)
        evs = []
        for _, row in top_n.iterrows():
            cid = row["cve_id"]
            ex = scoring.explain(conn, cid)
            comp_strs = [
                f"{c['factor'].upper()} contribution {c['contribution']:.4f}"
                for c in ex["components"]
            ]
            score_text = (
                f"{cid} is rank #{row['rank']} (tier: {row['tier']}, score: {row['score']:.4f}). "
                f"Factor breakdown: {', '.join(comp_strs)}."
            )
            if ex["kev_override"]:
                score_text += " Forced to Critical tier due to CISA KEV listing."
            evs.append(Evidence(
                id=f"{cid}:score",
                cve_id=cid,
                kind="score",
                text=score_text,
                source="scoring",
            ))

            if row["kev"]:
                k_row = conn.execute("SELECT date_added, due_date FROM kev WHERE cve_id = ?", (cid,)).fetchone()
                date_str = f"date added: {k_row['date_added']}" if k_row else "in KEV"
                evs.append(Evidence(
                    id=f"{cid}:kev",
                    cve_id=cid,
                    kind="kev",
                    text=f"{cid} is listed in CISA KEV ({date_str}).",
                    source="kev",
                ))

            if row["description"]:
                evs.append(Evidence(
                    id=f"{cid}:desc",
                    cve_id=cid,
                    kind="desc",
                    text=f"{cid}: {row['description']}",
                    source="cve",
                ))
        return evs

    # Intent 3: Multi-hop asset questions
    if re.search(r"\b(asset|assets|server|servers|infrastructure|my inventory)\b", q_lower):
        filter_kev = bool(re.search(r"\bkev\b", q_lower))
        join_kev_clause = "JOIN kev k ON k.cve_id = cp.cve_id" if filter_kev else "LEFT JOIN kev k ON k.cve_id = cp.cve_id"

        query = f"""
            SELECT DISTINCT
                a.name AS asset_name,
                a.criticality,
                cp.cve_id,
                c.description,
                k.date_added AS kev_date,
                f.url AS fix_url,
                f.kind AS fix_kind
            FROM asset a
            JOIN cve_product cp ON lower(a.vendor) = lower(cp.vendor) AND lower(a.product) = lower(cp.product)
            {join_kev_clause}
            JOIN cve c ON c.cve_id = cp.cve_id
            LEFT JOIN fix f ON f.cve_id = cp.cve_id
            ORDER BY cp.cve_id
        """
        rows = conn.execute(query).fetchall()
        if not rows:
            return []

        evs = []
        cve_groups: dict[str, list[sqlite3.Row]] = {}
        for r in rows:
            cve_groups.setdefault(r["cve_id"], []).append(r)

        for cid, group in cve_groups.items():
            first = group[0]
            asset_info = sorted({f"'{r['asset_name']}' (criticality {r['criticality']})" for r in group})
            evs.append(Evidence(
                id=f"{cid}:asset",
                cve_id=cid,
                kind="asset",
                text=f"Asset(s) affected by {cid}: {', '.join(asset_info)}.",
                source="asset",
            ))

            if first["kev_date"]:
                evs.append(Evidence(
                    id=f"{cid}:kev",
                    cve_id=cid,
                    kind="kev",
                    text=f"{cid} is listed in CISA KEV (date added: {first['kev_date']}).",
                    source="kev",
                ))

            fix_links = sorted({f"{r['fix_kind']}: {r['fix_url']}" for r in group if r["fix_url"]})
            if fix_links:
                evs.append(Evidence(
                    id=f"{cid}:fix",
                    cve_id=cid,
                    kind="fix",
                    text=f"Fix links for {cid}: {'; '.join(fix_links)}.",
                    source="fix",
                ))
            else:
                evs.append(Evidence(
                    id=f"{cid}:fix",
                    cve_id=cid,
                    kind="fix",
                    text=f"No fix link recorded for {cid}.",
                    source="fix",
                ))

            if first["description"]:
                evs.append(Evidence(
                    id=f"{cid}:desc",
                    cve_id=cid,
                    kind="desc",
                    text=f"{cid}: {first['description']}",
                    source="cve",
                ))

        return evs

    # Intent 4: General KEV question
    if re.search(r"\bkev\b", q_lower):
        kev_rows = conn.execute("SELECT cve_id, date_added, due_date FROM kev LIMIT 5").fetchall()
        if kev_rows:
            evs = []
            for kr in kev_rows:
                cid = kr["cve_id"]
                evs.append(Evidence(
                    id=f"{cid}:kev",
                    cve_id=cid,
                    kind="kev",
                    text=f"{cid} is in CISA KEV (date added: {kr['date_added']}, due: {kr['due_date']}).",
                    source="kev",
                ))
            return evs

    # Intent 5: Fallback FTS5 over cve_fts
    fts_term = _sanitize_fts_query(q_clean)
    if not fts_term:
        return []

    try:
        matches = conn.execute(
            "SELECT cve_id FROM cve_fts WHERE cve_fts MATCH ? LIMIT 3",
            (fts_term,),
        ).fetchall()
    except sqlite3.OperationalError:
        return []

    if not matches:
        return []

    evs = []
    for m in matches:
        cid = m["cve_id"]
        evs.extend(_build_cve_evidence(conn, cid, kind_filter={"desc", "score"}))
    return evs


def answer(question: str, conn: sqlite3.Connection | None = None) -> Answer:
    """Public entry point used by the app. Must never raise; refuse instead."""
    try:
        from . import db, llm

        conn = conn or db.connect()
        evidence = retrieve(conn, question)
        if not evidence:
            return {"answer": "I can't answer that from the loaded data.", "citations": [], "refused": True}

        # First attempt
        ans = llm.generate_llm_answer(question, evidence)
        if verify_citations(ans, evidence):
            cache_key = llm._compute_cache_key(question, evidence)
            llm.save_cached_answer(cache_key, ans)
            return ans

        # Retry once with verification feedback
        feedback = (
            f"Your citations {ans.get('citations', [])} failed verification. "
            f"Allowed evidence IDs: {[e.id for e in evidence]}. "
            f"Every cited ID must exist in the retrieved evidence, and all mentioned CVEs must match retrieved evidence."
        )
        retry_ans = llm.generate_llm_answer(question, evidence, retry_feedback=feedback)
        if verify_citations(retry_ans, evidence):
            cache_key = llm._compute_cache_key(question, evidence)
            llm.save_cached_answer(cache_key, retry_ans)
            return retry_ans

        # Fallback to refusal if verification still fails
        return {
            "answer": "I can't answer that from the loaded data.",
            "citations": [],
            "refused": True,
        }
    except Exception:
        return {
            "answer": "I can't answer that from the loaded data.",
            "citations": [],
            "refused": True,
        }


def verify_citations(ans: Answer, evidence: list[Evidence]) -> bool:
    """Baseline verifier (P3 extends). A non-refused answer is valid only if:
    1) it cites at least one id, 2) every cited id was retrieved,
    3) every CVE id mentioned in the text appears in the retrieved evidence."""
    if ans["refused"]:
        return not ans["citations"]
    ids = {e.id for e in evidence}
    cves = {e.cve_id.upper() for e in evidence if e.cve_id}
    if not ans["citations"] or not set(ans["citations"]) <= ids:
        return False
    mentioned = {m.upper() for m in CVE_RE.findall(ans["answer"])}
    return mentioned <= cves
