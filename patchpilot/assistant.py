"""Evidence-only assistant. OWNER: Person 3.

Flow: retrieve(question) -> list[Evidence] -> LLM (JSON) -> verify_citations -> Answer.
Rule: no evidence => refuse. Every cited id must have been retrieved.
"""
from __future__ import annotations

import re
import sqlite3

from .contracts import Answer, Evidence

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def retrieve(conn: sqlite3.Connection, question: str) -> list[Evidence]:
    """Build evidence from SQL (+ FTS5 for free text). (issue P3-1)"""
    raise NotImplementedError("P3-1: implement retrieval")


def answer(question: str, conn: sqlite3.Connection | None = None) -> Answer:
    """Public entry point used by the app. Must never raise; refuse instead."""
    try:
        from . import db

        conn = conn or db.connect()
        evidence = retrieve(conn, question)
    except NotImplementedError:
        return {"answer": "Assistant not implemented yet (see issue P3-1).", "citations": [], "refused": True}
    if not evidence:
        return {"answer": "I can't answer that from the loaded data.", "citations": [], "refused": True}
    raise NotImplementedError("P3-2: LLM generation + verification")


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
