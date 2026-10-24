import sqlite3
import numpy as np
import pandas as pd

from . import config

QUEUE_COLUMNS = [
    "rank", "cve_id", "tier", "score", "cvss", "epss", "kev",
    "asset_crit", "matched_assets", "description",
]


def tier_for(score: float, kev: bool) -> str:
    """Determine tier name. KEV-listed is ALWAYS Critical regardless of score."""
    if kev:
        return "Critical"
    for name, minimum in config.TIERS:
        if score >= minimum:
            return name
    return "Low"


def _frame(conn: sqlite3.Connection, cve_id: str | None = None) -> pd.DataFrame:
    where, params = ("WHERE c.cve_id = ?", (cve_id,)) if cve_id else ("", ())
    
    # Fast single SQL query joining cve, epss, kev
    df = pd.read_sql_query(
        f"""SELECT c.cve_id, c.description, c.published, c.cvss, c.cwe,
                   e.score AS epss,
                   CASE WHEN k.cve_id IS NULL THEN 0 ELSE 1 END AS kev
            FROM cve c
            LEFT JOIN epss e ON e.cve_id = c.cve_id
            LEFT JOIN kev k ON k.cve_id = c.cve_id
            {where}""",
        conn, params=params,
    )
    
    # Handle NULLs and clamp inputs to valid ranges
    # CVSS: 0.0 to 10.0
    df["cvss"] = pd.to_numeric(df["cvss"], errors="coerce").fillna(0.0).clip(lower=0.0, upper=10.0)
    # EPSS: 0.0 to 1.0
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce").fillna(0.0).clip(lower=0.0, upper=1.0)
    # KEV: binary 0 or 1
    df["kev"] = pd.to_numeric(df["kev"], errors="coerce").fillna(0).astype(int).clip(lower=0, upper=1)
    df["description"] = df["description"].fillna("")

    # Asset matching
    n_assets = conn.execute("SELECT COUNT(*) FROM asset").fetchone()[0]
    if n_assets == 0:
        # Neutral asset factor when no inventory is loaded
        df["asset_crit"] = float(config.NEUTRAL_ASSET)
        df["matched_assets"] = ""
    else:
        # Match assets via vendor/product join
        m = pd.read_sql_query(
            """SELECT cp.cve_id, a.name, a.criticality
               FROM cve_product cp
               JOIN asset a ON lower(a.vendor) = lower(cp.vendor)
                           AND lower(a.product) = lower(cp.product)""",
            conn,
        )
        if m.empty:
            df["asset_crit"] = 0.0
            df["matched_assets"] = ""
        else:
            m["criticality"] = pd.to_numeric(m["criticality"], errors="coerce").fillna(0.0).clip(0.0, 1.0)
            agg = m.groupby("cve_id").agg(
                asset_crit=("criticality", "max"),
                matched_assets=("name", lambda s: "; ".join(sorted(set(str(x) for x in s if str(x).strip())))),
            )
            df = df.merge(agg, how="left", left_on="cve_id", right_index=True)
            df["asset_crit"] = df["asset_crit"].fillna(0.0).clip(0.0, 1.0)
            df["matched_assets"] = df["matched_assets"].fillna("")

    w = config.WEIGHTS
    # Vectorized multi-factor score calculation: Risk = 0.35*CVSS/10 + 0.30*EPSS + 0.20*KEV + 0.15*Asset
    df["score"] = (
        w["cvss"] * (df["cvss"] / 10.0)
        + w["epss"] * df["epss"]
        + w["kev"] * df["kev"]
        + w["asset"] * df["asset_crit"]
    ).clip(0.0, 1.0).round(4)

    # Vectorized tier assignment
    # KEV items are Critical; otherwise check score against config.TIERS
    conditions = [
        (df["kev"] == 1) | (df["score"] >= config.TIERS[0][1]), # Critical (>= 0.75 or KEV)
        (df["score"] >= config.TIERS[1][1]),                    # High (0.50 - 0.74)
        (df["score"] >= config.TIERS[2][1]),                    # Medium (0.25 - 0.49)
    ]
    choices = ["Critical", "High", "Medium"]
    df["tier"] = np.select(conditions, choices, default="Low")

    return df


def ranked_queue(conn: sqlite3.Connection, only_matched: bool = False) -> pd.DataFrame:
    """Patch queue: tier order first (Critical..Low), then score desc, then cve_id.
    Columns = QUEUE_COLUMNS. Fast and vectorized.
    """
    df = _frame(conn)
    if only_matched:
        df = df[df["matched_assets"] != ""]
    
    df = df.assign(_t=df["tier"].map(config.TIER_ORDER)).sort_values(
        ["_t", "score", "cve_id"], ascending=[True, False, True]
    )
    df = df.reset_index(drop=True)
    df["rank"] = df.index + 1
    return df[QUEUE_COLUMNS]


def explain(conn: sqlite3.Connection, cve_id: str) -> dict:
    """Per-factor breakdown for a single CVE. components[i].contribution sums to `score`."""
    df = _frame(conn, cve_id)
    if df.empty:
        raise KeyError(f"CVE not found: {cve_id}")
    r = df.iloc[0]
    w = config.WEIGHTS
    
    norm = {
        "cvss": float(r.cvss / 10.0),
        "epss": float(r.epss),
        "kev": float(r.kev),
        "asset": float(r.asset_crit),
    }
    raw = {
        "cvss": float(r.cvss),
        "epss": float(r.epss),
        "kev": int(r.kev),
        "asset": float(r.asset_crit),
    }
    
    comps = [
        {
            "factor": f,
            "raw": float(raw[f]),
            "normalized": float(norm[f]),
            "weight": float(w[f]),
            "contribution": round(float(w[f] * norm[f]), 4),
        }
        for f in ("cvss", "epss", "kev", "asset")
    ]
    
    return {
        "cve_id": cve_id,
        "score": float(r.score),
        "tier": r.tier,
        "kev_override": bool(r.kev) and r.score < config.TIERS[0][1],
        "matched_assets": [a for a in r.matched_assets.split("; ") if a],
        "components": comps,
    }


def compare_orders(conn: sqlite3.Connection, top_n: int = 10) -> pd.DataFrame:
    """Compare CVSS-only order vs PatchPilot risk order.
    Powers Demo Step 1.
    Columns: cvss_rank, patchpilot_rank, cve_id, cvss, epss, kev, tier, why_moved.
    """
    full_q = ranked_queue(conn)
    if full_q.empty:
        return pd.DataFrame(
            columns=["cvss_rank", "patchpilot_rank", "cve_id", "cvss", "epss", "kev", "tier", "why_moved"]
        )

    # Sort pure CVSS descending (tiebreaker cve_id ascending so CVE-2099-0001 is #1)
    cvss_sorted = full_q.sort_values(
        by=["cvss", "cve_id"],
        ascending=[False, True],
    ).reset_index(drop=True)
    cvss_sorted["cvss_rank"] = cvss_sorted.index + 1

    # Merge with PatchPilot rank
    merged = cvss_sorted.merge(
        full_q[["cve_id", "rank"]],
        on="cve_id",
        suffixes=("", "_pp"),
    )
    merged = merged.rename(columns={"rank": "patchpilot_rank"})

    def format_why_moved(row) -> str:
        reasons = []
        if row["kev"] == 1:
            reasons.append("KEV-listed (active exploit)")
        if row["epss"] >= 0.70:
            reasons.append(f"High EPSS ({row['epss']:.2f})")
        elif row["epss"] <= 0.05 and row["cvss"] >= 8.5:
            reasons.append(f"Low EPSS ({row['epss']:.2f}) despite CVSS {row['cvss']:.1f}")

        if row["asset_crit"] >= 0.70 and row["matched_assets"]:
            reasons.append(f"Critical asset ({row['matched_assets'].split(';')[0]})")

        if not reasons:
            if row["patchpilot_rank"] < row["cvss_rank"]:
                reasons.append("Higher exploit probability")
            elif row["patchpilot_rank"] > row["cvss_rank"]:
                reasons.append("Low real-world threat")
            else:
                reasons.append("Aligned severity and exploit risk")

        return ", ".join(reasons)

    merged["why_moved"] = merged.apply(format_why_moved, axis=1)

    result_cols = [
        "cvss_rank", "patchpilot_rank", "cve_id", "cvss", "epss", "kev", "tier", "why_moved"
    ]
    return merged[result_cols].head(top_n)

