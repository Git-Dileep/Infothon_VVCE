"""Risk scoring + explanations. OWNER: Person 2.

Baseline implementation so the whole team can integrate on day one. P2 hardens it
(edge cases, performance, tests) but must NOT change the function signatures or column names.
"""
from __future__ import annotations

import sqlite3

import pandas as pd

from . import config

QUEUE_COLUMNS = [
    "rank", "cve_id", "tier", "score", "cvss", "epss", "kev",
    "asset_crit", "matched_assets", "description",
]


def tier_for(score: float, kev: bool) -> str:
    if kev:
        return "Critical"  # KEV-listed is always Critical
    for name, minimum in config.TIERS:
        if score >= minimum:
            return name
    return "Low"


def _frame(conn: sqlite3.Connection, cve_id: str | None = None) -> pd.DataFrame:
    where, params = ("WHERE c.cve_id = ?", (cve_id,)) if cve_id else ("", ())
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
    df["cvss"] = df["cvss"].fillna(0.0)
    df["epss"] = df["epss"].fillna(0.0)

    n_assets = conn.execute("SELECT COUNT(*) FROM asset").fetchone()[0]
    if n_assets == 0:
        df["asset_crit"] = config.NEUTRAL_ASSET
        df["matched_assets"] = ""
    else:
        m = pd.read_sql_query(
            """SELECT cp.cve_id, a.name, a.criticality
               FROM cve_product cp
               JOIN asset a ON lower(a.vendor) = lower(cp.vendor)
                           AND lower(a.product) = lower(cp.product)""",
            conn,
        )
        agg = m.groupby("cve_id").agg(
            asset_crit=("criticality", "max"),
            matched_assets=("name", lambda s: "; ".join(sorted(set(s)))),
        )
        df = df.merge(agg, how="left", left_on="cve_id", right_index=True)
        df["asset_crit"] = df["asset_crit"].fillna(0.0)
        df["matched_assets"] = df["matched_assets"].fillna("")

    w = config.WEIGHTS
    df["score"] = (
        w["cvss"] * df["cvss"] / 10.0
        + w["epss"] * df["epss"]
        + w["kev"] * df["kev"]
        + w["asset"] * df["asset_crit"]
    ).round(4)
    df["tier"] = [tier_for(s, bool(k)) for s, k in zip(df["score"], df["kev"])]
    return df


def ranked_queue(conn: sqlite3.Connection, only_matched: bool = False) -> pd.DataFrame:
    """Patch queue: tier order first (Critical..Low), then score desc. Columns = QUEUE_COLUMNS."""
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
    """Per-factor breakdown. components[i].contribution sums to `score`."""
    df = _frame(conn, cve_id)
    if df.empty:
        raise KeyError(cve_id)
    r = df.iloc[0]
    w = config.WEIGHTS
    norm = {"cvss": r.cvss / 10.0, "epss": r.epss, "kev": float(r.kev), "asset": r.asset_crit}
    raw = {"cvss": r.cvss, "epss": r.epss, "kev": int(r.kev), "asset": r.asset_crit}
    comps = [
        {"factor": f, "raw": float(raw[f]), "normalized": float(norm[f]),
         "weight": w[f], "contribution": round(w[f] * float(norm[f]), 4)}
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
