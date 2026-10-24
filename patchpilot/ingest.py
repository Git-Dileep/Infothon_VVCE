"""Data ingestion. OWNER: Person 1.

Implemented: fixture loader, new-KEV detector, simulated KEV (for the offline demo).
TODO (P1 issues): real NVD / KEV / EPSS downloaders + EPSS history for the backtest.
"""
from __future__ import annotations

import argparse
import json
import sqlite3

from . import config, db


def load_fixture(conn: sqlite3.Connection, path=config.FIXTURE_PATH) -> int:
    """Load the synthetic 20-CVE fixture (idempotent). Returns number of CVEs."""
    data = json.loads(open(path, encoding="utf-8").read())
    db.init_db(conn)
    for t in ("cve", "cve_product", "fix", "kev", "kev_seen", "epss", "asset"):
        conn.execute(f"DELETE FROM {t}")
    for c in data["cves"]:
        conn.execute(
            "INSERT INTO cve VALUES (?,?,?,?,?)",
            (c["cve_id"], c["description"], c["published"], c["cvss"], c["cwe"]),
        )
        for p in c["products"]:
            conn.execute("INSERT INTO cve_product VALUES (?,?,?)", (c["cve_id"], p["vendor"], p["product"]))
        for f in c["fixes"]:
            conn.execute("INSERT INTO fix VALUES (?,?,?)", (c["cve_id"], f["url"], f["kind"]))
        if c.get("epss"):
            conn.execute("INSERT INTO epss VALUES (?,?,?)", (c["cve_id"], c["epss"]["score"], c["epss"]["percentile"]))
        if c.get("kev"):
            conn.execute("INSERT INTO kev VALUES (?,?,?)", (c["cve_id"], c["kev"]["date_added"], c["kev"]["due_date"]))
    for a in data["assets"]:
        conn.execute(
            "INSERT INTO asset(name, vendor, product, criticality, match_confidence) VALUES (?,?,?,?,1.0)",
            (a["name"], a["vendor"], a["product"], a["criticality"]),
        )
    conn.commit()
    db.rebuild_fts(conn)
    mark_kev_seen(conn)
    return len(data["cves"])


def mark_kev_seen(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT OR IGNORE INTO kev_seen SELECT cve_id FROM kev")
    conn.commit()


def new_kev_since_last_sync(conn: sqlite3.Connection) -> list[str]:
    """KEV ids present in `kev` but not yet acknowledged in `kev_seen`."""
    rows = conn.execute("SELECT cve_id FROM kev WHERE cve_id NOT IN (SELECT cve_id FROM kev_seen)").fetchall()
    return [r[0] for r in rows]


def simulate_new_kev(conn: sqlite3.Connection, path=config.NEW_KEV_FIXTURE_PATH) -> str:
    """Offline demo helper: pretend CISA just added a CVE to KEV. Returns the CVE id."""
    d = json.loads(open(path, encoding="utf-8").read())
    conn.execute("INSERT OR REPLACE INTO kev VALUES (?,?,?)", (d["cve_id"], d["date_added"], d["due_date"]))
    conn.commit()
    return d["cve_id"]


# ---- P1 TODO: real downloaders -------------------------------------------------------------
def sync_kev(conn: sqlite3.Connection) -> list[str]:
    """Download CISA KEV JSON into `kev`; return NEW cve_ids. (issue P1-2)"""
    raise NotImplementedError("P1-2: implement KEV download")


def sync_epss(conn: sqlite3.Connection) -> int:
    """Load current EPSS scores into `epss`. (issue P1-2)"""
    raise NotImplementedError("P1-2: implement EPSS download")


def sync_nvd(conn: sqlite3.Connection, start: str, end: str) -> int:
    """Pull CVEs published in [start, end] from NVD 2.0 into cve/cve_product/fix. (issue P1-1)"""
    raise NotImplementedError("P1-1: implement NVD download")


def download_epss_history(dates: list[str]) -> None:
    """Fetch dated EPSS files into data/raw/epss/ for the backtest. (issue P1-3)"""
    raise NotImplementedError("P1-3: implement EPSS history download")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["fixture"])
    args = ap.parse_args()
    conn = db.connect()
    if args.cmd == "fixture":
        n = load_fixture(conn)
        print(f"Loaded {n} synthetic CVEs into {config.DB_PATH}")


if __name__ == "__main__":
    main()
