import sqlite3
import time
import pandas as pd
import pytest
from patchpilot import db, ingest, scoring, config


def make_test_conn():
    conn = db.connect(":memory:")
    db.init_db(conn)
    ingest.load_fixture(conn)
    return conn


def test_scoring_edge_cases_and_nulls():
    conn = make_test_conn()
    
    # Insert edge case CVEs: NULL CVSS, negative CVSS, huge CVSS, NULL EPSS
    conn.execute(
        "INSERT INTO cve (cve_id, description, cvss) VALUES ('CVE-EDGE-0001', 'Null CVSS and EPSS', NULL)"
    )
    conn.execute(
        "INSERT INTO cve (cve_id, description, cvss) VALUES ('CVE-EDGE-0002', 'Out of range CVSS', 15.0)"
    )
    conn.execute(
        "INSERT INTO epss (cve_id, score, percentile) VALUES ('CVE-EDGE-0002', 1.8, 0.99)"
    )
    conn.commit()

    q = scoring.ranked_queue(conn)
    assert q["score"].notna().all()
    assert (q["score"] >= 0.0).all() and (q["score"] <= 1.0).all()
    assert (q["cvss"] >= 0.0).all() and (q["cvss"] <= 10.0).all()
    assert (q["epss"] >= 0.0).all() and (q["epss"] <= 1.0).all()

    # Edge 1: missing CVSS & EPSS should resolve to 0.0
    r1 = q[q["cve_id"] == "CVE-EDGE-0001"].iloc[0]
    assert r1["cvss"] == 0.0
    assert r1["epss"] == 0.0
    # Edge 2: clamped to 10.0 and 1.0
    r2 = q[q["cve_id"] == "CVE-EDGE-0002"].iloc[0]
    assert r2["cvss"] == 10.0
    assert r2["epss"] == 1.0


def test_scoring_speed():
    conn = make_test_conn()
    t0 = time.perf_counter()
    q = scoring.ranked_queue(conn)
    duration = time.perf_counter() - t0
    # Queue generation should easily complete in under 500ms
    assert duration < 0.5
    assert len(q) >= 20


def test_compare_orders_powers_demo():
    conn = make_test_conn()
    comp = scoring.compare_orders(conn, top_n=10)
    
    expected_cols = [
        "cvss_rank", "patchpilot_rank", "cve_id", "cvss", "epss", "kev", "tier", "why_moved"
    ]
    assert list(comp.columns) == expected_cols
    assert len(comp) <= 10

    # In fixture, CVE-2099-0001 has CVSS 9.8 but EPSS 0.02 and no KEV.
    # It must rank #1 in CVSS, but drop in PatchPilot rank.
    cve1_row = comp[comp["cve_id"] == "CVE-2099-0001"]
    if not cve1_row.empty:
        r = cve1_row.iloc[0]
        assert r["cvss_rank"] == 1
        assert r["patchpilot_rank"] > 1
        assert "Low EPSS" in r["why_moved"] or "Low real-world threat" in r["why_moved"]

    # CVE-2099-0002 has CVSS 7.5, EPSS 0.94, KEV 1 -> should rank #1 in PatchPilot
    cve2_row = comp[comp["cve_id"] == "CVE-2099-0002"]
    if not cve2_row.empty:
        r2 = cve2_row.iloc[0]
        assert r2["patchpilot_rank"] == 1
        assert "KEV-listed" in r2["why_moved"]
