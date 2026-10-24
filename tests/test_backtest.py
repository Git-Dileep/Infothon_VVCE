"""Tests for backtest dataset building, leakage guardrails, and strategy metrics. OWNER: Person 2."""
import sqlite3
import pandas as pd
import pytest

from patchpilot import backtest, config, db


def make_backtest_fixture():
    """Create a minimal synthetic SQLite database with known publish and KEV dates."""
    conn = db.connect(":memory:")
    db.init_db(conn)

    # Insert test CVEs relative to cutoff 2025-01-01
    cves = [
        # 1. Already in KEV prior to cutoff -> MUST BE EXCLUDED from candidates
        ("CVE-OLD-KEV", "Pre-cutoff KEV", "2024-10-01", 8.0, "CWE-79"),
        # 2. Published after cutoff -> MUST BE EXCLUDED from candidates
        ("CVE-FUTURE-PUB", "Published after cutoff", "2025-03-01", 9.0, "CWE-89"),
        # 3. Candidate: enters KEV within 180 days -> label = 1
        ("CVE-CAND-POS1", "Exploited within 180d", "2024-11-01", 6.0, "CWE-20"),
        # 4. Candidate: high EPSS, enters KEV within 180 days -> label = 1
        ("CVE-CAND-POS2", "High EPSS exploited", "2024-11-15", 5.0, "CWE-22"),
        # 5. Candidate: enters KEV AFTER 180 days (e.g. 250 days) -> label = 0
        ("CVE-CAND-LATE", "Exploited after horizon", "2024-11-20", 7.5, "CWE-94"),
        # 6. Candidate: High CVSS, never exploited -> label = 0
        ("CVE-CAND-HIGH-CVSS", "High CVSS unexploited", "2024-11-25", 9.8, "CWE-119"),
        # 7. Candidate: Low CVSS, Low EPSS, never exploited -> label = 0
        ("CVE-CAND-BENIGN", "Benign flaw", "2024-12-01", 3.0, "CWE-200"),
    ]

    for cid, desc, pub, cvss, cwe in cves:
        conn.execute(
            "INSERT INTO cve (cve_id, description, published, cvss, cwe) VALUES (?, ?, ?, ?, ?)",
            (cid, desc, pub, cvss, cwe),
        )

    # Insert KEV dates
    kevs = [
        ("CVE-OLD-KEV", "2024-12-15", "2025-01-05"),     # before cutoff (2025-01-01)
        ("CVE-CAND-POS1", "2025-02-10", "2025-03-01"),   # within 180d
        ("CVE-CAND-POS2", "2025-03-15", "2025-04-01"),   # within 180d
        ("CVE-CAND-LATE", "2025-10-15", "2025-11-01"),   # > 180d after 2025-01-01
    ]
    for cid, d_add, d_due in kevs:
        conn.execute("INSERT INTO kev (cve_id, date_added, due_date) VALUES (?, ?, ?)", (cid, d_add, d_due))

    # EPSS scores as of 2025-01-01
    epss_scores = [
        ("CVE-OLD-KEV", 0.50),
        ("CVE-FUTURE-PUB", 0.80),
        ("CVE-CAND-POS1", 0.70),
        ("CVE-CAND-POS2", 0.95),
        ("CVE-CAND-LATE", 0.20),
        ("CVE-CAND-HIGH-CVSS", 0.02),
        ("CVE-CAND-BENIGN", 0.01),
    ]
    for cid, score in epss_scores:
        conn.execute("INSERT INTO epss (cve_id, score, percentile) VALUES (?, ?, 0.5)", (cid, score))

    conn.commit()
    return conn


def test_backtest_candidate_selection_and_leakage_guardrail():
    """Verify candidates strictly exclude pre-cutoff KEV and post-cutoff publications, and leak no KEV feature."""
    conn = make_backtest_fixture()
    cutoff = "2025-01-01"

    df = backtest.build_backtest_dataset(cutoff, horizon_days=180, conn=conn)

    # 1. Leakage Guardrail: No 'kev' column must exist in features
    assert "kev" not in df.columns, "Data leakage violation: 'kev' column present in candidate features"
    assert set(df.columns) == {"cve_id", "cvss", "epss", "blend", "label"}

    cve_ids = set(df["cve_id"])

    # 2. Pre-cutoff KEV CVE must be EXCLUDED
    assert "CVE-OLD-KEV" not in cve_ids, "Candidate leakage: CVE already in KEV before T was included"

    # 3. Post-cutoff published CVE must be EXCLUDED
    assert "CVE-FUTURE-PUB" not in cve_ids, "Candidate leakage: CVE published after T was included"

    # 4. Valid candidates must be INCLUDED
    assert "CVE-CAND-POS1" in cve_ids
    assert "CVE-CAND-POS2" in cve_ids
    assert "CVE-CAND-LATE" in cve_ids
    assert "CVE-CAND-HIGH-CVSS" in cve_ids
    assert "CVE-CAND-BENIGN" in cve_ids
    assert len(df) == 5

    # 5. Verify labels
    df_map = df.set_index("cve_id")
    assert df_map.loc["CVE-CAND-POS1", "label"] == 1
    assert df_map.loc["CVE-CAND-POS2", "label"] == 1
    assert df_map.loc["CVE-CAND-LATE", "label"] == 0  # entered KEV after 180d
    assert df_map.loc["CVE-CAND-HIGH-CVSS", "label"] == 0
    assert df_map.loc["CVE-CAND-BENIGN", "label"] == 0

    # 6. Verify feature values
    assert df_map.loc["CVE-CAND-HIGH-CVSS", "cvss"] == 9.8
    assert df_map.loc["CVE-CAND-HIGH-CVSS", "epss"] == 0.02


def test_evaluate_strategies_metrics():
    """Verify strategy evaluation calculates ranking shares and threshold fractions accurately."""
    records = [
        {"cve_id": f"CVE-{i:02d}", "cvss": 5.0, "epss": 0.1, "blend": 0.3, "label": 0}
        for i in range(20)
    ]
    # Set 2 positives
    records[0]["label"] = 1
    records[0]["epss"] = 0.99
    records[0]["blend"] = 0.95
    records[0]["cvss"] = 9.5

    records[1]["label"] = 1
    records[1]["epss"] = 0.90
    records[1]["blend"] = 0.90
    records[1]["cvss"] = 5.0

    # High CVSS but negative
    records[2]["cvss"] = 9.8
    records[2]["epss"] = 0.01
    records[2]["blend"] = 0.50

    df = pd.DataFrame(records)
    results = backtest.evaluate_strategies(df)

    # 5 strategies must be present
    assert "cvss_only" in results
    assert "epss_only" in results
    assert "blend" in results
    assert "cvss>=7" in results
    assert "cvss>=9" in results

    # With 20 candidates, top 5% is 1 candidate, top 10% is 2 candidates
    # Positives = 2 (records 0 and 1)
    # EPSS top 1 is CVE-00 (pos) -> caught 1/2 = 50%
    assert results["epss_only"]["top_5pct_caught"] == 0.5
    # EPSS top 2 are CVE-00 and CVE-01 (both pos) -> caught 2/2 = 100%
    assert results["epss_only"]["top_10pct_caught"] == 1.0

    # CVSS top 1 is CVE-02 (neg) -> caught 0/2 = 0%
    assert results["cvss_only"]["top_5pct_caught"] == 0.0
    # CVSS top 2 are CVE-02 and CVE-00 -> caught 1/2 = 50%
    assert results["cvss_only"]["top_10pct_caught"] == 0.5

    # Threshold rules
    # cvss >= 9: CVE-00 and CVE-02 -> 2/20 = 10% patched. 1 of 2 positives caught = 50%
    assert results["cvss>=9"]["fraction_patched"] == 0.10
    assert results["cvss>=9"]["fraction_caught"] == 0.50


def test_run_backtest_contract():
    """Verify run_backtest returns the contract dictionary format."""
    conn = make_backtest_fixture()
    bt = backtest.run_backtest("2025-01-01", horizon_days=180, conn=conn)

    assert bt["cutoff"] == "2025-01-01"
    assert bt["n_candidates"] == 5
    assert bt["n_positive"] == 2
    assert "results" in bt
    assert len(bt["results"]) == 5
    for strat in ("cvss_only", "epss_only", "blend", "cvss>=7", "cvss>=9"):
        assert strat in bt["results"]


def test_generated_artifacts_exist_and_valid():
    """Verify generated artifacts docs/backtest.* exist and contain required data."""
    csv_path = config.ROOT / "docs" / "backtest_results.csv"
    png_path = config.ROOT / "docs" / "backtest.png"
    md_path = config.ROOT / "docs" / "backtest.md"

    assert csv_path.exists()
    assert png_path.exists()
    assert md_path.exists()

    # CSV checks
    df_csv = pd.read_csv(csv_path)
    assert set(df_csv["cutoff"].unique()) == {"2025-01-01", "2025-07-01"}
    assert set(df_csv["strategy"].unique()) == {"cvss_only", "epss_only", "blend", "cvss>=7", "cvss>=9"}

    # MD checks
    md_text = md_path.read_text(encoding="utf-8")
    assert "KEV and asset factors are context and not testable here" in md_text
    assert "matches EPSS, adds asset context and fixes" in md_text
    assert "python -m patchpilot.backtest" in md_text


def test_real_snapshot_cutoffs_counts():
    """Verify run_backtest returns non-zero candidates and positives on real snapshot cutoffs."""
    res_jan = backtest.run_backtest("2025-01-01", horizon_days=180)
    assert res_jan["n_candidates"] > 250_000
    assert res_jan["n_positive"] > 0
    assert "blend" in res_jan["results"]

    res_jul = backtest.run_backtest("2025-07-01", horizon_days=180)
    assert res_jul["n_candidates"] > 250_000
    assert res_jul["n_positive"] > 0
    assert "blend" in res_jul["results"]

