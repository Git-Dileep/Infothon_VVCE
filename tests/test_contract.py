"""Contract tests. Everyone must keep these green. Run: python -m pytest -q"""
from patchpilot import assistant, config, db, ingest, scoring
from patchpilot.contracts import Evidence


def make_conn():
    conn = db.connect(":memory:")
    db.init_db(conn)
    ingest.load_fixture(conn)
    return conn


def test_weights_sum_to_one():
    assert abs(sum(config.WEIGHTS.values()) - 1.0) < 1e-9


def test_queue_columns_and_rank():
    q = scoring.ranked_queue(make_conn())
    assert list(q.columns) == scoring.QUEUE_COLUMNS
    assert list(q["rank"]) == list(range(1, len(q) + 1))


def test_kev_is_always_critical_and_sorted_first():
    q = scoring.ranked_queue(make_conn())
    kev = q[q["kev"] == 1]
    assert (kev["tier"] == "Critical").all()
    assert q.iloc[0]["kev"] == 1


def test_worked_example():
    conn = make_conn()
    a, b, c = (scoring.explain(conn, f"CVE-2099-000{i}") for i in (1, 2, 3))
    assert abs(a["score"] - 0.424) < 0.001 and a["tier"] == "Medium"
    assert abs(b["score"] - 0.8645) < 0.001 and b["tier"] == "Critical"
    assert abs(c["score"] - 0.5625) < 0.001 and c["tier"] == "Critical"
    q = scoring.ranked_queue(conn)
    ids = list(q["cve_id"])
    assert ids.index("CVE-2099-0002") < ids.index("CVE-2099-0003") < ids.index("CVE-2099-0001")


def test_explain_sums_to_score():
    e = scoring.explain(make_conn(), "CVE-2099-0010")
    assert abs(sum(x["contribution"] for x in e["components"]) - e["score"]) < 1e-3


def test_new_kev_detector():
    conn = make_conn()
    assert ingest.new_kev_since_last_sync(conn) == []
    new = ingest.simulate_new_kev(conn)
    assert ingest.new_kev_since_last_sync(conn) == [new]
    q = scoring.ranked_queue(conn)
    assert q.iloc[0]["cve_id"] == new


def test_missing_cvss_and_epss_do_not_crash():
    q = scoring.ranked_queue(make_conn())
    assert q["score"].notna().all()


def test_verifier():
    ev = [Evidence("CVE-2099-0002:kev", "CVE-2099-0002", "kev", "KEV-listed")]
    ok = {"answer": "CVE-2099-0002 is KEV-listed.", "citations": ["CVE-2099-0002:kev"], "refused": False}
    bad_id = {"answer": "CVE-2099-0002 is KEV-listed.", "citations": ["CVE-2099-0002:fix"], "refused": False}
    bad_cve = {"answer": "CVE-2099-0099 is bad.", "citations": ["CVE-2099-0002:kev"], "refused": False}
    none = {"answer": "It is fine.", "citations": [], "refused": False}
    assert assistant.verify_citations(ok, ev)
    assert not assistant.verify_citations(bad_id, ev)
    assert not assistant.verify_citations(bad_cve, ev)
    assert not assistant.verify_citations(none, ev)
