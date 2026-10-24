import json
import sqlite3
from pathlib import Path

from patchpilot import assistant, db, ingest


def make_conn():
    conn = db.connect(":memory:")
    db.init_db(conn)
    ingest.load_fixture(conn)
    return conn


def test_starter_questions_retrieval():
    conn = make_conn()
    questions_path = Path(__file__).resolve().parent.parent / "data" / "eval" / "questions.json"
    with open(questions_path) as f:
        data = json.load(f)

    for q in data["questions"]:
        evs = assistant.retrieve(conn, q["question"])
        if q["expect_refusal"]:
            assert len(evs) == 0, f"Expected refusal (empty evidence) for {q['id']}, got {evs}"
        else:
            assert len(evs) > 0, f"Expected evidence for {q['id']}, got empty list"
            retrieved_cves = {e.cve_id for e in evs if e.cve_id}
            for mc in q["must_cite"]:
                assert mc in retrieved_cves, f"Expected {mc} in retrieved CVEs for {q['id']}, got {retrieved_cves}"


def test_no_fix_recorded_evidence():
    conn = make_conn()
    evs = assistant.retrieve(conn, "Is there a fix for CVE-2099-0007?")
    fix_ev = next((e for e in evs if e.kind == "fix"), None)
    assert fix_ev is not None
    assert "no fix link recorded" in fix_ev.text.lower()


def test_unknown_cve_returns_empty():
    conn = make_conn()
    assert assistant.retrieve(conn, "Tell me about CVE-1900-9999") == []


def test_out_of_scope_returns_empty():
    conn = make_conn()
    assert assistant.retrieve(conn, "Who is the CEO of Acme?") == []
