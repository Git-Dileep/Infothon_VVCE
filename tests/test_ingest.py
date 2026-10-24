import gzip
import sqlite3
from unittest.mock import MagicMock, patch

import pytest

from patchpilot import db
from patchpilot import ingest


def make_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    db.init_db(conn)
    return conn


def nvd_entry(cve_id="CVE-2025-1234"):
    return {
        "cve": {
            "id": cve_id,
            "published": "2025-02-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
            "metrics": {
                "cvssMetricV30": [{"cvssData": {"baseScore": 7.0}}],
                "cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}],
            },
            "weaknesses": [
                {"description": [{"lang": "en", "value": "CWE-79"}]}
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "cpe:2.3:a:Acme:Widget:1.0:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                },
                                {
                                    "criteria": "cpe:2.3:a:ACME:WIDGET:2.0:*:*:*:*:*:*:*",
                                    "vulnerable": True,
                                },
                            ]
                        }
                    ]
                }
            ],
            "references": [
                {"url": "https://vendor.example/patch", "tags": ["Patch"]},
                {
                    "url": "https://vendor.example/advisory",
                    "tags": ["Vendor Advisory"],
                },
                {
                    "url": "https://vendor.example/other",
                    "tags": ["Third Party Advisory"],
                },
            ],
        }
    }


def nvd_response(vulnerabilities, total_results):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "totalResults": total_results,
        "vulnerabilities": vulnerabilities,
    }
    response.raise_for_status.return_value = None
    return response


def nvd_session(*responses):
    session = MagicMock()
    session.__enter__.return_value = session
    session.__exit__.return_value = False
    session.get.side_effect = responses
    return session


def test_sync_nvd_normalizes_pages_caches_and_rebuilds_fts(tmp_path, monkeypatch):
    conn = make_conn()
    monkeypatch.setattr(ingest.config, "RAW_DIR", tmp_path / "raw")
    monkeypatch.setattr(ingest.config, "NVD_API_KEY", "test-api-key")
    session = nvd_session(
        nvd_response([nvd_entry()], 2),
        nvd_response([nvd_entry("CVE-2025-5678")], 2),
    )
    with (
        patch("patchpilot.ingest.requests.Session", return_value=session),
        patch("patchpilot.ingest.time.sleep"),
    ):
        counts = ingest.sync_nvd(conn, "2025-02-01", "2025-02-01")

    row = conn.execute(
        "SELECT cvss, cwe FROM cve WHERE cve_id='CVE-2025-1234'"
    ).fetchone()
    assert tuple(row) == (8.1, "CWE-79")
    assert [tuple(row) for row in conn.execute(
        "SELECT vendor, product FROM cve_product WHERE cve_id='CVE-2025-1234'"
    )] == [("acme", "widget")]
    assert conn.execute(
        "SELECT COUNT(*) FROM fix WHERE cve_id='CVE-2025-1234'"
    ).fetchone()[0] == 2
    assert conn.execute(
        "SELECT COUNT(*) FROM cve_fts WHERE cve_id='CVE-2025-1234'"
    ).fetchone()[0] == 1
    assert counts == {
        "cves_processed": 2,
        "cves_total": 2,
        "products_total": 2,
        "fixes_total": 4,
        "pages_downloaded": 2,
    }
    assert session.get.call_args_list[0].kwargs["headers"] == {
        "apiKey": "test-api-key"
    }

    cached_session = nvd_session()
    with patch("patchpilot.ingest.requests.Session", return_value=cached_session):
        cached_counts = ingest.sync_nvd(conn, "2025-02-01", "2025-02-01")
    cached_session.get.assert_not_called()
    assert cached_counts["pages_downloaded"] == 0
    conn.close()


def test_sync_nvd_splits_published_range_into_api_windows(tmp_path, monkeypatch):
    conn = make_conn()
    monkeypatch.setattr(ingest.config, "RAW_DIR", tmp_path / "raw")
    session = nvd_session(nvd_response([], 0), nvd_response([], 0))
    with patch("patchpilot.ingest.requests.Session", return_value=session):
        ingest.sync_nvd(conn, "2024-01-01", "2024-05-01")

    requests = [call.kwargs["params"] for call in session.get.call_args_list]
    assert len(requests) == 2
    assert requests[0]["pubStartDate"] == "2024-01-01T00:00:00.000Z"
    assert requests[0]["pubEndDate"] == "2024-04-29T23:59:59.999Z"
    assert requests[1]["pubStartDate"] == "2024-04-30T00:00:00.000Z"
    assert all(request["resultsPerPage"] == 2000 for request in requests)
    conn.close()


def test_sync_nvd_retries_rate_limit_with_exponential_backoff(tmp_path, monkeypatch):
    conn = make_conn()
    monkeypatch.setattr(ingest.config, "RAW_DIR", tmp_path / "raw")
    limited = MagicMock(status_code=429)
    limited.raise_for_status.return_value = None
    success = nvd_response([], 0)
    session = nvd_session(limited, success)
    with (
        patch("patchpilot.ingest.requests.Session", return_value=session),
        patch("patchpilot.ingest.time.sleep") as sleep,
    ):
        ingest.sync_nvd(conn, "2025-02-01", "2025-02-01")

    sleep.assert_called_once_with(1)
    conn.close()


def test_sync_kev_returns_new_ids_and_updates_catalog_dates():
    conn = make_conn()
    conn.execute(
        "INSERT INTO kev(cve_id, date_added, due_date) VALUES (?, ?, ?)",
        ("CVE-2025-0001", "2025-01-01", "2025-01-20"),
    )
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2025-0001", "dateAdded": "2025-01-02", "dueDate": "2025-02-01"},
            {"cveID": "CVE-2025-0002", "dateAdded": "2025-02-02", "dueDate": "2025-03-01"},
            {"cveID": "CVE-2025-0002", "dateAdded": "2025-02-02", "dueDate": "2025-03-01"},
        ]
    }
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    with patch("patchpilot.ingest.requests.get", return_value=response):
        assert ingest.sync_kev(conn) == ["CVE-2025-0002"]

    row = conn.execute(
        "SELECT date_added, due_date FROM kev WHERE cve_id='CVE-2025-0001'"
    ).fetchone()
    assert tuple(row) == ("2025-01-02", "2025-02-01")
    conn.close()


def test_sync_kev_caches_feed_and_uses_it_offline(tmp_path, monkeypatch):
    conn = make_conn()
    monkeypatch.setattr(ingest.config, "RAW_DIR", tmp_path / "raw")
    payload = {
        "vulnerabilities": [
            {"cveID": "CVE-2025-0001", "dateAdded": "2025-01-01", "dueDate": "2025-01-22"}
        ]
    }
    response = MagicMock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    with patch("patchpilot.ingest.requests.get", return_value=response) as get:
        assert ingest.sync_kev(conn) == ["CVE-2025-0001"]
    get.assert_called_once_with(
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        timeout=30,
    )

    cache_path = (
        tmp_path / "raw" / "kev" / "known_exploited_vulnerabilities.json"
    )
    assert cache_path.exists()
    with patch(
        "patchpilot.ingest.requests.get",
        side_effect=ingest.requests.ConnectionError("offline"),
    ):
        assert ingest.sync_kev(conn) == []
    assert tuple(
        conn.execute(
            "SELECT date_added, due_date FROM kev WHERE cve_id='CVE-2025-0001'"
        ).fetchone()
    ) == ("2025-01-01", "2025-01-22")
    conn.close()


def test_sync_kev_propagates_network_error_without_cache(tmp_path, monkeypatch):
    conn = make_conn()
    monkeypatch.setattr(ingest.config, "RAW_DIR", tmp_path / "raw")
    with patch(
        "patchpilot.ingest.requests.get",
        side_effect=ingest.requests.ConnectionError("offline"),
    ):
        with pytest.raises(ingest.requests.ConnectionError, match="offline"):
            ingest.sync_kev(conn)
    conn.close()


def test_simulate_new_kev_uses_real_fixture_when_cve_is_loaded(tmp_path, monkeypatch):
    conn = make_conn()
    cve_id = "CVE-2025-49844"
    conn.execute(
        "INSERT INTO cve(cve_id, description) VALUES (?, ?)",
        (cve_id, "Valkey vulnerability"),
    )
    fixture_path = tmp_path / "new_kev.json"
    fixture_path.write_text(
        '{"cve_id":"CVE-2025-49844","date_added":"2026-10-24","due_date":"2026-11-14"}',
        encoding="utf-8",
    )
    monkeypatch.setattr(ingest.config, "NEW_KEV_FIXTURE_PATH", fixture_path)

    assert ingest.simulate_new_kev(conn) == cve_id
    assert conn.execute(
        "SELECT 1 FROM kev WHERE cve_id=?", (cve_id,)
    ).fetchone()
    conn.close()


def test_sync_epss_only_upserts_cves_already_in_database():
    conn = make_conn()
    conn.executemany(
        "INSERT INTO cve(cve_id, description) VALUES (?, ?)",
        [
            ("CVE-2025-0001", "Known CVE one"),
            ("CVE-2025-0002", "Known CVE two"),
        ],
    )
    csv_content = (
        "#model_version:v2026.06.15,score_date:2026-10-24T12:00:00Z\n"
        "cve,epss,percentile\n"
        "CVE-2025-0001,0.91,0.99\n"
        "CVE-2025-0002,0.12,0.60\n"
        "CVE-1999-9999,0.99,0.999\n"
        "CVE-2025-0002,invalid,0.50\n"
    )
    response = MagicMock()
    response.content = gzip.compress(csv_content.encode())
    response.raise_for_status.return_value = None
    with patch("patchpilot.ingest.requests.get", return_value=response):
        assert ingest.sync_epss(conn) == 2

    assert conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0] == 2
    assert conn.execute(
        "SELECT 1 FROM epss WHERE cve_id='CVE-1999-9999'"
    ).fetchone() is None
    assert tuple(
        conn.execute(
            "SELECT score, percentile FROM epss WHERE cve_id='CVE-2025-0001'"
        ).fetchone()
    ) == (0.91, 0.99)
    conn.close()


def test_download_and_load_epss_history(tmp_path, monkeypatch):
    conn = make_conn()
    monkeypatch.setattr(ingest.config, "RAW_DIR", tmp_path / "raw")
    content = gzip.compress(
        b"#score_date:2025-01-01\n"
        b"cve,epss,percentile\n"
        b"CVE-2025-0001,0.91,0.99\n"
        b"CVE-2025-0002,invalid,0.50\n"
    )
    response = MagicMock()
    response.content = content
    response.raise_for_status.return_value = None
    url = "https://epss.empiricalsecurity.com/epss_scores-2025-01-01.csv.gz"
    with patch("patchpilot.ingest.requests.get", return_value=response) as get:
        paths = ingest.download_epss_history(["2025-01-01"])

    get.assert_called_once_with(url, timeout=120)
    assert paths == [tmp_path / "raw" / "epss" / "epss_scores-2025-01-01.csv.gz"]
    history = ingest.load_epss_history("2025-01-01")
    assert list(history.columns) == ["cve_id", "score"]
    assert history.to_dict("records") == [
        {"cve_id": "CVE-2025-0001", "score": 0.91}
    ]

    with patch("patchpilot.ingest.requests.get") as get:
        assert ingest.download_epss_history(["2025-01-01"]) == paths
    get.assert_not_called()
    conn.close()


def test_load_epss_history_reports_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ingest.config, "RAW_DIR", tmp_path / "raw")
    with pytest.raises(FileNotFoundError, match="download_epss_history"):
        ingest.load_epss_history("2025-01-01")


def test_ingestion_cli_prints_sync_counts(monkeypatch, capsys):
    conn = make_conn()
    monkeypatch.setattr(ingest.db, "connect", lambda path=None: conn)
    sync_mock = MagicMock(
        return_value={
            "cves_processed": 3,
            "cves_total": 3,
            "products_total": 2,
            "fixes_total": 1,
            "pages_downloaded": 1,
        }
    )
    monkeypatch.setattr(ingest, "sync_nvd", sync_mock)
    monkeypatch.setattr("sys.argv", ["patchpilot.ingest", "nvd"])

    ingest.main()

    sync_mock.assert_called_once_with(conn, "2024-01-01", "2025-12-31")
    assert "3 processed" in capsys.readouterr().out
    conn.close()


def test_fixture_cli_uses_separate_database_by_default(monkeypatch, capsys):
    conn = make_conn()
    connect = MagicMock(return_value=conn)
    load = MagicMock(return_value=20)
    monkeypatch.setattr(ingest.db, "connect", connect)
    monkeypatch.setattr(ingest, "load_fixture", load)
    monkeypatch.setattr("sys.argv", ["patchpilot.ingest", "fixture"])

    ingest.main()

    connect.assert_called_once_with(str(ingest.config.FIXTURE_DB_PATH))
    load.assert_called_once_with(conn)
    assert "20 synthetic CVEs" in capsys.readouterr().out
    conn.close()


def test_snapshot_cli_runs_all_sources_and_prints_row_counts(monkeypatch, capsys):
    conn = make_conn()
    monkeypatch.setattr(ingest.db, "connect", lambda path=None: conn)
    sync_nvd = MagicMock(
        return_value={
            "cves_processed": 0,
            "cves_total": 0,
            "products_total": 0,
            "fixes_total": 0,
            "pages_downloaded": 1,
        }
    )
    monkeypatch.setattr(ingest, "sync_nvd", sync_nvd)
    sync_kev = MagicMock(return_value=["CVE-2025-0001"])
    sync_epss = MagicMock(return_value=0)
    mark_seen = MagicMock()
    monkeypatch.setattr(ingest, "sync_kev", sync_kev)
    monkeypatch.setattr(ingest, "sync_epss", sync_epss)
    monkeypatch.setattr(ingest, "mark_kev_seen", mark_seen)
    monkeypatch.setattr("sys.argv", ["patchpilot.ingest", "snapshot"])

    ingest.main()

    sync_nvd.assert_called_once_with(conn, "2025-10-01", "2025-12-31")
    sync_kev.assert_called_once_with(conn)
    sync_epss.assert_called_once_with(conn)
    mark_seen.assert_called_once_with(conn)
    assert "0 CVEs" in capsys.readouterr().out
    conn.close()
