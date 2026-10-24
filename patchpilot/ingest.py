"""Data ingestion. OWNER: Person 1.

Includes NVD, KEV, and EPSS loaders, snapshot creation, and offline demo helpers.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import sqlite3
import time
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import pandas as pd
import requests

from . import config, db

NVD_PAGE_SIZE = 2000
NVD_MAX_WINDOW_DAYS = 120
NVD_MAX_RETRIES = 6


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


def simulate_new_kev(
    conn: sqlite3.Connection, path: str | Path | None = None
) -> str:
    """Offline demo helper: pretend CISA just added a CVE to KEV. Returns the CVE id."""
    selected_path = Path(path) if path is not None else config.NEW_KEV_FIXTURE_PATH
    with selected_path.open(encoding="utf-8") as handle:
        d = json.load(handle)
    cve_id = d["cve_id"]
    if conn.execute("SELECT 1 FROM cve WHERE cve_id=?", (cve_id,)).fetchone() is None:
        if path is None and conn.execute(
            "SELECT 1 FROM cve WHERE cve_id LIKE 'CVE-2099-%' LIMIT 1"
        ).fetchone():
            selected_path = config.SYNTHETIC_NEW_KEV_FIXTURE_PATH
            with selected_path.open(encoding="utf-8") as handle:
                d = json.load(handle)
            cve_id = d["cve_id"]
        else:
            raise ValueError(f"Demo KEV CVE {cve_id} is not present in the database")
    conn.execute("INSERT OR REPLACE INTO kev VALUES (?,?,?)", (d["cve_id"], d["date_added"], d["due_date"]))
    conn.commit()
    return cve_id


def _project_config() -> dict[str, Any]:
    with (config.ROOT / "config" / "project.json").open(encoding="utf-8") as handle:
        return json.load(handle)


def _download_url(source: str) -> str:
    url = _project_config()["download_urls"][source]
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        raise ValueError(f"Invalid download URL configured for {source!r}")
    return url


def _as_datetime(value: datetime | date | str, *, end: bool = False) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, date):
        parsed = datetime.combine(value, datetime_time.max if end else datetime_time.min)
    else:
        text = value.strip()
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if len(text) == 10:
            parsed = datetime.combine(
                parsed.date(), datetime_time.max if end else datetime_time.min
            )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _date_windows(start: datetime, end: datetime) -> Iterable[tuple[datetime, datetime]]:
    cursor = start
    max_duration = timedelta(days=NVD_MAX_WINDOW_DAYS)
    while cursor <= end:
        window_end = min(end, cursor + max_duration - timedelta(milliseconds=1))
        yield cursor, window_end
        cursor = window_end + timedelta(milliseconds=1)


def _cache_path(start: datetime, end: datetime, start_index: int) -> Path:
    cache_dir = config.RAW_DIR / "nvd"
    cache_dir.mkdir(parents=True, exist_ok=True)
    stamp = f"{start:%Y%m%dT%H%M%S%f}_{end:%Y%m%dT%H%M%S%f}_{start_index:09d}"
    return cache_dir / f"nvd_{stamp}.json"


def _fetch_nvd_page(
    session: requests.Session,
    start: datetime,
    end: datetime,
    start_index: int,
) -> dict[str, Any]:
    cache_path = _cache_path(start, end, start_index)
    if cache_path.exists():
        with cache_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, dict):
            raise ValueError(f"Cached NVD response is not a JSON object: {cache_path}")
        return payload

    headers = {}
    api_key = config.NVD_API_KEY.strip()
    if api_key:
        headers["apiKey"] = api_key
    params = {
        "pubStartDate": _format_nvd_date(start),
        "pubEndDate": _format_nvd_date(end),
        "resultsPerPage": NVD_PAGE_SIZE,
        "startIndex": start_index,
    }
    for attempt in range(NVD_MAX_RETRIES):
        try:
            response = session.get(
                _download_url("nvd"), params=params, headers=headers, timeout=60
            )
            if response.status_code in (403, 429):
                if attempt == NVD_MAX_RETRIES - 1:
                    response.raise_for_status()
                time.sleep(min(2**attempt, 60))
                continue
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("NVD response must be a JSON object")
            temporary_path = cache_path.with_suffix(".json.tmp")
            with temporary_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False)
            temporary_path.replace(cache_path)
            return payload
        except requests.RequestException:
            if attempt == NVD_MAX_RETRIES - 1:
                raise
            time.sleep(min(2**attempt, 60))
    raise RuntimeError("NVD request retries exhausted")


def _format_nvd_date(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _first_cvss(metrics: dict[str, Any]) -> float | None:
    for version in ("cvssMetricV31", "cvssMetricV30"):
        for metric in metrics.get(version, []):
            score = metric.get("cvssData", {}).get("baseScore")
            if score is not None:
                return float(score)
    return None


def _first_cwe(weaknesses: list[dict[str, Any]]) -> str | None:
    for weakness in weaknesses:
        descriptions = weakness.get("description", [])
        for item in descriptions:
            value = item.get("value", "").strip().upper()
            if value.startswith("CWE-"):
                return value
    return None


def _products(configurations: list[dict[str, Any]]) -> set[tuple[str, str]]:
    products: set[tuple[str, str]] = set()

    def visit(nodes: list[dict[str, Any]]) -> None:
        for node in nodes:
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) < 5 or parts[:2] != ["cpe", "2.3"]:
                    continue
                vendor, product = parts[3].strip().lower(), parts[4].strip().lower()
                if vendor not in ("", "*", "-") and product not in ("", "*", "-"):
                    products.add((vendor, product))
            visit(node.get("nodes", []))
            visit(node.get("children", []))

    for configuration in configurations:
        visit(configuration.get("nodes", []))
    return products


def _fixes(references: list[dict[str, Any]]) -> set[tuple[str, str]]:
    fixes: set[tuple[str, str]] = set()
    for reference in references:
        url = reference.get("url")
        if not url:
            continue
        for tag in reference.get("tags", []):
            if tag in {"Patch", "Vendor Advisory"}:
                fixes.add((url, tag))
    return fixes


def _save_cve(conn: sqlite3.Connection, entry: dict[str, Any]) -> str | None:
    item = entry.get("cve", {})
    cve_id = item.get("id")
    if not cve_id:
        return None
    descriptions = item.get("descriptions", [])
    description = next(
        (value.get("value", "") for value in descriptions if value.get("lang") == "en"),
        "",
    )
    conn.execute(
        """INSERT INTO cve(cve_id, description, published, cvss, cwe)
        VALUES (?, ?, ?, ?, ?) ON CONFLICT(cve_id) DO UPDATE SET
        description=excluded.description, published=excluded.published,
        cvss=excluded.cvss, cwe=excluded.cwe""",
        (
            cve_id,
            description,
            item.get("published"),
            _first_cvss(item.get("metrics", {})),
            _first_cwe(item.get("weaknesses", [])),
        ),
    )
    conn.execute("DELETE FROM cve_product WHERE cve_id=?", (cve_id,))
    conn.executemany(
        "INSERT INTO cve_product(cve_id, vendor, product) VALUES (?, ?, ?)",
        [(cve_id, vendor, product) for vendor, product in _products(item.get("configurations", []))],
    )
    conn.execute("DELETE FROM fix WHERE cve_id=?", (cve_id,))
    conn.executemany(
        "INSERT INTO fix(cve_id, url, kind) VALUES (?, ?, ?)",
        [(cve_id, url, tag) for url, tag in _fixes(item.get("references", []))],
    )
    return cve_id


def sync_kev(conn: sqlite3.Connection) -> list[str]:
    """Download CISA KEV, falling back to the last valid feed when offline."""
    cache_path = config.RAW_DIR / "kev" / "known_exploited_vulnerabilities.json"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    url = _download_url("kev")
    downloaded = False
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        payload = response.json()
        downloaded = True
    except requests.RequestException:
        if not cache_path.exists():
            raise
        with cache_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)

    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("CISA KEV response is missing its vulnerabilities list")

    if downloaded:
        temporary_path = cache_path.with_suffix(".json.tmp")
        with temporary_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        temporary_path.replace(cache_path)

    db.init_db(conn)
    existing = {row[0] for row in conn.execute("SELECT cve_id FROM kev")}
    new_ids: list[str] = []
    for item in payload["vulnerabilities"]:
        cve_id = (item.get("cveID") or "").strip().upper()
        if not cve_id:
            continue
        if cve_id not in existing:
            new_ids.append(cve_id)
            existing.add(cve_id)
        conn.execute(
            """INSERT INTO kev(cve_id, date_added, due_date) VALUES (?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
            date_added=excluded.date_added, due_date=excluded.due_date""",
            (cve_id, item.get("dateAdded"), item.get("dueDate")),
        )
    conn.commit()
    return new_ids


def _epss_reader(content: bytes, required_columns: set[str]) -> csv.DictReader:
    if content.startswith(b"\x1f\x8b"):
        content = gzip.decompress(content)
    text = content.decode("utf-8-sig")
    lines = [
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        raise ValueError("EPSS feed contained no CSV header or score rows")
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not required_columns.issubset(reader.fieldnames or []):
        names = ", ".join(sorted(required_columns))
        raise ValueError(f"EPSS CSV must contain {names} columns")
    return reader


def _epss_history_path(value: str | date) -> tuple[str, Path]:
    date_text = value.isoformat() if isinstance(value, date) else value
    try:
        normalized = date.fromisoformat(date_text).isoformat()
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid EPSS history date: {date_text!r}") from exc
    return normalized, config.RAW_DIR / "epss" / f"epss_scores-{normalized}.csv.gz"


def sync_epss(conn: sqlite3.Connection) -> int:
    """Load current EPSS score and percentile only for CVEs already in `cve`."""
    response = requests.get(_download_url("epss"), timeout=120)
    response.raise_for_status()
    reader = _epss_reader(response.content, {"cve", "epss", "percentile"})

    db.init_db(conn)
    known_cves = {row[0] for row in conn.execute("SELECT cve_id FROM cve")}
    scores: dict[str, tuple[float, float]] = {}
    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        if not cve_id or cve_id not in known_cves:
            continue
        try:
            score = float(row.get("epss", ""))
            percentile = float(row.get("percentile", ""))
        except (TypeError, ValueError):
            continue
        if 0 <= score <= 1 and 0 <= percentile <= 1:
            scores[cve_id] = (score, percentile)
    conn.executemany(
        """INSERT INTO epss(cve_id, score, percentile) VALUES (?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
        score=excluded.score, percentile=excluded.percentile""",
        [
            (cve_id, score, percentile)
            for cve_id, (score, percentile) in scores.items()
        ],
    )
    conn.commit()
    return len(scores)


def download_epss_history(dates: list[str]) -> list[Path]:
    """Download archived daily EPSS scores, retaining the original gzip files."""
    requested = [_epss_history_path(value) for value in dates]
    url_template = _download_url("epss_history")
    paths: list[Path] = []
    for day, path in requested:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            with path.open("rb") as handle:
                _epss_reader(handle.read(), {"cve", "epss"})
            paths.append(path)
            continue

        response = requests.get(url_template.format(date=day), timeout=120)
        response.raise_for_status()
        content = response.content
        if not content.startswith(b"\x1f\x8b"):
            raise ValueError(f"EPSS history feed for {day} was not gzip-compressed")
        _epss_reader(content, {"cve", "epss"})
        temporary_path = path.with_suffix(path.suffix + ".tmp")
        with temporary_path.open("wb") as handle:
            handle.write(content)
        temporary_path.replace(path)
        paths.append(path)
    return paths


def load_epss_history(value: str | date) -> pd.DataFrame:
    """Load an archived EPSS file with columns `cve_id` and `score`."""
    day, path = _epss_history_path(value)
    if not path.exists():
        raise FileNotFoundError(
            f"EPSS history for {day} is missing; run download_epss_history first"
        )
    with path.open("rb") as handle:
        reader = _epss_reader(handle.read(), {"cve", "epss"})

    scores: dict[str, float] = {}
    for row in reader:
        cve_id = (row.get("cve") or "").strip().upper()
        try:
            score = float(row.get("epss", ""))
        except (TypeError, ValueError):
            continue
        if cve_id and 0 <= score <= 1:
            scores[cve_id] = score
    return pd.DataFrame(
        [(cve_id, score) for cve_id, score in scores.items()],
        columns=["cve_id", "score"],
    )


def sync_nvd(conn: sqlite3.Connection, start: str, end: str) -> dict[str, int]:
    """Ingest published NVD CVEs for an inclusive date range, using cached pages."""
    start_dt, end_dt = _as_datetime(start), _as_datetime(end, end=True)
    if start_dt > end_dt:
        raise ValueError("start must be on or before end")
    db.init_db(conn)

    processed_ids: set[str] = set()
    pages_downloaded = 0
    with requests.Session() as session:
        for window_start, window_end in _date_windows(start_dt, end_dt):
            start_index = 0
            while True:
                cache_path = _cache_path(window_start, window_end, start_index)
                was_cached = cache_path.exists()
                payload = _fetch_nvd_page(session, window_start, window_end, start_index)
                if not was_cached:
                    pages_downloaded += 1
                vulnerabilities = payload.get("vulnerabilities", [])
                if not isinstance(vulnerabilities, list):
                    raise ValueError("NVD response is missing its vulnerabilities list")
                for entry in vulnerabilities:
                    cve_id = _save_cve(conn, entry)
                    if cve_id:
                        processed_ids.add(cve_id)
                conn.commit()
                total_results = int(payload.get("totalResults", 0))
                if not vulnerabilities or start_index + len(vulnerabilities) >= total_results:
                    break
                start_index += len(vulnerabilities)
                if not _cache_path(window_start, window_end, start_index).exists():
                    time.sleep(0.7 if config.NVD_API_KEY.strip() else 6)

    db.rebuild_fts(conn)
    return {
        "cves_processed": len(processed_ids),
        "cves_total": conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0],
        "products_total": conn.execute("SELECT COUNT(*) FROM cve_product").fetchone()[0],
        "fixes_total": conn.execute("SELECT COUNT(*) FROM fix").fetchone()[0],
        "pages_downloaded": pages_downloaded,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="PatchPilot data ingestion")
    subparsers = ap.add_subparsers(dest="cmd", required=True)
    fixture_parser = subparsers.add_parser(
        "fixture", help="Load the synthetic development fixture"
    )
    fixture_parser.add_argument("--db", default=str(config.FIXTURE_DB_PATH))
    nvd_parser = subparsers.add_parser("nvd", help="Sync published CVEs from NVD API 2.0")
    nvd_parser.add_argument("--start", default="2024-01-01")
    nvd_parser.add_argument("--end", default="2025-12-31")
    subparsers.add_parser("kev", help="Sync the CISA Known Exploited Vulnerabilities catalog")
    subparsers.add_parser("epss", help="Sync current EPSS scores for known CVEs")
    history_parser = subparsers.add_parser(
        "epss-history", help="Download archived daily EPSS score files"
    )
    history_parser.add_argument("dates", nargs="+")
    snapshot_parser = subparsers.add_parser(
        "snapshot", help="Build the real NVD, KEV, EPSS, and FTS snapshot"
    )
    snapshot_parser.add_argument("--start", default="2025-10-01")
    snapshot_parser.add_argument("--end", default="2025-12-31")
    args = ap.parse_args()
    conn = db.connect(args.db if args.cmd == "fixture" else None)
    try:
        if args.cmd == "fixture":
            n = load_fixture(conn)
            print(f"Loaded {n} synthetic CVEs into {args.db}")
        elif args.cmd == "nvd":
            counts = sync_nvd(conn, args.start, args.end)
            print(
                "NVD sync complete: "
                f"{counts['cves_processed']} processed, "
                f"{counts['cves_total']} total CVEs, "
                f"{counts['products_total']} products, "
                f"{counts['fixes_total']} fix links, "
                f"{counts['pages_downloaded']} pages downloaded."
            )
        elif args.cmd == "kev":
            new_ids = sync_kev(conn)
            print(f"CISA KEV sync complete: {len(new_ids)} new CVEs.")
        elif args.cmd == "epss":
            count = sync_epss(conn)
            print(f"EPSS sync complete: {count} known CVEs updated.")
        elif args.cmd == "epss-history":
            paths = download_epss_history(args.dates)
            print(f"Downloaded or reused {len(paths)} EPSS history files.")
        elif args.cmd == "snapshot":
            nvd_counts = sync_nvd(conn, args.start, args.end)
            new_kev_ids = sync_kev(conn)
            sync_epss(conn)
            mark_kev_seen(conn)
            conn.execute("VACUUM")
            counts = {
                "cves": conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0],
                "products": conn.execute("SELECT COUNT(*) FROM cve_product").fetchone()[0],
                "fixes": conn.execute("SELECT COUNT(*) FROM fix").fetchone()[0],
                "kev": conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0],
                "epss": conn.execute("SELECT COUNT(*) FROM epss").fetchone()[0],
                "fts": conn.execute("SELECT COUNT(*) FROM cve_fts").fetchone()[0],
            }
            print(
                "Snapshot complete: "
                f"{counts['cves']} CVEs, {counts['products']} products, "
                f"{counts['fixes']} fixes, {counts['kev']} KEV, "
                f"{counts['epss']} EPSS, {counts['fts']} FTS rows; "
                f"{nvd_counts['pages_downloaded']} NVD pages downloaded; "
                f"{len(new_kev_ids)} new KEV entries."
            )
    finally:
        conn.close()


if __name__ == "__main__":
    main()
