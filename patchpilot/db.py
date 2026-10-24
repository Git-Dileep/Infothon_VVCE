"""SQLite schema + connection helpers. OWNER: Person 1. Schema changes need an all-hands PR."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    published TEXT,          -- ISO date
    cvss REAL,               -- CVSS v3.x base score, NULL if not analysed yet
    cwe TEXT                 -- e.g. 'CWE-89', NULL if unknown
);
CREATE TABLE IF NOT EXISTS cve_product (
    cve_id TEXT NOT NULL,
    vendor TEXT NOT NULL,    -- lowercase CPE vendor
    product TEXT NOT NULL    -- lowercase CPE product
);
CREATE INDEX IF NOT EXISTS ix_cve_product_cve ON cve_product(cve_id);
CREATE INDEX IF NOT EXISTS ix_cve_product_vp ON cve_product(vendor, product);
CREATE TABLE IF NOT EXISTS fix (
    cve_id TEXT NOT NULL,
    url TEXT NOT NULL,
    kind TEXT NOT NULL       -- 'Patch' | 'Vendor Advisory'
);
CREATE INDEX IF NOT EXISTS ix_fix_cve ON fix(cve_id);
CREATE TABLE IF NOT EXISTS kev (
    cve_id TEXT PRIMARY KEY,
    date_added TEXT,
    due_date TEXT
);
CREATE TABLE IF NOT EXISTS kev_seen (   -- KEV ids already shown to the user (new-KEV detector)
    cve_id TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS epss (
    cve_id TEXT PRIMARY KEY,
    score REAL,
    percentile REAL
);
CREATE TABLE IF NOT EXISTS asset (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    criticality REAL NOT NULL DEFAULT 0.5,   -- 0..1
    match_confidence REAL                    -- 0..1, NULL = not matched yet
);
CREATE VIRTUAL TABLE IF NOT EXISTS cve_fts USING fts5(cve_id UNINDEXED, description);
"""


def connect(path: str | None = None) -> sqlite3.Connection:
    path = path or config.DB_PATH
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def rebuild_fts(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM cve_fts")
    conn.execute("INSERT INTO cve_fts(cve_id, description) SELECT cve_id, description FROM cve")
    conn.commit()
