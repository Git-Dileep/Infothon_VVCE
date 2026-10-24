"""Asset inventory + fuzzy matching to vendor/product. OWNER: Person 4."""
from __future__ import annotations

import sqlite3

import pandas as pd


def list_assets(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT id, name, vendor, product, criticality, match_confidence FROM asset ORDER BY id", conn
    )


def import_assets_csv(conn: sqlite3.Connection, file) -> int:
    """CSV columns: name, criticality (0..1) [, vendor, product]. Match missing vendor/product
    with match_asset(). Returns rows imported. (issue P4-2)"""
    raise NotImplementedError("P4-2: implement CSV import")


def match_asset(conn: sqlite3.Connection, name: str) -> tuple[str | None, str | None, float]:
    """RapidFuzz match of a messy name to a known (vendor, product) in cve_product.
    Returns (vendor, product, confidence 0..1). (issue P4-2)"""
    raise NotImplementedError("P4-2: implement fuzzy match")
