"""Asset inventory + fuzzy matching to vendor/product. OWNER: Person 4."""
from __future__ import annotations

import sqlite3

import pandas as pd


import io
from rapidfuzz import fuzz, process


def list_assets(conn: sqlite3.Connection) -> pd.DataFrame:
    return pd.read_sql_query(
        "SELECT id, name, vendor, product, criticality, match_confidence FROM asset ORDER BY id", conn
    )


def match_asset(conn: sqlite3.Connection, name: str) -> tuple[str | None, str | None, float]:
    """RapidFuzz match of a messy name to a known (vendor, product) in cve_product.
    Returns (vendor, product, confidence 0..1). (issue P4-2)"""
    if not name or not name.strip():
        return None, None, 0.0

    pairs = conn.execute(
        "SELECT DISTINCT vendor, product FROM cve_product WHERE vendor IS NOT NULL AND product IS NOT NULL"
    ).fetchall()
    if not pairs:
        return None, None, 0.0

    # Build candidate strings like 'dbcorp datastore'
    candidates = [f"{v.lower()} {p.lower()}" for v, p in pairs]

    result = process.extractOne(
        name.lower(),
        candidates,
        scorer=fuzz.WRatio,
        score_cutoff=0,
    )
    if not result:
        return None, None, 0.0

    best_match_str, score, idx = result
    confidence = round(score / 100.0, 4)
    best_vendor, best_product = pairs[idx]

    # Threshold rules: confidence >= 0.60 mapped; below 0.60 considered unmatched
    if confidence < 0.60:
        return None, None, confidence

    return best_vendor.lower(), best_product.lower(), confidence


def import_assets_csv(conn: sqlite3.Connection, file) -> int:
    """CSV columns: name, criticality (0..1) [, vendor, product]. Match missing vendor/product
    with match_asset(). Returns rows imported. (issue P4-2)"""
    if isinstance(file, str):
        if "\n" in file or "," in file:
            df = pd.read_csv(io.StringIO(file))
        else:
            df = pd.read_csv(file)
    elif isinstance(file, bytes):
        df = pd.read_csv(io.BytesIO(file))
    elif hasattr(file, "read"):
        df = pd.read_csv(file)
    else:
        df = pd.DataFrame(file)

    if "name" not in df.columns or "criticality" not in df.columns:
        raise ValueError("CSV must contain 'name' and 'criticality' columns.")

    rows_inserted = 0
    cur = conn.cursor()

    for _, row in df.iterrows():
        name = str(row["name"]).strip()
        criticality = float(row["criticality"])
        criticality = max(0.0, min(1.0, criticality))

        vendor = row.get("vendor")
        product = row.get("product")
        confidence = row.get("match_confidence")

        # If vendor or product missing, use RapidFuzz
        if pd.isna(vendor) or pd.isna(product) or not str(vendor).strip() or not str(product).strip():
            matched_v, matched_p, conf = match_asset(conn, name)
            vendor = matched_v
            product = matched_p
            confidence = conf
        else:
            vendor = str(vendor).strip().lower()
            product = str(product).strip().lower()
            confidence = float(confidence) if pd.notna(confidence) else 1.0

        cur.execute(
            """INSERT INTO asset (name, vendor, product, criticality, match_confidence)
               VALUES (?, ?, ?, ?, ?)""",
            (name, vendor, product, criticality, confidence),
        )
        rows_inserted += 1

    conn.commit()
    return rows_inserted


def update_asset(conn: sqlite3.Connection, asset_id: int, vendor: str, product: str, confidence: float = 1.0) -> None:
    """Update asset vendor/product mappings during user review in the UI."""
    conn.execute(
        "UPDATE asset SET vendor = ?, product = ?, match_confidence = ? WHERE id = ?",
        (vendor.strip().lower(), product.strip().lower(), confidence, asset_id),
    )
    conn.commit()

