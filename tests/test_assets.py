import sqlite3
import pandas as pd
from patchpilot import db, ingest, assets, scoring


def test_asset_matching_and_import():
    conn = db.connect(":memory:")
    db.init_db(conn)
    ingest.load_fixture(conn)

    # 1. Test match_asset with messy names
    v, p, conf = assets.match_asset(conn, "Prod DB server (dbcorp datastore)")
    assert v == "dbcorp" and p == "datastore" and conf >= 0.85

    v, p, conf = assets.match_asset(conn, "HR system acme ERP")
    assert v == "acme" and p == "erp" and conf >= 0.85

    initial_count = len(assets.list_assets(conn))
    # 2. Test import from sample CSV
    n = assets.import_assets_csv(conn, "data/fixture/sample_assets.csv")
    assert n == 6

    asset_df = assets.list_assets(conn)
    assert len(asset_df) == initial_count + 6
    assert set(asset_df["vendor"].dropna()) == {
        "dbcorp", "webly", "netwave", "cloudkit", "acme", "lfprojects"
    }
    valkey = asset_df[asset_df["product"] == "valkey"].iloc[0]
    assert valkey["vendor"] == "lfprojects" and valkey["criticality"] == 1.0

    # 3. Test that queue re-ranks based on matched assets
    q = scoring.ranked_queue(conn)
    matched_q = scoring.ranked_queue(conn, only_matched=True)
    assert len(matched_q) > 0
    assert (matched_q["asset_crit"] > 0).all()
