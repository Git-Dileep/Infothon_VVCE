import sqlite3
import networkx as nx
from patchpilot import db, ingest, graph


def test_graph_construction_and_render():
    conn = db.connect(":memory:")
    db.init_db(conn)
    ingest.load_fixture(conn)

    # Build graph for CVE-2099-0002 (which has KEV, CWE, Products, Fixes, Assets)
    g = graph.build_graph(conn, "CVE-2099-0002")
    assert isinstance(g, nx.Graph)
    assert len(g.nodes) > 1
    assert "CVE-2099-0002" in g.nodes
    assert g.nodes["CVE-2099-0002"]["node_type"] == "CVE"
    assert g.nodes["CVE-2099-0002"]["color"] == graph.NODE_COLORS["CVE_KEV"]

    # Verify relationships (CWE, Product, Fix)
    node_types = {data["node_type"] for _, data in g.nodes(data=True)}
    assert "CWE" in node_types
    assert "Product" in node_types
    assert "Fix" in node_types

    # Render HTML test
    html = graph.render_html(g)
    assert isinstance(html, str)
    assert "<html" in html.lower()
    assert "CVE-2099-0002" in html
