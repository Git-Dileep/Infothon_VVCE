"""Graph data model over SQLite tables (no Neo4j). OWNER: Person 4.

Nodes: CVE, CWE, Product, Fix, Asset.  Edges: CVE-CWE, CVE-Product, CVE-Fix, Product-Asset.
"""
from __future__ import annotations

import sqlite3

import networkx as nx


def build_graph(conn: sqlite3.Connection, cve_id: str) -> nx.Graph:
    """Neighbourhood of one CVE. (issue P4-3)"""
    raise NotImplementedError("P4-3: implement graph build")


def render_html(g: nx.Graph) -> str:
    """Return pyvis HTML for st.components.v1.html. (issue P4-3)"""
    raise NotImplementedError("P4-3: implement pyvis render")
