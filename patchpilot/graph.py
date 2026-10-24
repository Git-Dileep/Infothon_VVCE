"""Graph data model over SQLite tables (no Neo4j). OWNER: Person 4.

Nodes: CVE, CWE, Product, Fix, Asset.  Edges: CVE-CWE, CVE-Product, CVE-Fix, Product-Asset.
"""
from __future__ import annotations

import sqlite3
import networkx as nx
from pyvis.network import Network

# Node color palette
NODE_COLORS = {
    "CVE_KEV": "#d62728",     # Red for actively exploited KEV CVE
    "CVE": "#e0b000",         # Gold for standard CVE
    "CWE": "#9467bd",         # Purple for CWE category
    "Product": "#1f77b4",     # Blue for Vendor/Product
    "Fix": "#2ca02c",         # Green for Patch / Vendor Advisory
    "Asset": "#ff7f0e",       # Orange for internal Company Asset
}


def build_graph(conn: sqlite3.Connection, cve_id: str) -> nx.Graph:
    """Neighbourhood of one CVE. (issue P4-3 / Dimple-3)
    Nodes: CVE, CWE, Product, Fix, Asset.
    Edges: CVE-CWE, CVE-Product, CVE-Fix, Product-Asset.
    Max ~25 nodes to keep the visualization clear and fast.
    """
    g = nx.Graph()

    # 1. Fetch CVE row
    cve_row = conn.execute(
        "SELECT cve_id, cvss, cwe FROM cve WHERE cve_id = ?", (cve_id,)
    ).fetchone()
    if not cve_row:
        return g

    _, cvss, cwe = cve_row
    is_kev = bool(conn.execute("SELECT 1 FROM kev WHERE cve_id = ?", (cve_id,)).fetchone())

    # Add central CVE node
    cve_color = NODE_COLORS["CVE_KEV"] if is_kev else NODE_COLORS["CVE"]
    cve_title = f"{cve_id}<br>CVSS: {cvss or 'N/A'}<br>KEV: {'Yes (Active Exploitation)' if is_kev else 'No'}"
    g.add_node(
        cve_id,
        label=cve_id,
        color=cve_color,
        title=cve_title,
        node_type="CVE",
        size=26,
        shape="dot",
    )

    # 2. Add CWE node
    if cwe and str(cwe).strip() and str(cwe).lower() != "none":
        cwe_clean = str(cwe).strip()
        g.add_node(
            cwe_clean,
            label=cwe_clean,
            color=NODE_COLORS["CWE"],
            title=f"Weakness Type: {cwe_clean}",
            node_type="CWE",
            size=18,
            shape="diamond",
        )
        g.add_edge(cve_id, cwe_clean, label="classifies", color="#cccccc")

    # 3. Add Fix / Advisory nodes (up to 5)
    fixes = conn.execute(
        "SELECT url, kind FROM fix WHERE cve_id = ? LIMIT 5", (cve_id,)
    ).fetchall()
    for i, (url, kind) in enumerate(fixes):
        fix_id = f"fix:{cve_id}:{i}"
        kind_label = kind or "Fix"
        g.add_node(
            fix_id,
            label=f"{kind_label}",
            color=NODE_COLORS["Fix"],
            title=f"{kind_label}: {url}",
            node_type="Fix",
            size=16,
            shape="triangle",
        )
        g.add_edge(cve_id, fix_id, label="remediated by", color="#2ca02c")

    # 4. Add Product nodes and connected Company Assets (cap total nodes to ~25)
    products = conn.execute(
        "SELECT vendor, product FROM cve_product WHERE cve_id = ? LIMIT 6", (cve_id,)
    ).fetchall()

    for vendor, product in products:
        prod_id = f"prod:{vendor}:{product}"
        prod_label = f"{vendor} {product}"
        g.add_node(
            prod_id,
            label=prod_label,
            color=NODE_COLORS["Product"],
            title=f"Affected Product: {prod_label}",
            node_type="Product",
            size=20,
            shape="dot",
        )
        g.add_edge(cve_id, prod_id, label="affects", color="#1f77b4")

        # Find internal matched assets for this vendor + product
        assets = conn.execute(
            """SELECT name, criticality FROM asset
               WHERE lower(vendor) = lower(?) AND lower(product) = lower(?)
               LIMIT 4""",
            (vendor, product),
        ).fetchall()

        for a_name, a_crit in assets:
            asset_id = f"asset:{a_name}"
            g.add_node(
                asset_id,
                label=f"🖥️ {a_name}",
                color=NODE_COLORS["Asset"],
                title=f"Internal Asset: {a_name}<br>Criticality: {a_crit}",
                node_type="Asset",
                size=18,
                shape="box",
            )
            g.add_edge(prod_id, asset_id, label="deployed on", color="#ff7f0e")

    return g


def render_html(g: nx.Graph) -> str:
    """Return standalone pyvis HTML for st.components.v1.html. (issue P4-3 / Dimple-3)"""
    if len(g.nodes) == 0:
        return "<div style='color:gray; padding:20px; font-family:sans-serif;'>No graph elements found for this vulnerability.</div>"

    net = Network(height="580px", width="100%", bgcolor="#0e1117", font_color="#fafafa", cdn_resources="in_line")
    
    # Configure smooth physics & interactive controls
    net.set_options("""
    {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -50,
          "centralGravity": 0.01,
          "springLength": 100,
          "springConstant": 0.08
        },
        "maxVelocity": 40,
        "solver": "forceAtlas2Based",
        "timestep": 0.35,
        "stabilization": {"iterations": 120}
      },
      "edges": {
        "smooth": {"type": "continuous"}
      },
      "interaction": {
        "hover": true,
        "zoomView": true,
        "navigationButtons": true
      }
    }
    """)

    # Populate pyvis network from nx.Graph
    for node, data in g.nodes(data=True):
        net.add_node(
            node,
            label=data.get("label", str(node)),
            color=data.get("color", "#97c2fc"),
            title=data.get("title", str(node)),
            size=data.get("size", 16),
            shape=data.get("shape", "dot"),
        )

    for u, v, data in g.edges(data=True):
        net.add_edge(
            u,
            v,
            title=data.get("label", ""),
            color=data.get("color", "#888888"),
        )

    return net.generate_html()

