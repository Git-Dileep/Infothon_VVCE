"""Graph data model over SQLite tables (no Neo4j). OWNER: Person 4.

Nodes: CVE, CWE, Product, Fix, Asset.  Edges: CVE-CWE, CVE-Product, CVE-Fix, Product-Asset.
"""
from __future__ import annotations

import html
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


def _short_url(url: str) -> str:
    """Return a shortened URL label for display (domain + last path part)."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        path_parts = [p for p in parsed.path.split("/") if p]
        if path_parts:
            return f"{domain}/…/{path_parts[-1][:30]}"
        return domain
    except Exception:
        return url[:40]


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
    kev_badge = "⚠️ ACTIVE EXPLOIT" if is_kev else "No"
    cve_title = f"<b>🔒 {cve_id}</b><br>CVSS: {cvss or 'N/A'}<br>KEV: {kev_badge}"
    g.add_node(
        cve_id,
        label=f"🔒 {cve_id}",
        color=cve_color,
        title=cve_title,
        node_type="CVE",
        size=30,
        shape="dot",
        font={"size": 14, "color": "#ffffff", "face": "monospace", "bold": True},
    )

    # 2. Add CWE node
    if cwe and str(cwe).strip() and str(cwe).lower() != "none":
        cwe_clean = str(cwe).strip()
        g.add_node(
            cwe_clean,
            label=f"🛡️ {cwe_clean}",
            color=NODE_COLORS["CWE"],
            title=f"<b>Weakness Category</b><br>{cwe_clean}",
            node_type="CWE",
            size=20,
            shape="diamond",
            font={"size": 12, "color": "#ffffff"},
        )
        g.add_edge(cve_id, cwe_clean, label="classifies", color="#9467bd", width=2)

    # 3. Add Fix / Advisory nodes (up to 5) — CLICKABLE with URL
    fixes = conn.execute(
        "SELECT url, kind FROM fix WHERE cve_id = ? LIMIT 5", (cve_id,)
    ).fetchall()
    for i, (url, kind) in enumerate(fixes):
        fix_id = f"fix:{cve_id}:{i}"
        kind_label = kind or "Fix"
        short_label = _short_url(url) if url else kind_label
        safe_url = html.escape(url or "", quote=True)
        # Title shows full URL as clickable link
        fix_title = (
            f"<b>🔧 {kind_label}</b><br>"
            f"<a href='{safe_url}' target='_blank' style='color:#2ca02c;'>{safe_url}</a><br>"
            f"<i>Click node to open link ↗</i>"
        )
        g.add_node(
            fix_id,
            label=f"🔧 {kind_label}\n{short_label}",
            color=NODE_COLORS["Fix"],
            title=fix_title,
            node_type="Fix",
            size=18,
            shape="triangle",
            url=url or "",
            font={"size": 10, "color": "#ffffff", "multi": True},
        )
        g.add_edge(cve_id, fix_id, label="remediated by", color="#2ca02c", width=2)

    # 4. Add Product nodes and connected Company Assets (cap total nodes to ~25)
    products = conn.execute(
        "SELECT vendor, product FROM cve_product WHERE cve_id = ? LIMIT 6", (cve_id,)
    ).fetchall()

    for vendor, product in products:
        prod_id = f"prod:{vendor}:{product}"
        prod_label = f"{vendor} {product}"
        g.add_node(
            prod_id,
            label=f"📦 {prod_label}",
            color=NODE_COLORS["Product"],
            title=f"<b>Affected Product</b><br>{prod_label}",
            node_type="Product",
            size=22,
            shape="dot",
            font={"size": 11, "color": "#ffffff"},
        )
        g.add_edge(cve_id, prod_id, label="affects", color="#1f77b4", width=2)

        # Find internal matched assets for this vendor + product
        matched_assets = conn.execute(
            """SELECT name, criticality FROM asset
               WHERE lower(vendor) = lower(?) AND lower(product) = lower(?)
               LIMIT 4""",
            (vendor, product),
        ).fetchall()

        for a_name, a_crit in matched_assets:
            asset_id = f"asset:{a_name}"
            crit_bar = "🔴" if a_crit >= 0.8 else ("🟡" if a_crit >= 0.5 else "🟢")
            g.add_node(
                asset_id,
                label=f"🖥️ {a_name}",
                color=NODE_COLORS["Asset"],
                title=f"<b>Internal Asset</b><br>{a_name}<br>Criticality: {crit_bar} {a_crit:.1f}",
                node_type="Asset",
                size=20,
                shape="box",
                font={"size": 11, "color": "#ffffff"},
            )
            g.add_edge(prod_id, asset_id, label="deployed on", color="#ff7f0e", width=2)

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
          "gravitationalConstant": -60,
          "centralGravity": 0.01,
          "springLength": 120,
          "springConstant": 0.06
        },
        "maxVelocity": 40,
        "solver": "forceAtlas2Based",
        "timestep": 0.35,
        "stabilization": {"iterations": 150}
      },
      "edges": {
        "smooth": {"type": "continuous"},
        "font": {"size": 11, "color": "#aaaaaa", "strokeWidth": 0, "align": "middle"},
        "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}}
      },
      "interaction": {
        "hover": true,
        "zoomView": true,
        "navigationButtons": true,
        "tooltipDelay": 100
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
            font=data.get("font", {"size": 12, "color": "#ffffff"}),
            url=data.get("url", ""),
        )

    for u, v, data in g.edges(data=True):
        net.add_edge(
            u,
            v,
            title=data.get("label", ""),
            label=data.get("label", ""),
            color=data.get("color", "#888888"),
            width=data.get("width", 1),
        )

    raw_html = net.generate_html()
    
    # Inject JavaScript click handler to open Fix/Advisory URLs in new tab
    click_handler = """
    <script type="text/javascript">
    document.addEventListener('DOMContentLoaded', function() {
        // Wait for vis.js network to be ready
        setTimeout(function() {
            try {
                var container = document.querySelector('.vis-network');
                if (!container) return;
                
                // Access the vis.js network instance
                var networkEl = document.getElementById(Object.keys(network)[0] || 'mynetwork');
                
                // Listen for double-click on nodes
                network.on("doubleClick", function(params) {
                    if (params.nodes.length > 0) {
                        var nodeId = params.nodes[0];
                        var nodeData = network.body.data.nodes.get(nodeId);
                        if (nodeData && nodeData.url && nodeData.url.length > 0) {
                            window.open(nodeData.url, '_blank');
                        }
                    }
                });
                
                // Also handle single click for convenience
                network.on("click", function(params) {
                    if (params.nodes.length > 0) {
                        var nodeId = params.nodes[0];
                        var nodeData = network.body.data.nodes.get(nodeId);
                        if (nodeData && nodeData.url && nodeData.url.length > 0) {
                            window.open(nodeData.url, '_blank');
                        }
                    }
                });
            } catch(e) {
                // Silently ignore if network not yet ready
            }
        }, 1500);
    });
    </script>
    """
    
    # Insert click handler before closing </body>
    raw_html = raw_html.replace("</body>", click_handler + "</body>")
    
    return raw_html
