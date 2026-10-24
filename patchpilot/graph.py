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
    kev_badge = "⚠️ ACTIVE CISA KEV EXPLOIT" if is_kev else "Standard CVE"
    cve_title = f"<b>🔒 {cve_id}</b><br>CVSS Score: {cvss or 'N/A'}<br>Status: {kev_badge}"
    cve_label = f"🔒 {cve_id}\nCVSS: {cvss or 'N/A'}" + ("\n⚠️ KEV EXPLOITED" if is_kev else "")
    g.add_node(
        cve_id,
        label=cve_label,
        color=cve_color,
        title=cve_title,
        node_type="CVE Vulnerability",
        size=32,
        shape="dot",
        font={"size": 13, "color": "#ffffff", "face": "monospace", "bold": True, "multi": True},
    )

    # 2. Add CWE node
    if cwe and str(cwe).strip() and str(cwe).lower() != "none":
        cwe_clean = str(cwe).strip()
        g.add_node(
            cwe_clean,
            label=f"🛡️ Weakness Type\n{cwe_clean}",
            color=NODE_COLORS["CWE"],
            title=f"<b>🛡️ Common Weakness Enumeration</b><br>{cwe_clean}",
            node_type="CWE Weakness",
            size=22,
            shape="diamond",
            font={"size": 11, "color": "#ffffff", "multi": True},
        )
        g.add_edge(cve_id, cwe_clean, label="classified as", color="#9467bd", width=2)

    # 3. Add Fix / Advisory nodes (up to 5) — CLICKABLE with URL
    fixes = conn.execute(
        "SELECT url, kind FROM fix WHERE cve_id = ? LIMIT 5", (cve_id,)
    ).fetchall()
    for i, (url, kind) in enumerate(fixes):
        fix_id = f"fix:{cve_id}:{i}"
        kind_label = (kind or "Vendor Fix").title()
        short_label = _short_url(url) if url else kind_label
        safe_url = html.escape(url or "", quote=True)
        fix_title = (
            f"<b>🔧 {kind_label}</b><br>"
            f"Click to open: <a href='{safe_url}' target='_blank' style='color:#4ade80;'>{safe_url}</a>"
        )
        g.add_node(
            fix_id,
            label=f"🔧 {kind_label}\n{short_label}\n↗ Open Link",
            color=NODE_COLORS["Fix"],
            title=fix_title,
            node_type="Fix / Security Advisory",
            size=22,
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
        prod_display = f"{vendor} / {product}"
        g.add_node(
            prod_id,
            label=f"📦 Software\n{prod_display}",
            color=NODE_COLORS["Product"],
            title=f"<b>📦 Affected Software</b><br>Vendor: {vendor}<br>Product: {product}",
            node_type="Affected Product",
            size=22,
            shape="dot",
            font={"size": 11, "color": "#ffffff", "multi": True},
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
            crit_badge = "🔴 Critical" if a_crit >= 0.8 else ("🟡 Medium" if a_crit >= 0.5 else "🟢 Low")
            g.add_node(
                asset_id,
                label=f"🖥️ Asset\n{a_name}\n({crit_badge} {a_crit:.1f})",
                color=NODE_COLORS["Asset"],
                title=f"<b>🖥️ Internal Company Asset</b><br>Name: {a_name}<br>Criticality: {crit_badge} ({a_crit:.2f})",
                node_type="Internal Asset",
                size=22,
                shape="box",
                font={"size": 10, "color": "#ffffff", "multi": True},
            )
            g.add_edge(prod_id, asset_id, label="deployed on", color="#ff7f0e", width=2)

    return g


def render_html(g: nx.Graph) -> str:
    """Return standalone pyvis HTML for st.components.v1.html with click handlers and interactive banner."""
    if len(g.nodes) == 0:
        return "<div style='color:gray; padding:20px; font-family:sans-serif;'>No graph elements found for this vulnerability.</div>"

    net = Network(height="580px", width="100%", bgcolor="#0e1117", font_color="#fafafa", cdn_resources="in_line")
    
    # Configure smooth physics & interactive controls
    net.set_options("""
    {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -65,
          "centralGravity": 0.015,
          "springLength": 130,
          "springConstant": 0.06
        },
        "maxVelocity": 40,
        "solver": "forceAtlas2Based",
        "timestep": 0.35,
        "stabilization": {"iterations": 120}
      },
      "edges": {
        "smooth": {"type": "continuous"},
        "font": {"size": 11, "color": "#8b949e", "strokeWidth": 0, "align": "middle"},
        "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}}
      },
      "interaction": {
        "hover": true,
        "zoomView": true,
        "navigationButtons": true,
        "tooltipDelay": 80
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
            size=data.get("size", 18),
            shape=data.get("shape", "dot"),
            font=data.get("font", {"size": 11, "color": "#ffffff"}),
            url=data.get("url", ""),
            node_type=data.get("node_type", "Entity"),
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
    
    # Inject JavaScript handler that displays an interactive node banner & opens URLs
    click_handler = """
    <script type="text/javascript">
    (function() {
        function setupInteractiveGraph() {
            if (typeof network === 'undefined' || typeof nodes === 'undefined') {
                setTimeout(setupInteractiveGraph, 200);
                return;
            }

            var container = document.getElementById('mynetwork') || document.body;
            container.style.position = 'relative';

            // Top overlay banner showing active node details and clickable buttons
            var banner = document.createElement('div');
            banner.id = 'interactive-node-banner';
            banner.style.cssText = 'position: absolute; top: 12px; left: 14px; right: 14px; background: rgba(13, 17, 23, 0.94); border: 1px solid #30363d; border-radius: 8px; padding: 10px 16px; color: #f0f6fc; font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif; font-size: 13px; z-index: 1000; box-shadow: 0 4px 16px rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px;';
            banner.innerHTML = '<span style="color: #8b949e;">💡 <b>Click any node</b> to inspect details. Clicking a green 🔧 <b>Fix / Advisory</b> node will open its official vendor link.</span>';
            container.appendChild(banner);

            function onNodeClick(nodeId) {
                var nodeData = nodes.get(nodeId);
                if (!nodeData) return;

                var url = nodeData.url;
                var rawLabel = (nodeData.label || nodeId).replace(/\\n/g, ' ');
                var nodeType = nodeData.node_type || "Entity";

                if (url && url.length > 0) {
                    banner.innerHTML = '<div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">' +
                        '<span style="background: #238636; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">🔧 ' + nodeType.toUpperCase() + '</span>' +
                        '<span style="color: #ffffff; font-weight: 600;">' + rawLabel + '</span>' +
                        '</div>' +
                        '<div style="display: flex; align-items: center; gap: 10px;">' +
                        '<a href="' + url + '" target="_blank" rel="noopener noreferrer" style="background: #2ea043; color: white; padding: 6px 14px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 12px; display: inline-flex; align-items: center; gap: 6px; border: 1px solid rgba(255,255,255,0.2); box-shadow: 0 2px 6px rgba(46,160,67,0.4);">↗ Open Vendor Fix / Advisory</a>' +
                        '</div>';
                    
                    // Attempt programmatic click via synthesized <a> element
                    try {
                        var a = document.createElement('a');
                        a.href = url;
                        a.target = '_blank';
                        a.rel = 'noopener noreferrer';
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                    } catch(e) {
                        try { window.open(url, '_blank'); } catch(e2) {}
                    }
                } else {
                    var badgeColor = nodeType.includes("CVE") ? "#d62728" : (nodeType.includes("Asset") ? "#ff7f0e" : (nodeType.includes("Weakness") ? "#9467bd" : "#1f77b4"));
                    banner.innerHTML = '<div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">' +
                        '<span style="background: ' + badgeColor + '; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">' + nodeType.toUpperCase() + '</span>' +
                        '<span style="color: #ffffff; font-weight: 600;">' + rawLabel + '</span>' +
                        '</div>' +
                        '<span style="color: #8b949e; font-size: 12px;">' + (nodeData.title ? nodeData.title.replace(/<[^>]*>/g, ' • ') : '') + '</span>';
                }
            }

            network.on("click", function(params) {
                if (params.nodes && params.nodes.length > 0) {
                    onNodeClick(params.nodes[0]);
                }
            });

            network.on("doubleClick", function(params) {
                if (params.nodes && params.nodes.length > 0) {
                    onNodeClick(params.nodes[0]);
                }
            });
        }

        if (document.readyState === 'complete' || document.readyState === 'interactive') {
            setTimeout(setupInteractiveGraph, 300);
        } else {
            document.addEventListener('DOMContentLoaded', function() {
                setTimeout(setupInteractiveGraph, 300);
            });
        }
    })();
    </script>
    """
    
    # Insert click handler before closing </body>
    raw_html = raw_html.replace("</body>", click_handler + "</body>")
    
    return raw_html

