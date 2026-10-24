"""PatchPilot Streamlit app. OWNER: Person 4. Run: streamlit run app.py"""
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from patchpilot import assistant, assets, config, db, ingest, scoring

st.set_page_config(page_title="PatchPilot", layout="wide")
conn = db.connect()
db.init_db(conn)

TIER_COLORS = {"Critical": "#d62728", "High": "#ff7f0e", "Medium": "#e0b000", "Low": "#2ca02c"}

# ---------------- sidebar ----------------
with st.sidebar:
    st.title("PatchPilot")
    st.caption(f"DB: `{config.DB_PATH}`")
    n_cves = conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
    if n_cves == 0:
        st.warning("Database is empty.")
        if st.button("Load synthetic fixture"):
            ingest.load_fixture(conn)
            st.rerun()
    st.divider()
    demo_mode = st.toggle("Demo mode (simulate KEV feed)", value=True)
    if st.button("Check for new KEV entries", type="primary"):
        try:
            if demo_mode:
                new_cve = ingest.simulate_new_kev(conn)
            else:
                ingest.sync_kev(conn)
            new_entries = ingest.new_kev_since_last_sync(conn)
            st.session_state["new_kev"] = new_entries
            ingest.mark_kev_seen(conn)
            st.rerun()
        except NotImplementedError as e:
            st.info(str(e))
        except Exception as e:
            st.error(f"KEV sync error: {e}")

if n_cves == 0:
    st.stop()

# ---------------- New KEV Alert Banner & Patch Plan ----------------
new_kev_list = st.session_state.get("new_kev", [])
if new_kev_list:
    st.error(
        f"🚨 **NEW CISA KEV ALERT DETECTED ({len(new_kev_list)} new entry):** "
        f"**{', '.join(new_kev_list)}** added to Known Exploited Vulnerabilities catalog. "
        "Queue automatically re-ranked to prioritize in-the-wild threats."
    )
    # Auto-generate patch plan sentences from scoring.explain (no LLM needed)
    with st.expander("⚡ **Immediate Auto-Generated Patch Plan**", expanded=True):
        for cve_id in new_kev_list:
            try:
                ex = scoring.explain(conn, cve_id)
                matched_str = ", ".join(ex["matched_assets"]) if ex["matched_assets"] else "general infrastructure"
                st.markdown(
                    f"- **{cve_id}** (Elevated to **{ex['tier']}**, Risk Score **{ex['score']:.4f}**): "
                    f"Affects **{matched_str}**. Active exploitation confirmed in the wild. "
                    f"Immediate remediation required: apply vendor security patch or isolate affected endpoints."
                )
            except Exception:
                st.markdown(f"- **{cve_id}**: Elevated to Critical due to active CISA KEV listing.")
        if st.button("Acknowledge & Dismiss Alert"):
            st.session_state["new_kev"] = []
            st.rerun()

queue = scoring.ranked_queue(conn)
tab_q, tab_chat, tab_assets, tab_graph = st.tabs(["Patch queue", "Assistant", "Assets", "Graph"])

# ---------------- patch queue ----------------
with tab_q:
    c = st.columns(4)
    c[0].metric("Total CVEs", len(queue))
    c[1].metric("KEV-listed", int(queue["kev"].sum()))
    c[2].metric("Critical Tier", int((queue["tier"] == "Critical").sum()))
    c[3].metric("Assets Loaded", conn.execute("SELECT COUNT(*) FROM asset").fetchone()[0])

    st.markdown("---")

    # Filters row
    f_col1, f_col2, f_col3, f_col4 = st.columns([1.5, 1.5, 2, 2])
    with f_col1:
        only_matched = st.checkbox("Only CVEs affecting my assets", value=False)
    with f_col2:
        only_kev = st.checkbox("Only KEV-listed", value=False)
    with f_col3:
        selected_tiers = st.multiselect("Filter by Tier", ["Critical", "High", "Medium", "Low"], default=["Critical", "High", "Medium", "Low"])
    with f_col4:
        search_kw = st.text_input("Search CVE or description", placeholder="e.g. CVE-2099 or overflow").strip().lower()

    # Apply filters
    view = scoring.ranked_queue(conn, only_matched=only_matched)
    if only_kev:
        view = view[view["kev"] == 1]
    if selected_tiers:
        view = view[view["tier"].isin(selected_tiers)]
    if search_kw:
        view = view[
            view["cve_id"].str.lower().str.contains(search_kw)
            | view["description"].str.lower().str.contains(search_kw)
        ]

    if new_kev_list:
        new_elevated = view[view["cve_id"].isin(new_kev_list)]
        if len(new_elevated):
            st.warning(f"🚨 **Newly Elevated CISA KEV Vulnerabilities ({len(new_elevated)}):**")
            st.dataframe(
                new_elevated.drop(columns=["description"]),
                column_config=column_config,
                use_container_width=True,
                hide_index=True,
            )

    # Display Queue with configured columns
    column_config = {
        "rank": st.column_config.NumberColumn("Rank", width="small"),
        "cve_id": st.column_config.TextColumn("CVE ID", width="medium"),
        "tier": st.column_config.TextColumn("Tier", width="small"),
        "score": st.column_config.ProgressColumn("Risk Score", format="%.3f", min_value=0, max_value=1),
        "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
        "epss": st.column_config.NumberColumn("EPSS", format="%.3f"),
        "kev": st.column_config.CheckboxColumn("KEV"),
        "asset_crit": st.column_config.NumberColumn("Asset Crit", format="%.2f"),
        "matched_assets": st.column_config.TextColumn("Matched Assets", width="large"),
    }

    st.dataframe(
        view.drop(columns=["description"]),
        column_config=column_config,
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "📥 Export Filtered Queue to CSV",
        view.to_csv(index=False),
        "patch_queue.csv",
        mime="text/csv",
    )

    st.markdown("### 🔍 CVE Deep Dive & Factor Breakdown")
    if len(view):
        pick = st.selectbox(
            "Select a CVE to inspect why it is ranked here:",
            view["cve_id"],
            key="queue_cve_pick",
        )
        ex = scoring.explain(conn, pick)

        col_left, col_right = st.columns([1, 1.5])
        with col_left:
            tier_color = TIER_COLORS.get(ex["tier"], "#2ca02c")
            st.markdown(
                f"<div style='padding:12px; border-radius:8px; border-left:6px solid {tier_color}; background-color:rgba(128,128,128,0.1);'>"
                f"<h3 style='margin:0; color:{tier_color};'>{ex['tier']} Tier</h3>"
                f"<h2 style='margin:4px 0 0 0;'>Score: {ex['score']:.4f}</h2>"
                f"</div>",
                unsafe_allow_html=True,
            )
            if ex["kev_override"]:
                st.warning("⚠️ **KEV Override Active**: Elevated directly to Critical because it is actively exploited in the wild (CISA KEV), regardless of base score.")
            else:
                st.info(f"Tier based on score threshold (Critical ≥ 0.75, High ≥ 0.50, Medium ≥ 0.25).")

            matched = ex["matched_assets"]
            if matched:
                st.success(f"🎯 **Matched Assets ({len(matched)}):** {', '.join(matched)}")
            else:
                st.caption("ℹ️ No matched internal inventory assets.")

        with col_right:
            st.markdown("**Factor Contribution to Final Risk Score**")
            chart_data = pd.DataFrame(ex["components"])
            chart_data["factor_label"] = chart_data["factor"].map({
                "cvss": "CVSS (35%)",
                "epss": "EPSS (30%)",
                "kev": "KEV (20%)",
                "asset": "Asset (15%)"
            })
            st.bar_chart(
                chart_data.set_index("factor_label")["contribution"],
                use_container_width=True,
            )

        # ---------------- Demo Step 1: CVSS-only vs PatchPilot Comparison ----------------
        st.markdown("---")
        with st.expander("⚖️ Demo Step 1: CVSS-only vs PatchPilot Order Comparison", expanded=False):
            st.markdown(
                "Small security teams waste limited patching cycles on high-CVSS vulnerabilities that have "
                "no weaponization or exploit activity in the wild. Compare how PatchPilot re-prioritizes the queue:"
            )
            try:
                if hasattr(scoring, "compare_orders"):
                    comp_df = scoring.compare_orders(conn, top_n=10)
                else:
                    # Built-in P4 fallback until P2 merges compare_orders
                    full_q = scoring.ranked_queue(conn)
                    cvss_sorted = full_q.sort_values(by=["cvss", "score"], ascending=[False, False]).reset_index(drop=True)
                    cvss_sorted["cvss_rank"] = cvss_sorted.index + 1
                    
                    merged = cvss_sorted.merge(full_q[["cve_id", "rank"]], on="cve_id", suffixes=("_cvss", ""))
                    merged = merged.rename(columns={"rank": "patchpilot_rank"})
                    
                    def why(row):
                        reasons = []
                        if row["kev"] == 1:
                            reasons.append("KEV-listed (in-the-wild exploit)")
                        if row["epss"] >= 0.7:
                            reasons.append(f"High EPSS ({row['epss']:.2f})")
                        elif row["epss"] <= 0.05 and row["cvss"] >= 9.0:
                            reasons.append(f"Low exploit probability (EPSS {row['epss']:.2f}) despite CVSS {row['cvss']}")
                        if row["asset_crit"] >= 0.8 and row["matched_assets"]:
                            reasons.append("Critical asset impact")
                        return "; ".join(reasons) or "Balanced risk formula"

                    merged["why_moved"] = merged.apply(why, axis=1)
                    comp_df = merged[["cvss_rank", "patchpilot_rank", "cve_id", "cvss", "epss", "kev", "tier", "why_moved"]].head(10)

                st.dataframe(
                    comp_df,
                    column_config={
                        "cvss_rank": st.column_config.NumberColumn("CVSS Rank", width="small"),
                        "patchpilot_rank": st.column_config.NumberColumn("PatchPilot Rank", width="small"),
                        "cve_id": st.column_config.TextColumn("CVE ID", width="medium"),
                        "cvss": st.column_config.NumberColumn("CVSS", format="%.1f"),
                        "epss": st.column_config.NumberColumn("EPSS", format="%.3f"),
                        "kev": st.column_config.CheckboxColumn("KEV"),
                        "tier": st.column_config.TextColumn("Tier"),
                        "why_moved": st.column_config.TextColumn("Why It Moved", width="large"),
                    },
                    use_container_width=True,
                    hide_index=True,
                )
            except Exception as e:
                st.warning(f"Comparison view unavailable: {e}")

# ---------------- assistant ----------------
with tab_chat:
    st.subheader("🤖 Evidence-Only Vulnerability Assistant")
    st.markdown(
        "Ask natural language questions about your patch queue, CVE risks, fixes, and affected assets. "
        "Every answer is **grounded exclusively in verified SQLite facts** and verified by a deterministic citation checker. "
        "If verifiable evidence is not found, the assistant strictly **refuses to answer** to eliminate hallucinations."
    )

    if "assistant_query_input" not in st.session_state:
        st.session_state["assistant_query_input"] = ""

    def _set_assistant_query(q_text: str):
        st.session_state["assistant_query_input"] = q_text
        st.session_state["trigger_auto_ask"] = True

    st.markdown("**Example Questions (Click to test):**")
    top_cve = queue.iloc[0]["cve_id"] if len(queue) > 0 else "CVE-2025-55182"

    col_btn1, col_btn2, col_btn3, col_btn4 = st.columns(4)
    with col_btn1:
        st.button(
            "🚨 What to patch first?",
            use_container_width=True,
            on_click=_set_assistant_query,
            args=("What should we patch first?",),
        )
    with col_btn2:
        st.button(
            f"🔧 Fix for {top_cve}?",
            use_container_width=True,
            on_click=_set_assistant_query,
            args=(f"Is there a fix for {top_cve}?",),
        )
    with col_btn3:
        st.button(
            "🏢 Affected assets?",
            use_container_width=True,
            on_click=_set_assistant_query,
            args=("Which internal assets are affected by critical vulnerabilities?",),
        )
    with col_btn4:
        st.button(
            "🛑 Out-of-scope (Refusal)",
            use_container_width=True,
            on_click=_set_assistant_query,
            args=("Who is the CEO of Acme Corporation?",),
        )

    q_input = st.text_input(
        "Ask a question about vulnerabilities or assets:",
        placeholder="e.g. What is the risk score of CVE-2025-55182? or Is there a patch?",
        key="assistant_query_input",
    )

    ask_clicked = st.button("Ask Assistant", type="primary")
    auto_ask = st.session_state.pop("trigger_auto_ask", False)

    active_query = st.session_state.get("assistant_query_input", "").strip()
    if (ask_clicked or auto_ask) and active_query:
        with st.spinner("Retrieving evidence and verifying citations..."):
            res = assistant.answer(active_query, conn)
            try:
                retrieved_evs = assistant.retrieve(conn, active_query)
                ev_map = {ev.id: ev for ev in retrieved_evs}
            except Exception:
                ev_map = {}

        if res["refused"]:
            st.warning(f"⚠️ **Refused by Verification Policy**: {res['answer']}")
            st.info(
                "🛡️ **Zero-Hallucination Guarantee**: The assistant could not find verifiable facts "
                "in the loaded database to support an answer to this query. In accordance with PatchPilot "
                "safety rules, the query was refused rather than generating ungrounded claims."
            )
        else:
            st.success(res["answer"])
            if res["citations"]:
                with st.expander(f"🔎 **Cited Evidence & Verification Details ({len(res['citations'])} facts)**", expanded=True):
                    st.markdown("✅ **Deterministic Citation Verification: PASSED**")
                    st.caption("Every claim in the answer is verified against retrieved SQLite ground-truth facts:")
                    for cid in res["citations"]:
                        ev = ev_map.get(cid)
                        if ev:
                            st.markdown(f"- **`[{cid}]`** *(source: {ev.source})*: {ev.text}")
                        else:
                            st.markdown(f"- **`[{cid}]`** *(verified fact)*")


# ---------------- assets ----------------
with tab_assets:
    st.subheader("🏢 Internal Asset Inventory & Fuzzy Vendor/Product Mapping")
    st.markdown(
        "Upload your asset inventory to contextualize vulnerability risk. Messy asset names are automatically mapped "
        "to official vendor/product records using **RapidFuzz** (`WRatio`). High-confidence matches ($\ge 0.85$) are "
        "auto-accepted; borderline matches ($0.60 - 0.85$) are flagged for manual review."
    )

    asset_list = assets.list_assets(conn)

    up_col1, up_col2 = st.columns([1.5, 1.5])
    with up_col1:
        st.markdown("**📤 Upload Custom Asset Inventory:**")
        up = st.file_uploader("Upload CSV (`name, criticality [, vendor, product]`)", type="csv")
        if up and st.button("Import Uploaded CSV", type="primary"):
            try:
                count = assets.import_assets_csv(conn, up)
                st.success(f"Successfully imported and mapped {count} assets! Patch queue re-ranked.")
                st.rerun()
            except Exception as e:
                st.error(f"Import failed: {e}")

    with up_col2:
        st.markdown("**📂 Load Demo Scenario Datasets:**")
        sample_catalog = {
            "☁️ Cloud & FinTech Infrastructure": "docs/sample_cloud_fintech.csv",
            "🏥 Healthcare & Hospital Network": "docs/sample_healthcare_hospital.csv",
            "🛒 E-Commerce & Retail Fleet": "docs/sample_ecommerce_retail.csv",
            "🏢 Enterprise (Messy Fuzzy Inventory)": "docs/sample_enterprise_assets.csv",
            "Default Sample": str(config.SAMPLE_ASSETS_CSV),
        }
        chosen_sample_name = st.selectbox("Select scenario dataset to test:", list(sample_catalog.keys()), key="sample_scenario_select")
        col_load, col_clear = st.columns(2)
        with col_load:
            if st.button("📥 Load Dataset", type="primary", use_container_width=True):
                chosen_file = sample_catalog[chosen_sample_name]
                p = Path(chosen_file)
                if not p.is_absolute():
                    p = Path(config.PROJECT_ROOT) / p
                try:
                    with open(p, "rb") as f:
                        count = assets.import_assets_csv(conn, f)
                    st.success(f"Loaded {count} assets from '{chosen_sample_name}'! Queue re-ranked.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to load sample: {e}")
        with col_clear:
            if len(asset_list) > 0:
                if st.button("🗑️ Clear Assets", use_container_width=True):
                    conn.execute("DELETE FROM asset")
                    conn.commit()
                    st.warning("Asset inventory cleared. Risk scores reset to neutral asset factor.")
                    st.rerun()

    st.markdown("---")

    if len(asset_list) == 0:
        st.info("No assets currently registered. Upload a CSV above or select a scenario dataset to see asset-driven re-ranking.")
    else:
        # Match status annotation
        def status_label(conf):
            if pd.isna(conf) or conf < 0.60:
                return "❌ Unmatched (<0.60)"
            elif conf < 0.85:
                return "⚠️ Needs Review (0.60-0.85)"
            return "✅ Auto-Accepted (≥0.85)"

        asset_list["status"] = asset_list["match_confidence"].apply(status_label)

        st.markdown(f"**Loaded Assets ({len(asset_list)})** — Edit vendor/product below to refine matches:")
        
        edited_df = st.data_editor(
            asset_list,
            column_config={
                "id": st.column_config.NumberColumn("ID", disabled=True, width="small"),
                "name": st.column_config.TextColumn("Asset Name", disabled=True, width="large"),
                "vendor": st.column_config.TextColumn("Vendor (editable)"),
                "product": st.column_config.TextColumn("Product (editable)"),
                "criticality": st.column_config.NumberColumn("Criticality", min_value=0.0, max_value=1.0, format="%.2f"),
                "match_confidence": st.column_config.ProgressColumn("Confidence", min_value=0.0, max_value=1.0, format="%.2f"),
                "status": st.column_config.TextColumn("Match Status", disabled=True, width="medium"),
            },
            hide_index=True,
            use_container_width=True,
            key="asset_editor",
        )

        if st.button("Save Asset Mapping Edits"):
            for _, row in edited_df.iterrows():
                conn.execute(
                    "UPDATE asset SET vendor = ?, product = ?, criticality = ? WHERE id = ?",
                    (
                        str(row["vendor"]).strip().lower() if pd.notna(row["vendor"]) else None,
                        str(row["product"]).strip().lower() if pd.notna(row["product"]) else None,
                        float(row["criticality"]),
                        int(row["id"]),
                    ),
                )
            conn.commit()
            st.success("Asset mappings updated! The patch queue is immediately re-ranked.")
            st.rerun()

# ---------------- graph ----------------
with tab_graph:
    st.subheader("🕸️ Vulnerability & Asset Relationship Knowledge Graph")
    st.markdown(
        "Interactive entity-relationship graph modeled directly over SQLite tables "
        "(`cve`, `cwe`, `cve_product`, `fix`, `asset`) using **NetworkX** and rendered via **Pyvis**. "
        "**Click any node to inspect details; click green 🔧 Fix/Advisory nodes to open vendor patch links.** "
        "*(Powered by a relational graph model over SQLite, not an expensive Neo4j instance).*"
    )

    g_col1, g_col2 = st.columns([3, 1])
    with g_col1:
        sel = st.selectbox("Select CVE to visualize neighbourhood:", queue["cve_id"], key="graph_cve")
    with g_col2:
        st.markdown(
            """
            **Legend (node types):**
            - 🔒🔴 **KEV CVE** — Active Exploit
            - 🔒🟡 **Standard CVE**
            - 🛡️🟣 **CWE Category** — Weakness Type
            - 📦🔵 **Product** — Affected Software
            - 🔧🟢 **Fix / Advisory** — *Click to open ↗*
            - 🖥️🟠 **Internal Asset** — Your Infrastructure
            """
        )

    try:
        from patchpilot import graph

        g = graph.build_graph(conn, sel)
        st.caption(f"Graph neighbourhood for **{sel}**: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges")
        components.html(graph.render_html(g), height=620)

        # Directly provide structured, clickable remediation links & node details
        fixes = conn.execute("SELECT url, kind FROM fix WHERE cve_id = ?", (sel,)).fetchall()
        cve_row = conn.execute("SELECT cvss, cwe, description FROM cve WHERE cve_id = ?", (sel,)).fetchone()
        is_kev = bool(conn.execute("SELECT 1 FROM kev WHERE cve_id = ?", (sel,)).fetchone())
        prods = conn.execute("SELECT vendor, product FROM cve_product WHERE cve_id = ?", (sel,)).fetchall()
        
        st.markdown("---")
        st.markdown(f"#### 🔎 Inspected Details & Remediation for `{sel}`")
        det_col1, det_col2, det_col3 = st.columns([1.2, 1, 1])
        
        with det_col1:
            st.markdown("**🔧 Direct Fix / Advisory Links (Click to Open):**")
            if fixes:
                for fix_url, fix_kind in fixes:
                    kind_tag = (fix_kind or "Advisory").title()
                    # Truncated display label
                    disp_url = fix_url
                    if len(disp_url) > 42:
                        disp_url = disp_url[:39] + "…"
                    st.link_button(f"↗ {kind_tag}: {disp_url}", fix_url, use_container_width=True)
            else:
                st.info("No vendor advisory URLs recorded in NVD for this CVE.")

        with det_col2:
            st.markdown("**🛡️ Weakness & Threat Status:**")
            st.markdown(f"- **Severity:** `CVSS {cve_row[0] if cve_row else 'N/A'}`")
            st.markdown(f"- **CISA KEV Status:** `{'⚠️ Listed (Active Exploit)' if is_kev else 'Not listed in KEV'}`")
            cwe_val = cve_row[1] if cve_row and cve_row[1] else "None recorded"
            st.markdown(f"- **Weakness (CWE):** `{cwe_val}`")

        with det_col3:
            st.markdown("**📦 Affected Products & Connected Assets:**")
            if prods:
                prod_strs = [f"`{v} / {p}`" for v, p in prods[:4]]
                st.markdown("- **Products:** " + ", ".join(prod_strs))
            else:
                st.markdown("- *No specific product mapping recorded.*")

            # Check if any loaded assets match these products
            matched_q = conn.execute("""
                SELECT a.name, a.criticality FROM asset a
                JOIN cve_product p ON lower(a.vendor) = lower(p.vendor) AND lower(a.product) = lower(p.product)
                WHERE p.cve_id = ?
            """, (sel,)).fetchall()
            if matched_q:
                st.markdown(f"- **Affected Company Assets ({len(matched_q)}):**")
                for an, ac in matched_q:
                    crit_emoji = "🔴" if ac >= 0.8 else ("🟡" if ac >= 0.5 else "🟢")
                    st.markdown(f"  - {crit_emoji} **{an}** *(Crit: {ac:.1f})*")
            else:
                st.caption("No internal company assets are currently matched to this product.")

    except Exception as e:
        st.error(f"Error rendering knowledge graph: {e}")



