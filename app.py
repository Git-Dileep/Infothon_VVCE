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
    if st.button("Check for new KEV entries"):
        try:
            if demo_mode:
                ingest.simulate_new_kev(conn)
            else:
                ingest.sync_kev(conn)  # P1-2
            st.session_state["new_kev"] = ingest.new_kev_since_last_sync(conn)
            ingest.mark_kev_seen(conn)
        except NotImplementedError as e:
            st.info(str(e))

if n_cves == 0:
    st.stop()

if st.session_state.get("new_kev"):
    st.error(f"New CISA KEV entries: {', '.join(st.session_state['new_kev'])}. Queue re-scored.")

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
    q = st.text_input("Ask about your patch queue", placeholder="What should we patch first?")
    if st.button("Ask") and q:
        res = assistant.answer(q, conn)
        (st.warning if res["refused"] else st.success)(res["answer"])
        if res["citations"]:
            st.caption("Evidence: " + ", ".join(res["citations"]))

# ---------------- assets ----------------
with tab_assets:
    st.dataframe(assets.list_assets(conn), use_container_width=True, hide_index=True)
    up = st.file_uploader("Upload asset CSV (name, criticality)", type="csv")
    if up and st.button("Import"):
        try:
            st.success(f"Imported {assets.import_assets_csv(conn, up)} assets")
            st.rerun()
        except NotImplementedError as e:
            st.info(str(e))

# ---------------- graph ----------------
with tab_graph:
    sel = st.selectbox("CVE", queue["cve_id"], key="graph_cve")
    try:
        from patchpilot import graph

        components.html(graph.render_html(graph.build_graph(conn, sel)), height=600)
    except NotImplementedError as e:
        st.info(str(e))
    except ImportError as e:
        st.info(f"Missing dependency: {e}")
