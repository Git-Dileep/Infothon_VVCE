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
    c[0].metric("CVEs", len(queue))
    c[1].metric("KEV-listed", int(queue["kev"].sum()))
    c[2].metric("Critical", int((queue["tier"] == "Critical").sum()))
    c[3].metric("Assets", conn.execute("SELECT COUNT(*) FROM asset").fetchone()[0])
    only_matched = st.checkbox("Only CVEs affecting my assets")
    view = scoring.ranked_queue(conn, only_matched=only_matched)
    st.dataframe(view.drop(columns=["description"]), use_container_width=True, hide_index=True)
    st.download_button("Export CSV", view.to_csv(index=False), "patch_queue.csv")
    if len(view):
        pick = st.selectbox("Why is this ranked here?", view["cve_id"])
        ex = scoring.explain(conn, pick)
        left, right = st.columns([1, 2])
        left.markdown(f"**{ex['tier']}**, score **{ex['score']:.3f}**")
        if ex["kev_override"]:
            left.caption("Forced to Critical because it is KEV-listed.")
        left.write(ex["matched_assets"] or "No matching assets")
        right.bar_chart(pd.DataFrame(ex["components"]).set_index("factor")["contribution"])
        # TODO P4-1: CVSS-only vs PatchPilot comparison view, tier colouring (TIER_COLORS)

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
