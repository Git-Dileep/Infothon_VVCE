# Antigravity prompt (paste into the agent; fill in YOUR role on the first line)

Open the cloned repo in Antigravity on **your branch**, then paste everything inside the block below.

````text
MY ROLE: <P1 Data | P2 Scoring+Backtest | P3 Assistant | P4 App+Assets+Graph+Demo>   MY BRANCH: <p1-data | p2-scoring | p3-assistant | p4-app>

## Who we are and what we are building
We are a 4-person team in an 8-hour hackathon (in7.0thon, VVCE, problem statement PS #17
"Autonomous Vulnerability Intelligence & RAG Agent"). We are building PatchPilot from scratch:
a vulnerability prioritisation tool for small IT/security teams without an enterprise budget.
Judges reward a polished, reliable, defensible demo, not feature count.

## The ONLY two things we perfect
1. Exploit-aware ranking with an explainable score, proven by a backtest against CVSS-only.
   Risk = 0.35*CVSS/10 + 0.30*EPSS + 0.20*KEV + 0.15*Asset (all inputs 0..1).
   Tiers: Critical >= 0.75 OR KEV-listed; High 0.50-0.74; Medium 0.25-0.49; Low < 0.25.
   KEV-listed is always Critical, but ordering inside a tier is by score. Order = tier, then score desc.
   Asset factor = max criticality of matched assets; 0.5 if no inventory loaded; 0.0 if an inventory
   exists and the CVE matches nothing. Missing CVSS/EPSS count as 0.
2. An evidence-only assistant: retrieves evidence from SQLite, the LLM answers ONLY from it and cites
   evidence ids, a deterministic verifier rejects any citation or CVE id not in the retrieved evidence,
   and it REFUSES when there is no evidence. We report measured citation and refusal accuracy.
Supporting (small, cut first if short on time): asset CSV import with RapidFuzz matching, a graph view,
a "Check for new KEV" demo flow.

## Hard constraints (do not violate)
- Simple stack only: Python 3.11+, SQLite (+FTS5), pandas, requests, Streamlit (single app), RapidFuzz,
  networkx + pyvis, ONE LLM provider. NO Neo4j, ChromaDB/embeddings, LangChain, FastAPI, Docker,
  APScheduler, LLM-based asset matching, OSV/GitHub/vendor scraping. Do not add dependencies.
- The "knowledge graph" is a graph data model over SQLite tables, drawn with networkx/pyvis.
- The demo must run OFFLINE from a committed SQLite snapshot. Never require live network at demo time.
- Never invent data. Fixture CVEs (CVE-2099-*) are SYNTHETIC; real data comes from NVD API 2.0,
  CISA KEV JSON and FIRST EPSS files. If a URL or API behaves differently than assumed, say so and adapt.
- Be honest in claims. If the backtest does not beat EPSS-only, we say "matches EPSS, adds asset
  context and fix links".

## Repo map and ownership (edit ONLY files you own)
- P1 Data:      patchpilot/db.py, patchpilot/ingest.py, data/patchpilot.db, data/raw/
- P2 Scoring:   patchpilot/scoring.py, patchpilot/backtest.py, docs/backtest.*
- P3 Assistant: patchpilot/assistant.py, patchpilot/eval.py, patchpilot/llm.py, data/eval/
- P4 App:       app.py, patchpilot/assets.py, patchpilot/graph.py, README.md, docs/
- Shared contract (change only via an all-hands GitHub issue + PR): config/project.json,
  patchpilot/config.py, patchpilot/contracts.py, the SQL schema in db.py, all public function
  signatures, tests/test_contract.py.
If you need a change in a file you do not own, write the exact request as a comment for its owner
instead of editing it.

## The contract
Read config/project.json first: it lists the tables, every public function and its return shape.
Tables: cve, cve_product, fix, kev, kev_seen, epss, asset, cve_fts (FTS5).
Key functions: scoring.ranked_queue(conn, only_matched=False) -> DataFrame with columns
[rank, cve_id, tier, score, cvss, epss, kev, asset_crit, matched_assets, description];
scoring.explain(conn, cve_id) -> dict with components that sum to the score;
assistant.retrieve(conn, question) -> list[Evidence]; assistant.answer(question, conn) -> Answer
{answer, citations, refused} and it must never raise; assistant.verify_citations;
ingest.new_kev_since_last_sync / simulate_new_kev; assets.match_asset; graph.build_graph/render_html.

## How to work
1. Read README.md, CONTRIBUTING.md, config/project.json and the stubs you own. Run
   `python -m patchpilot.ingest fixture`, `python -m pytest -q`, `streamlit run app.py`.
2. Open my GitHub issues (labelled with my role: p1-data, p2-scoring, p3-assistant or p4-app) and work
   them in dependency order. For each issue: state a short plan, implement, add or extend tests, run
   `python -m pytest -q`, commit with message "<issue key>: <what>" (e.g. "P2-1: vectorise scoring").
3. Develop against the synthetic fixture until data/patchpilot.db exists. Keep every function working
   on both the fixture and the real snapshot.
4. Prefer small, boring, readable code: type hints, short docstrings, no clever abstractions,
   no premature optimisation. Handle None/NaN explicitly.
5. Do not refactor or reformat files you do not own. Do not rename columns, tables or functions.
6. When an issue is done, tell me what to verify manually (one command + expected output), then
   open a PR into main using the PR template. Do not start the next issue until I confirm.
7. If something in these instructions conflicts with what you find in the code or data, stop and ask me
   instead of guessing.

## Definition of done (team)
Must: real snapshot committed; ranked queue with factor breakdown in the UI; backtest chart and table
reproducible with one command; assistant answers with verified citations and refuses correctly, with
eval numbers recorded. Should: asset CSV import with fuzzy match and review; graph view; new-KEV demo.
Demo (4 min): CVSS-only vs PatchPilot order -> backtest chart -> cited answer -> refusal on an
unanswerable question -> upload assets and watch the queue re-rank -> "Check for new KEV" makes a CVE
jump to #1.

Start now: confirm my role from the first line, list my issues in the order you will do them, and begin
with the first one.
````

## Role cheat-sheet (what to say after pasting)
- **P1:** "Start with P1-3 (EPSS history) and P1-1 (NVD); verify the EPSS URL first."
- **P2:** "Start with P2-1, then P2-3 once P1-3 lands."
- **P3:** "Start with P3-1, then P3-2 and P3-3."
- **P4:** "Start with P4-1 and P4-2; wire P4-4 when P3-2 merges."
