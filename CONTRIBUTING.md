# How we work (8-hour build, 4 people)

| Person | Branch | Owns |
|---|---|---|
| P1 Data | `p1-data` | `patchpilot/db.py`, `ingest.py`, `data/patchpilot.db`, `data/raw/` |
| P2 Scoring + backtest | `p2-scoring` | `patchpilot/scoring.py`, `backtest.py`, `docs/backtest.*` |
| P3 Assistant | `p3-assistant` | `patchpilot/assistant.py`, `eval.py`, `llm.py`, `data/eval/` |
| P4 App + assets + graph + demo | `p4-app` | `app.py`, `patchpilot/assets.py`, `graph.py`, `README.md`, `docs/` |

## Rules
1. `git checkout <your branch>`; pull `main` often (`git merge origin/main`).
2. **Edit only files you own.** Need something from another file? Comment on their issue.
3. The contract (`config/project.json`, schema in `db.py`, `contracts.py`, function signatures, weights in `config.py`) changes only via an all-hands issue + PR.
4. Small PRs into `main`, early and often. Another person approves; green tests required.
5. Develop against the synthetic fixture until P1 ships `data/patchpilot.db`.
6. No new dependencies without telling the team. The demo must run offline.

## Commands (no `make` needed)
```
pip install -r requirements.txt
python -m patchpilot.ingest fixture      # load synthetic data into data/fixture.db
streamlit run app.py
python -m pytest -q
python -m patchpilot.backtest            # P2
python -m patchpilot.eval                # P3
```
