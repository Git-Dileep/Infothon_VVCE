"""Backtest: does PatchPilot catch future-exploited CVEs better than CVSS-only? OWNER: Person 2.

Design (fixed, do not change without telling the team):
  cutoff T. Candidates = CVEs published before T and NOT in KEV as of T (kev.date_added < T excluded).
  Label = enters KEV within `horizon_days` after T.
  Features use only data as of T: EPSS file dated T, CVSS from NVD. No KEV feature (candidates are not listed).
  Strategies: cvss_only, epss_only, blend (0.35/0.30 reweighted to sum 1), cvss>=7, cvss>=9.
  Metric: share of labelled CVEs caught when patching the top 5% / 10% of candidates (+ patched fraction for thresholds).
  Honest note for the write-up: KEV and asset factors are context, not testable here.
"""
from __future__ import annotations


def run_backtest(cutoff: str, horizon_days: int = 180) -> dict:
    """Returns {'cutoff':..., 'n_candidates':..., 'n_positive':..., 'results': {strategy: {...}}}. (issues P2-3, P2-4)"""
    raise NotImplementedError("P2-3/P2-4: implement backtest")


if __name__ == "__main__":
    raise SystemExit("Not implemented yet - see issues P2-3 / P2-4")
