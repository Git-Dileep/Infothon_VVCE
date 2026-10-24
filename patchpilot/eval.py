"""Assistant evaluation harness. OWNER: Person 3.

Reads data/eval/questions.json. Reports citation accuracy (answered questions whose citations all verify)
and refusal accuracy (unanswerable questions refused, answerable ones not refused). (issue P3-4)
"""
from __future__ import annotations


def run_eval() -> dict:
    raise NotImplementedError("P3-4: implement eval")


if __name__ == "__main__":
    raise SystemExit("Not implemented yet - see issue P3-4")
