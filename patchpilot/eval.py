"""Assistant evaluation harness. OWNER: Person 3.

Reads data/eval/questions.json. Reports citation accuracy (answered questions whose citations all verify
and contain must_cite CVEs) and refusal accuracy (unanswerable questions refused, answerable ones not refused). (issue P3-4)
"""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from . import assistant, db

EVAL_QUESTIONS_PATH = Path("data/eval/questions.json")


def run_eval(
    questions_path: Path | str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict:
    """Run evaluation over the question set and compute citation and refusal accuracy."""
    q_path = Path(questions_path or EVAL_QUESTIONS_PATH)
    if not q_path.exists():
        raise FileNotFoundError(f"Questions file not found: {q_path}")

    with open(q_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    questions = data.get("questions", [])
    if conn is None:
        from . import config
        # If questions target synthetic fixture (CVE-2099-*) and fixture.db exists, use it
        has_fixture_qs = any("CVE-2099-" in q.get("question", "") for q in questions)
        if has_fixture_qs and getattr(config, "FIXTURE_DB_PATH", None) and config.FIXTURE_DB_PATH.exists():
            conn = db.connect(config.FIXTURE_DB_PATH)
        else:
            conn = db.connect()

    refusal_correct = 0
    citation_correct = 0
    answerable_count = 0
    results = []

    for q in questions:
        qid = q.get("id", "")
        question_text = q.get("question", "")
        expect_refusal = bool(q.get("expect_refusal", False))
        must_cite = q.get("must_cite", [])

        evidence = assistant.retrieve(conn, question_text)
        ans = assistant.answer(question_text, conn)

        # 1. Refusal accuracy check: refused iff expect_refusal
        is_refusal_correct = bool(ans.get("refused", False)) == expect_refusal
        if is_refusal_correct:
            refusal_correct += 1

        # 2. Citation accuracy check for answerable questions
        is_citation_correct = False
        if not expect_refusal:
            answerable_count += 1
            if not ans.get("refused", False):
                # Verify citations pass
                citations_valid = assistant.verify_citations(ans, evidence)
                # Check must_cite CVEs appear in citations or answer
                answer_text = ans.get("answer", "")
                cited_str = " ".join(ans.get("citations", []))
                must_cite_ok = all(
                    (mc.upper() in answer_text.upper() or mc.upper() in cited_str.upper())
                    for mc in must_cite
                )
                if citations_valid and must_cite_ok:
                    is_citation_correct = True
                    citation_correct += 1

        results.append({
            "id": qid,
            "question": question_text,
            "expect_refusal": expect_refusal,
            "refused": ans.get("refused", False),
            "refusal_correct": is_refusal_correct,
            "must_cite": must_cite,
            "citations": ans.get("citations", []),
            "citation_correct": is_citation_correct,
            "answer": ans.get("answer", ""),
        })

    n = len(questions)
    refusal_acc = refusal_correct / n if n > 0 else 0.0
    citation_acc = citation_correct / answerable_count if answerable_count > 0 else 0.0

    return {
        "n": n,
        "answerable_count": answerable_count,
        "refusal_accuracy": round(refusal_acc, 4),
        "citation_accuracy": round(citation_acc, 4),
        "refusal_correct": refusal_correct,
        "citation_correct": citation_correct,
        "results": results,
    }


def main():
    print("=" * 60)
    print("PatchPilot Assistant Evaluation Harness")
    print("=" * 60)
    metrics = run_eval()
    print(f"Total questions evaluated (N): {metrics['n']}")
    print(f"  Answerable questions:       {metrics['answerable_count']}")
    print(f"  Unanswerable questions:     {metrics['n'] - metrics['answerable_count']}")
    print("-" * 60)
    print(f"Refusal Accuracy:  {metrics['refusal_accuracy'] * 100:.1f}% ({metrics['refusal_correct']}/{metrics['n']})")
    print(f"Citation Accuracy: {metrics['citation_accuracy'] * 100:.1f}% ({metrics['citation_correct']}/{metrics['answerable_count']})")
    print("=" * 60)


if __name__ == "__main__":
    main()
