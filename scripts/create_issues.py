"""Create labels, milestones and issues from issues.json using the GitHub CLI (`gh`).

Usage (run inside the cloned repo, after `gh auth login`):
  python scripts/create_issues.py --assign P1=alice P2=bob P3=carol P4=dave
  python scripts/create_issues.py --dry-run          # print what would happen
Issues with role ALL are assigned to everyone listed.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def gh(args, dry, check=True):
    if dry:
        print("  $ gh " + " ".join(a if len(a) < 60 else a[:57] + "..." for a in args))
        return ""
    r = subprocess.run(["gh", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        print(r.stderr.strip(), file=sys.stderr)
        raise SystemExit(f"gh {' '.join(args[:3])} failed")
    return r.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--assign", nargs="*", default=[], help="P1=handle P2=handle ...")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    people = dict(x.split("=", 1) for x in a.assign)
    data = json.loads((ROOT / "issues.json").read_text(encoding="utf-8"))

    for lb in data["labels"]:
        gh(["label", "create", lb["name"], "--color", lb["color"], "--force"], a.dry_run)
    for ms in data["milestones"]:
        # 422 = already exists; ignore
        gh(["api", "-X", "POST", "repos/{owner}/{repo}/milestones", "-f", f"title={ms}"], a.dry_run, check=False)

    for it in data["issues"]:
        args = ["issue", "create", "--title", it["title"], "--body", it["body"], "--milestone", it["milestone"]]
        for lb in it["labels"]:
            args += ["--label", lb]
        who = list(people.values()) if it["role"] == "ALL" else ([people[it["role"]]] if it["role"] in people else [])
        for h in who:
            args += ["--assignee", h]
        print(f"Creating {it['title']}  -> {', '.join(who) or 'unassigned'}")
        gh(args, a.dry_run)


if __name__ == "__main__":
    main()
