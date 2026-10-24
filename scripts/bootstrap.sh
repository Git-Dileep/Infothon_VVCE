#!/usr/bin/env bash
# One-time setup by ONE teammate. Requires: git, gh (GitHub CLI, logged in), python3.
# Usage: bash scripts/bootstrap.sh <repo-name> <p1-handle> <p2-handle> <p3-handle> <p4-handle>
set -euo pipefail
REPO="${1:?repo name}"; P1="${2:?}"; P2="${3:?}"; P3="${4:?}"; P4="${5:?}"

[ -d .git ] || git init -b main
git add -A
git commit -m "chore: PatchPilot skeleton (contract, fixture, stubs)" || true
gh repo create "$REPO" --private --source=. --remote=origin --push
for u in "$P1" "$P2" "$P3" "$P4"; do
  gh api -X PUT "repos/{owner}/{repo}/collaborators/$u" -f permission=push >/dev/null || echo "invite $u manually"
done
for b in p1-data p2-scoring p3-assistant p4-app; do git branch "$b"; git push origin "$b"; done
python3 scripts/create_issues.py --assign P1="$P1" P2="$P2" P3="$P3" P4="$P4"
echo "Done. Everyone: git clone, git checkout <your branch>, read docs/ANTIGRAVITY_PROMPT.md"
