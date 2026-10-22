#!/usr/bin/env bash
# setup.sh — SignatureFixer environment bootstrap & verification
# Installs dependencies, type-checks, runs the test suite, and reports branch state.
set -uo pipefail
cd "$(dirname "$0")"

FAIL=0
step() { echo; echo "==> $*"; }
ok()   { echo "    [OK] $*"; }
bad()  { echo "    [FAIL] $*"; FAIL=1; }

step "Toolchain"
node --version && npm --version || { bad "node/npm missing"; exit 1; }

step "Install dependencies (npm install)"
if npm install --no-audit --fund=false; then ok "dependencies installed"; else bad "npm install failed"; fi

step "Type check (tsc --noEmit)"
if npx tsc --noEmit; then ok "no type errors"; else bad "tsc reported errors"; fi

step "Test suite (vitest run)"
if npx vitest run --reporter=basic; then ok "tests passed"; else bad "tests failed"; fi

step "Git / branch state"
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "    current branch: ${BRANCH}"
echo "    HEAD commit:    $(git log --oneline -1)"
if git merge-base --is-ancestor main HEAD 2>/dev/null; then
    ok "main is an ancestor of HEAD (fast-forward merge into main possible)"
else
    bad "branch has diverged from main — manual merge required"
fi
DIRTY=$(git status --porcelain -- . ':(exclude)node_modules' | head -5)
[ -z "$DIRTY" ] && ok "working tree clean (excluding node_modules)" || bad "uncommitted changes: ${DIRTY}"

echo
if [ "$FAIL" -eq 0 ]; then
    echo "SETUP COMPLETE — all checks green."
else
    echo "SETUP FINISHED WITH FAILURES — see [FAIL] lines above."
fi
exit "$FAIL"
