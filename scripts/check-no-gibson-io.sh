#!/usr/bin/env bash
# check-no-gibson-io.sh — the retired `gibson.io` SPIFFE trust domain never
# comes back.
#
# The trust domain is `zeroroot.ai` (workspace CLAUDE.md § 9). The guard for
# the old name was lost in the history reset and, before that, ran in no CI
# workflow (gibson#26): the only thing between a `gibson.io` reference and
# main was whether someone ran `make check` locally. This one scans THIS
# repository, from its own root, and runs in go-ci.
#
#   check-no-gibson-io.sh             exit 1 on a reference, 0 when clean
#   check-no-gibson-io.sh --selftest  prove a planted reference fails and the tree passes
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

scan() { # <dir> -> prints matches
  grep -rnE 'gibson\.io\b' "$1" \
    --include='*.go' --include='*.yaml' --include='*.yml' --include='*.proto' \
    --include='*.cue' --include='*.md' --include='*.sh' --include='*.json' --include='*.toml' \
    --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor \
    | grep -vE '/scripts/check-no-gibson-io\.sh:' || true
}

if [ "${1:-}" = "--selftest" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/internal"
  printf 'const trustDomain = "spiffe://gibson.io/platform/daemon"\n' > "$tmp/internal/bad.go"
  [ -n "$(scan "$tmp")" ] || { echo "SELFTEST FAIL: a planted gibson.io reference was not found"; exit 1; }
  printf 'const trustDomain = "spiffe://zeroroot.ai/platform/daemon"\n' > "$tmp/internal/bad.go"
  [ -z "$(scan "$tmp")" ] || { echo "SELFTEST FAIL: a clean tree was flagged"; exit 1; }
  echo "OK: a gibson.io reference fails, a zeroroot.ai one passes"
  exit 0
fi

hits="$(scan "$ROOT")"
if [ -n "$hits" ]; then
  echo "❌ the retired gibson.io trust domain is referenced; the trust domain is zeroroot.ai:"
  echo "$hits" | head -20 | sed 's/^/  /'
  exit 1
fi
echo "✓ no gibson.io reference in the tree"
