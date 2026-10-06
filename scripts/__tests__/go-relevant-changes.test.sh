#!/usr/bin/env bash
# Fixture for go-relevant-changes.sh: each case states the changed paths and
# the answer. A Markdown-only change is the one case that skips the Go gates.
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 1
SCRIPT=scripts/go-relevant-changes.sh
PASS=0 FAIL=0
check() { # name expected paths...
  local name=$1 want=$2; shift 2
  got=$(printf '%s\n' "$@" | bash "$SCRIPT"); rc=$?
  if [ "$rc" -eq 0 ] && [ "$got" = "$want" ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); echo "FAIL: $name: got '$got' (rc=$rc), want '$want'"; fi
}
check "go file" true internal/server/daemon/grpc.go
check "embedded catalog yaml" true internal/platform/componentcatalog/manifests/github-plugin.yaml
check "dockerfile" true Dockerfile
check "sql migration" true pkg/platform/migrations/postgres/platform/040_drop_connector_manifest.up.sql
check "workflow" true .github/workflows/go-ci.yml
check "markdown and yaml" true README.md configs/env-readers.txt
check "markdown only" false README.md docs/plugins.md
check "empty diff" true ""
echo "go-relevant-changes: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
