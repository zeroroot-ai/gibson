#!/usr/bin/env bash
# check-no-trust-domain-literal.sh — CI guard: no code holds the SaaS SPIFFE
# trust domain as a literal.
#
# Why: each install has its own SPIFFE trust domain (ADR-0164, gibson#757). One
# config value names it (auth.spiffe.trust_domain), and the code builds each
# SPIFFE ID from that value and a path. A literal SaaS SPIFFE ID in code makes
# a second install with a different domain fail. This guard fails on a new
# literal in a tracked file. Test files, testdata and Markdown are out of
# scope, the same scope as the count in gibson#757. Keyed by content, never by
# path or line number.
#
# Usage:
#   bash scripts/check-no-trust-domain-literal.sh            # real check
#   bash scripts/check-no-trust-domain-literal.sh --selftest # prove the guard can fail
#
# Exit codes: 0 clean, 1 violation (or self-test failure), 2 usage.
set -euo pipefail

# The SaaS trust domain. The script spells it in two parts, so this file does
# not match its own pattern.
SAAS_DOMAIN="zeroroot"'.ai'
PATTERN="spiffe://${SAAS_DOMAIN//./\\.}"

# A scan of a real tree must read at least this many files. A detached
# worktree or a wrong working directory then fails instead of reading nothing.
MIN_FILES=500

list_files() {
  if [ -n "${SCAN_ROOT:-}" ]; then
    find "$SCAN_ROOT" -type f ! -name '*_test.go' ! -name '*.md' ! -path '*/testdata/*' -print0
  else
    git ls-files -z -- . ':!:*_test.go' ':!:**/testdata/**' ':!:*.md'
  fi
}

scan() {
  local count hits
  count=$(list_files | tr -cd '\0' | wc -c)
  if [ -z "${SCAN_ROOT:-}" ] && [ "$count" -lt "$MIN_FILES" ]; then
    echo "check-no-trust-domain-literal: read only $count files, need $MIN_FILES. Run it from the repo root." >&2
    return 1
  fi
  hits=$(list_files | xargs -0 -r grep -n -I -E -- "$PATTERN" || true)
  if [ -n "$hits" ]; then
    while IFS= read -r line; do
      echo "::error file=${line%%:*}::SPIFFE trust domain literal: ${line#*:}"
    done <<<"$hits"
    echo "check-no-trust-domain-literal: build each SPIFFE ID from the configured trust domain (ADR-0164)." >&2
    return 1
  fi
  echo "check-no-trust-domain-literal: no SPIFFE trust domain literal in $count files."
}

selftest() {
  local rc tmp
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064 # expand tmp now, at trap time it is out of scope
  trap "rm -rf '$tmp'" EXIT
  # case 1: a literal in Go code and a literal in a workflow must be rejected.
  mkdir -p "$tmp/bad1" "$tmp/bad2"
  printf 'package a\nconst id = "spiffe://%s/platform/envoy"\n' "$SAAS_DOMAIN" >"$tmp/bad1/a.go"
  printf 'peers:\n  - spiffe://%s/platform/e2e-runner\n' "$SAAS_DOMAIN" >"$tmp/bad2/values.yaml"
  for i in 1 2; do
    rc=0
    SCAN_ROOT="$tmp/bad$i" scan >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 1 ]; then
      echo "SELFTEST case 1.$i FAILED: trust domain literal not rejected (rc=$rc)" >&2
      return 1
    fi
  done
  echo "SELFTEST case 1 PASSED: Go and YAML literals rejected."
  # case 2: an ID built from a value, a literal in a test file, in testdata
  # and in Markdown must pass.
  mkdir -p "$tmp/good/testdata"
  printf 'package a\nfunc id(td string) string { return "spiffe://" + td + "/platform/envoy" }\n' >"$tmp/good/a.go"
  printf 'package a\nconst fixture = "spiffe://%s/platform/envoy"\n' "$SAAS_DOMAIN" >"$tmp/good/a_test.go"
  printf 'spiffe://%s/platform/envoy\n' "$SAAS_DOMAIN" >"$tmp/good/testdata/peer.txt"
  printf 'The SaaS uses spiffe://%s.\n' "$SAAS_DOMAIN" >"$tmp/good/README.md"
  SCAN_ROOT="$tmp/good" scan >/dev/null 2>&1 || {
    echo "SELFTEST case 2 FAILED: clean tree rejected" >&2
    return 1
  }
  echo "SELFTEST case 2 PASSED: clean tree accepted."
  # case 3: a scan of a tree under the floor must fail.
  rc=0
  (cd "$tmp/good" && git init -q && git add -A && scan) >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 1 ]; then
    echo "SELFTEST case 3 FAILED: a scan of $MIN_FILES files or fewer passed (rc=$rc)" >&2
    return 1
  fi
  echo "SELFTEST case 3 PASSED: a small scan is refused."
}

case "${1:-}" in
  --selftest) selftest ;;
  "") scan ;;
  *)
    echo "usage: $0 [--selftest]" >&2
    exit 2
    ;;
esac
