#!/usr/bin/env bash
# check-brand.sh — CI guard: the retired brand strings never come back.
#
# The org is zeroroot.ai and the company name is Zero Root AI. Four strings
# from before the rename still leak into new files, and each one is a public
# artifact once it reaches main:
#
#   zero-day.ai   the retired domain, and the retired CRD group prefix
#                 (gibson.zero-day.ai/...) which no cluster has ever served
#   zero-day-ai   the same domain as a slug, in fixtures and image tags
#   Zero Day AI   the retired company name, in copyright headers and prose
#   gibson.io     the domain before that one, in Kubernetes label keys
#
# This replaces check-no-gibson-io.sh, which matched only the fourth string,
# told the reader to "use zero-day.ai instead" (itself a violation), and
# computed its scan root as the pre-split workspace directory three levels
# above scripts/. That directory does not exist in a single-repo checkout, so
# the guard scanned the gibson tree by accident and its eight allowlist entries
# (deploy/helm/..., platform/dashboard/...) named files in repos that no longer
# exist. It also had a --selftest that no caller ever passed.
#
# Scope: every file `git ls-files` reports, or every regular file under
# SCAN_ROOT when that variable is set (used by --selftest). Binary files are
# skipped by grep -I.
#
# Exemptions are repo-relative paths or a content marker, never line numbers.
# A file that must carry an old string — because it asserts the string is
# absent, or because it is a generated history — either appears in
# EXEMPT_PATHS below or carries the marker `brand-guard-exempt:` followed by a
# reason. Both survive an unrelated edit anywhere in the file.
#
# Usage:
#   bash scripts/check-brand.sh            # real check
#   bash scripts/check-brand.sh --selftest # prove the guard can fail
#
# Exit codes: 0 clean, 1 violation (or self-test failure), 2 usage.
set -euo pipefail

GUARD_NAME="check-brand"

# The retired strings, as extended regular expressions. Case-sensitive: the
# company name is only ever wrong in title case, and lowering the case here
# would flag ordinary prose about a zero-day.
PATTERNS=(
  'zero-day\.ai'
  'zero-day-ai'
  'Zero Day AI'
  'gibson\.io'
)

# Repo-relative paths whose old strings are intentional. Keep this list short:
# every entry is a place the guard cannot protect.
EXEMPT_PATHS=(
  # This guard names the strings it forbids.
  "scripts/check-brand.sh"
  # release-please owns the changelog. It records what commit subjects said at
  # the time, including the rename commits themselves.
  "CHANGELOG.md"
  # The code-scanning dismissal log quotes alert text verbatim.
  "docs/code-scanning-dismissals.md"
)

# Any file containing this marker is exempt. A test that asserts an old string
# is absent must contain that string, so it declares itself here.
EXEMPT_MARKER='brand-guard-exempt:'

is_exempt_path() {
  local rel=$1 entry
  for entry in "${EXEMPT_PATHS[@]}"; do
    [ "$rel" = "$entry" ] && return 0
  done
  return 1
}

list_files() {
  if [ -n "${SCAN_ROOT:-}" ]; then
    find "$SCAN_ROOT" -type f -print0
  else
    git ls-files -z
  fi
}

scan() {
  local violations=0 f rel pattern hits
  while IFS= read -r -d '' f; do
    if [ ! -f "$f" ] || [ -L "$f" ]; then continue; fi
    if [ -n "${SCAN_ROOT:-}" ]; then
      rel="${f#"$SCAN_ROOT"/}"
    else
      rel="$f"
    fi
    is_exempt_path "$rel" && continue
    grep -Iqs -- "$EXEMPT_MARKER" "$f" && continue
    for pattern in "${PATTERNS[@]}"; do
      hits=$(grep -IEns -- "$pattern" "$f" || true)
      [ -n "$hits" ] || continue
      while IFS= read -r line; do
        echo "::error file=${rel},line=${line%%:*}::retired brand string (${pattern}): ${line#*:}"
      done <<<"$hits"
      violations=$((violations + 1))
    done
  done < <(list_files)

  if [ "$violations" -gt 0 ]; then
    {
      echo "${GUARD_NAME}: ${violations} file/pattern pair(s) carry a retired brand string."
      echo "The domain is zeroroot.ai, the CRD group is gibson.zeroroot.ai, and the"
      echo "company name is Zero Root AI. Rewrite the reference."
      echo "If the string is load-bearing — a test that asserts it is absent — put the"
      echo "marker '${EXEMPT_MARKER} <reason>' in the file, or add the path to"
      echo "EXEMPT_PATHS in scripts/check-brand.sh."
    } >&2
    return 1
  fi
  echo "${GUARD_NAME}: no retired brand strings."
}

selftest() {
  local tmp rc pattern i=0
  tmp=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT

  # One failing fixture per pattern, each on its own scan root, so a guard
  # that lost a pattern fails here instead of passing by finding nothing.
  local fixtures=(
    'apiVersion: gibson.zero-day.ai/v1'
    'image: ghcr.io/zeroroot-ai/zero-day-ai-daemon:v1'
    '// Copyright 2026 Zero Day AI'
    'label: gibson.io/sandbox-host=true'
  )
  for pattern in "${PATTERNS[@]}"; do
    mkdir -p "$tmp/case$i/nested"
    printf '%s\n' "${fixtures[$i]}" > "$tmp/case$i/nested/fixture.yaml"
    rc=0
    SCAN_ROOT="$tmp/case$i" scan >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 1 ]; then
      echo "SELFTEST FAILED: pattern ${pattern} did not reject '${fixtures[$i]}' (rc=$rc)" >&2
      return 1
    fi
    echo "SELFTEST PASSED: pattern ${pattern} rejected its fixture."
    i=$((i + 1))
  done

  # A clean tree passes.
  mkdir -p "$tmp/clean"
  printf 'apiVersion: gibson.zeroroot.ai/v1alpha1\n// Copyright 2026 Zero Root AI\n' \
    > "$tmp/clean/ok.yaml"
  SCAN_ROOT="$tmp/clean" scan >/dev/null 2>&1 || {
    echo "SELFTEST FAILED: clean tree rejected" >&2
    return 1
  }
  echo "SELFTEST PASSED: clean tree accepted."

  # The content marker exempts a file that must carry an old string.
  mkdir -p "$tmp/marker"
  printf '// %s asserts the retired group is gone.\nconst old = "gibson.zero-day.ai"\n' \
    "$EXEMPT_MARKER" > "$tmp/marker/assert_absent_test.go"
  SCAN_ROOT="$tmp/marker" scan >/dev/null 2>&1 || {
    echo "SELFTEST FAILED: content marker did not exempt the file" >&2
    return 1
  }
  echo "SELFTEST PASSED: content marker exempts its file."
}

case "${1:-}" in
  --selftest) selftest ;;
  "") scan ;;
  *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
esac
