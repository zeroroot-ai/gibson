#!/usr/bin/env bash
# check-executor-catalog-current.sh — is the captured executor catalog still the
# executor's actual tool set?
#
# The tool-manifest drift gate (gibsoncheck.yml) regenerates the manifests from
# the COMMITTED executor-catalog.json and diffs the result. That proves the
# manifests match the capture. It cannot prove the capture matches the executor,
# because it deliberately never looks at an image — and that is the gap this
# script closes: trivy and tlsx shipped in gibson-executor and stayed invisible
# to the catalog for two releases while the drift gate was green (gibson#1675).
#
# Compares TOOL SETS, not image digests. A digest comparison would go red on
# every executor rebuild that changed no tool, and would go green on a
# manifest-list vs manifest digest mismatch that changed every tool — both
# answers are wrong. The question worth asking is "does the catalog name the
# tools the image actually ships".
#
# Usage:
#   check-executor-catalog-current.sh <list-tools.json> [catalog.json]
#   check-executor-catalog-current.sh --selftest
#
# Exit 0 when the sets match, 1 when they differ or the comparison could not be
# made honestly.

set -euo pipefail

CATALOG_DEFAULT="internal/platform/componentcatalog/executor-catalog.json"

# names_from extracts the sorted tool names from either shape: the catalog file
# ({"image":…,"tools":[…]}) or raw `--list-tools` output (a bare array, or the
# same object). An input that yields no names at all is a hard failure, never an
# empty set that could agree with another empty set.
names_from() {
  local file="$1" label="$2" names
  names=$(python3 -c '
import json, sys
raw = json.load(open(sys.argv[1]))
tools = raw.get("tools", raw) if isinstance(raw, dict) else raw
if not isinstance(tools, list):
    sys.exit("not a tool list")
for t in tools:
    name = t.get("name") if isinstance(t, dict) else None
    if name:
        print(name)
' "$file" | sort -u)

  if [ -z "$names" ]; then
    echo "check-executor-catalog-current: ${label} yielded no tool names — refusing to compare" >&2
    echo "  (an empty set would agree with anything, which is how a broken probe looks green)" >&2
    return 1
  fi
  printf '%s\n' "$names"
}

compare() {
  local image_tools="$1" catalog="$2" from_image from_catalog only_image only_catalog

  from_image=$(names_from "$image_tools" "the image's --list-tools output") || return 1
  from_catalog=$(names_from "$catalog" "the committed catalog") || return 1

  only_image=$(comm -23 <(printf '%s\n' "$from_image") <(printf '%s\n' "$from_catalog"))
  only_catalog=$(comm -13 <(printf '%s\n' "$from_image") <(printf '%s\n' "$from_catalog"))

  if [ -z "$only_image" ] && [ -z "$only_catalog" ]; then
    echo "check-executor-catalog-current: catalog is current ($(printf '%s\n' "$from_image" | wc -l) tools)"
    return 0
  fi

  echo "check-executor-catalog-current: the captured catalog is NOT the executor's tool set." >&2
  if [ -n "$only_image" ]; then
    echo "" >&2
    echo "  In the executor image but NOT in the catalog — these tools cannot be" >&2
    echo "  dispatched at all, and nothing else reports it:" >&2
    printf '    %s\n' $only_image >&2
  fi
  if [ -n "$only_catalog" ]; then
    echo "" >&2
    echo "  In the catalog but NOT in the executor image — dispatching one of these" >&2
    echo "  launches a tool the image does not have:" >&2
    printf '    %s\n' $only_catalog >&2
  fi
  echo "" >&2
  echo "  Re-capture against the current executor release, then commit both the" >&2
  echo "  JSON and the regenerated manifests:" >&2
  echo "    make tool-catalog-capture IMAGE=ghcr.io/zeroroot-ai/gibson-executor@sha256:<digest>" >&2
  return 1
}

# SELFTEST_DIR is global on purpose: an EXIT trap runs after a function's locals
# are gone, so a `local dir` would leave the trap dereferencing an unset variable
# under `set -u` and turn a passing self-test into a failing one.
SELFTEST_DIR=""
cleanup_selftest() { [ -n "$SELFTEST_DIR" ] && rm -rf "$SELFTEST_DIR"; }

selftest() {
  local dir rc=0
  SELFTEST_DIR=$(mktemp -d)
  dir="$SELFTEST_DIR"
  trap cleanup_selftest EXIT

  cat >"$dir/catalog.json" <<'JSON'
{"image":"ghcr.io/zeroroot-ai/gibson-executor@sha256:aaa","tools":[{"name":"nmap"},{"name":"httpx"}]}
JSON

  # 1. Identical sets agree.
  echo '[{"name":"httpx"},{"name":"nmap"}]' >"$dir/same.json"
  if compare "$dir/same.json" "$dir/catalog.json" >/dev/null 2>&1; then
    echo "  pass  identical tool sets agree"
  else
    echo "  FAIL  identical tool sets should agree"; rc=1
  fi

  # 2. The real gibson#1675 shape: the image gained a tool nobody captured.
  echo '[{"name":"httpx"},{"name":"nmap"},{"name":"trivy"}]' >"$dir/added.json"
  if compare "$dir/added.json" "$dir/catalog.json" >/dev/null 2>&1; then
    echo "  FAIL  a tool added to the image must go red"; rc=1
  else
    echo "  pass  a tool added to the image goes red"
  fi

  # 3. The reverse: the catalog names a tool the image dropped.
  echo '[{"name":"nmap"}]' >"$dir/dropped.json"
  if compare "$dir/dropped.json" "$dir/catalog.json" >/dev/null 2>&1; then
    echo "  FAIL  a tool dropped from the image must go red"; rc=1
  else
    echo "  pass  a tool dropped from the image goes red"
  fi

  # 4. A probe that returned nothing must hard-fail, not agree with an empty set.
  echo '[]' >"$dir/empty.json"
  if compare "$dir/empty.json" "$dir/catalog.json" >/dev/null 2>&1; then
    echo "  FAIL  an empty probe must hard-fail"; rc=1
  else
    echo "  pass  an empty probe hard-fails instead of masquerading as agreement"
  fi

  # 5. …in both directions, so the check cannot rot into a no-op.
  if compare "$dir/same.json" "$dir/empty.json" >/dev/null 2>&1; then
    echo "  FAIL  an empty catalog must hard-fail"; rc=1
  else
    echo "  pass  an empty catalog hard-fails"
  fi

  if [ "$rc" -eq 0 ]; then
    echo "check-executor-catalog-current --selftest: 5/5 checks pass"
  fi
  return "$rc"
}

main() {
  if [ "${1:-}" = "--selftest" ]; then
    selftest
    return
  fi
  if [ $# -lt 1 ]; then
    echo "usage: $0 <list-tools.json> [catalog.json]" >&2
    echo "       $0 --selftest" >&2
    return 2
  fi
  compare "$1" "${2:-$CATALOG_DEFAULT}"
}

main "$@"
