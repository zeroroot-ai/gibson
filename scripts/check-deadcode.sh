#!/usr/bin/env bash
# check-deadcode.sh — BLOCKING whole-program dead-code gate (gibson#778, QUALITY-BARS §3).
#
# Runs golang.org/x/tools/cmd/deadcode reachability from ALL binary mains —
# the top-level `cmd/*` (daemon, ext-authz, spiffe-jwks-exporter, migrators)
# AND the operator mains under `operators/*/cmd/*` (tenant + platform
# operators), which are separate binaries not imported by the daemon. Passing
# only `./cmd/...` left operator-reachable code unanalyzed (gibson#789/#918).
# Because `deadcode` has no native diff-scoping, the pre-existing
# backlog is baselined in `.deadcode-baseline` (file<TAB>func, sorted). The gate
# fails when a function becomes unreachable that is NOT already in the baseline —
# i.e. NEW dead code. It does NOT fail on the existing backlog (burndown tracked
# in gibson#918).
#
# Self-healing baseline: when previously-dead code becomes reachable again (or is
# deleted), its baseline entry is simply stale — that is fine, it never causes a
# failure. Regenerate with: make lint-deadcode-baseline
#
# Public API surfaces are "used by definition" by external consumers; gibson is a
# closed binary tree (no exported library surface that ships to third parties),
# so whole-program reachability from the mains is the correct closed-world model.
# (The Apache public surfaces — sdk / gibson-executor / adk — live in OTHER repos
# and are exempted there, per QUALITY-BARS §3.)
# Usage:
#   bash scripts/check-deadcode.sh            # real gate
#   bash scripts/check-deadcode.sh --selftest # prove the gate can fail, and that
#                                             # it reports WHY the tool failed
#
# Exit codes: 0 clean, 1 new dead code (or self-test failure), 2 usage/setup,
# otherwise the tool's own exit status.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Integration branches (epic/*) intentionally carry not-yet-wired code built
# bottom-up: the whole-program closed-world gate cannot see a caller that a later
# slice (e.g. the daemon-wiring PR) will add, so it false-positives on every such
# PR. Skip here and enforce the gate at the epic->main merge, by which point the
# integration is complete. GITHUB_BASE_REF is the PR target branch in CI;
# DEADCODE_SKIP forces a skip locally.
selftest() {
  # Two fixtures, each run against a STUB tool, so neither builds the tree.
  local tmp stub baseline out status fails=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # Fixture 1 — the tool refuses to run. The gate must exit non-zero AND print
  # the tool's own reason. This is the case that failed silently on 2026-10-01:
  # deadcode v0.44.0 could not read Go 1.27.1 export data, its stderr went to
  # /dev/null, and CI showed one line of make output and no cause.
  stub="$tmp/refusing-tool"
  cat > "$stub" <<'STUB'
#!/usr/bin/env bash
echo "stub: export data version 4 is greater than maximum supported version 2" >&2
exit 1
STUB
  chmod +x "$stub"
  : > "$tmp/empty-baseline"
  set +e
  out="$(DEADCODE_SKIP= GITHUB_BASE_REF=main \
    DEADCODE_BIN="$stub" DEADCODE_BASELINE="$tmp/empty-baseline" \
    bash "${BASH_SOURCE[0]}" 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "selftest FAIL: a refusing tool left the gate green" >&2; fails=1
  elif ! printf '%s' "$out" | grep -q "maximum supported version 2"; then
    echo "selftest FAIL: the tool's reason was swallowed. Gate said:" >&2
    printf '%s\n' "$out" >&2; fails=1
  else
    echo "selftest PASS: a refusing tool fails the gate and reports its reason"
  fi

  # Fixture 2 — the tool reports one unreachable func that the baseline does not
  # carry. The gate must fail and name it.
  stub="$tmp/one-dead-func"
  cat > "$stub" <<'STUB'
#!/usr/bin/env bash
echo "internal/selftest/fixture.go:1:6: unreachable func: NeverCalled"
STUB
  chmod +x "$stub"
  set +e
  out="$(DEADCODE_SKIP= GITHUB_BASE_REF=main \
    DEADCODE_BIN="$stub" DEADCODE_BASELINE="$tmp/empty-baseline" \
    bash "${BASH_SOURCE[0]}" 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    echo "selftest FAIL: new dead code left the gate green" >&2; fails=1
  elif ! printf '%s' "$out" | grep -q "NeverCalled"; then
    echo "selftest FAIL: the gate failed without naming the dead func" >&2; fails=1
  else
    echo "selftest PASS: new dead code fails the gate and is named"
  fi

  return "$fails"
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi

if [ -n "${DEADCODE_SKIP:-}" ] || [[ "${GITHUB_BASE_REF:-}" == epic/* ]]; then
  echo "check-deadcode: skipping on integration branch base '${GITHUB_BASE_REF:-}' (enforced at epic->main)"
  exit 0
fi

DEADCODE_BIN="${DEADCODE_BIN:-bin/tools/deadcode}"
BASELINE="${DEADCODE_BASELINE:-.deadcode-baseline}"

if [ ! -x "$DEADCODE_BIN" ]; then
  echo "check-deadcode: $DEADCODE_BIN not found. Run 'make lint-deadcode' (builds it) first." >&2
  exit 2
fi
if [ ! -f "$BASELINE" ]; then
  echo "check-deadcode: baseline $BASELINE missing. Run 'make lint-deadcode-baseline' to create it." >&2
  exit 2
fi

# Normalise current deadcode to the same `file<TAB>func` shape as the baseline.
#
# deadcode's stderr is kept, not discarded. It used to go to /dev/null, so when
# the tool itself died the gate reported no cause at all: under the Go 1.27.1
# floor deadcode v0.44.0 panics in callgraph/rta, a panic exits 2, and all CI
# showed was `make: *** [Makefile:232: lint-deadcode] Error 2`. A gate that
# cannot say why it failed costs more than it catches, so the tool's stderr is
# captured and printed on any non-zero exit.
CURRENT="$(mktemp)"
TOOL_ERR="$(mktemp)"
RAW="$(mktemp)"
trap 'rm -f "$CURRENT" "$TOOL_ERR" "$RAW"' EXIT
set +e
bash scripts/run-capped.sh "$DEADCODE_BIN" -test=false ./cmd/... ./operators/... >"$RAW" 2>"$TOOL_ERR"
TOOL_STATUS=$?
set -e
if [ "$TOOL_STATUS" -ne 0 ]; then
  echo "check-deadcode: $DEADCODE_BIN exited $TOOL_STATUS. Its output was:" >&2
  cat "$TOOL_ERR" >&2
  echo "" >&2
  echo "A panic or a type-checking refusal here usually means the DEADCODE_VERSION" >&2
  echo "pin in the Makefile is older than the toolchain floor in go.mod. deadcode" >&2
  echo "analyses the tree with its own vendored x/tools, so raise that pin. The" >&2
  echo "toolchain that builds the binary is not the lever." >&2
  exit "$TOOL_STATUS"
fi
sed -E 's/^([^:]+):[0-9]+:[0-9]+: unreachable func: (.+)$/\1\t\2/' "$RAW" \
  | sort -u > "$CURRENT"

# NEW dead code = lines in CURRENT not present in BASELINE.
NEW="$(comm -23 "$CURRENT" <(sort -u "$BASELINE") || true)"

if [ -n "$NEW" ]; then
  echo "FAIL: new dead (unreachable) code introduced — not present in $BASELINE:" >&2
  echo "" >&2
  echo "$NEW" | sed 's/\t/  ->  /' >&2
  echo "" >&2
  echo "Remediation: delete the unreachable function, or wire it into a reachable" >&2
  echo "code path. If it is a genuine keep (e.g. a deliberately-retained helper)," >&2
  echo "regenerate the baseline with 'make lint-deadcode-baseline' and justify the" >&2
  echo "addition in your PR description." >&2
  exit 1
fi

echo "check-deadcode PASSED (no new dead code vs $BASELINE; $(wc -l < "$BASELINE" | tr -d ' ') baselined entries)"
