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
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Integration branches (epic/*) intentionally carry not-yet-wired code built
# bottom-up: the whole-program closed-world gate cannot see a caller that a later
# slice (e.g. the daemon-wiring PR) will add, so it false-positives on every such
# PR. Skip here and enforce the gate at the epic->main merge, by which point the
# integration is complete. GITHUB_BASE_REF is the PR target branch in CI;
# DEADCODE_SKIP forces a skip locally.
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
CURRENT="$(mktemp)"
trap 'rm -f "$CURRENT"' EXIT
bash scripts/run-capped.sh "$DEADCODE_BIN" -test=false ./cmd/... ./operators/... 2>/dev/null \
  | sed -E 's/^([^:]+):[0-9]+:[0-9]+: unreachable func: (.+)$/\1\t\2/' \
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
