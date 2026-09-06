#!/usr/bin/env bash
#
# check-coverage-floor.sh — absolute total-coverage floor (gibson#794, E3 /
# QUALITY-BARS §4). Supersedes the old 60% bar (former ADR-0021).
#
# The repo total is well below the 80% target today (~48% on measured
# packages), so an immediate hard 80% would red main — forbidden by the
# systemic-halt rule. Instead this is a *ratchet*: the committed floor in
# .coverage-floor may only ever rise toward 80, and the gate fails any change
# that drops total coverage below it. New tests push the number up; nothing may
# push it down. 80 is the documented destination, enforced incrementally here
# and per-PR on changed lines by cmd/diff-coverage.
#
# Usage:
#   scripts/check-coverage-floor.sh <coverage-profile> [floor-file]
#
# Args:
#   coverage-profile  go test -coverprofile output (atomic mode)
#   floor-file        file holding the single required floor percent
#                     (default: .coverage-floor at repo root)
set -euo pipefail

PROFILE="${1:?usage: check-coverage-floor.sh <coverage-profile> [floor-file]}"
FLOOR_FILE="${2:-.coverage-floor}"
TARGET=80

if [[ ! -f "$PROFILE" ]]; then
  echo "check-coverage-floor: coverage profile '$PROFILE' not found" >&2
  exit 2
fi
if [[ ! -f "$FLOOR_FILE" ]]; then
  echo "check-coverage-floor: floor file '$FLOOR_FILE' not found" >&2
  exit 2
fi

FLOOR=$(grep -vE '^\s*#' "$FLOOR_FILE" | grep -oE '[0-9]+(\.[0-9]+)?' | head -1)
if [[ -z "${FLOOR:-}" ]]; then
  echo "check-coverage-floor: no numeric floor in '$FLOOR_FILE'" >&2
  exit 2
fi

TOTAL=$(go tool cover -func="$PROFILE" | awk '/^total:/ {gsub(/%/,"",$3); print $3}')
if [[ -z "${TOTAL:-}" ]]; then
  echo "check-coverage-floor: could not read total coverage from '$PROFILE'" >&2
  exit 2
fi

echo "Total coverage: ${TOTAL}%  (floor ${FLOOR}%, target ${TARGET}%)"

# Regression gate: total must not drop below the committed floor.
if awk "BEGIN{exit !($TOTAL < $FLOOR)}"; then
  echo "FAIL: total coverage ${TOTAL}% is below the floor ${FLOOR}%." >&2
  echo "      Add tests to restore coverage, or justify and lower the floor in a reviewed change." >&2
  exit 1
fi

# Ratchet hint: when coverage climbs a full point above the floor, the floor
# should be bumped so the gain is locked in. This is advisory, not blocking,
# to avoid a race where two PRs both raise coverage.
if awk "BEGIN{exit !($TOTAL >= $FLOOR + 1 && $FLOOR < $TARGET)}"; then
  NEW=$(awk "BEGIN{v=$TOTAL; t=$TARGET; if (v>t) v=t; printf \"%d\", v}")
  echo "NOTE: coverage ${TOTAL}% exceeds the floor by >=1pt — consider raising .coverage-floor toward ${NEW} (target ${TARGET})."
fi

echo "check-coverage-floor PASSED"
