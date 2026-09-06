#!/usr/bin/env bash
#
# check-guard-baselines.sh — the STALE half of the security-guard
# baseline ratchet.
#
# tools/gibsoncheck/checks/guard_baseline.txt records the security-guard
# findings that predate the guards. The analyzers themselves enforce
# half the ratchet: a finding that is not in the baseline fails the
# build, so new debt can never be absorbed.
#
# This script enforces the OTHER half, which is the half that decides
# whether the baseline is temporary or permanent: a baseline line whose
# site has been FIXED or REMOVED is a HARD FAILURE. You cannot fix a
# violation and leave its line behind, so the file is forced
# monotonically downward.
#
# It works by re-running the guards with GIBSON_GUARD_BASELINE=off to
# get the unsuppressed finding set, then comparing key sets in both
# directions.
#
# SELFTEST=1 runs the script against a synthetic pair of key sets to
# prove the comparison logic itself works, so a silently-broken guard
# cannot pass by finding nothing. Same pattern as
# scripts/check-no-tenant-id-column.sh.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE="${REPO_ROOT}/tools/gibsoncheck/checks/guard_baseline.txt"

# ---------------------------------------------------------------------------
# selftest — prove the comparison bites before trusting a clean run
# ---------------------------------------------------------------------------
if [[ "${SELFTEST:-0}" == "1" ]]; then
  echo "SELFTEST: verifying stale/new detection logic"
  tmp="$(mktemp -d)"
  trap 'rm -rf "${tmp}"' EXIT
  printf 'a|p|x\nb|p|y\n' > "${tmp}/baseline"
  printf 'a|p|x\n'          > "${tmp}/live"

  stale="$(comm -23 <(sort "${tmp}/baseline") <(sort "${tmp}/live"))"
  if [[ -z "${stale}" ]]; then
    echo "SELFTEST FAILED: stale entry 'b|p|y' was not detected" >&2
    exit 1
  fi

  printf 'a|p|x\nc|p|z\n' > "${tmp}/live2"
  fresh="$(comm -13 <(sort "${tmp}/baseline") <(sort "${tmp}/live2"))"
  if [[ -z "${fresh}" ]]; then
    echo "SELFTEST FAILED: new finding 'c|p|z' was not detected" >&2
    exit 1
  fi
  echo "SELFTEST passed: both directions of the ratchet detect correctly."
  exit 0
fi

cd "${REPO_ROOT}"

echo "Building gibsoncheck..."
go build -o bin/gibsoncheck ./tools/gibsoncheck

echo "Collecting unsuppressed guard findings..."
live="$(mktemp)"
trap 'rm -f "${live}"' EXIT

# GIBSON_GUARD_BASELINE=off disables baseline suppression so we see the
# true, current finding set. Diagnostics carry their baseline key in
# square brackets, which is what we extract.
GIBSON_GUARD_BASELINE=off ./bin/gibsoncheck \
  -failopenauthorizer -privilegedfallback -fgalistusers -constantverdictdouble \
  ./internal/... ./cmd/... ./operators/... ./pkg/... 2>&1 \
  | grep -oE '\[[a-z-]+\|[^]]+\]' \
  | sed 's/^\[//; s/\]$//' \
  | sort -u > "${live}" || true

baseline_keys="$(mktemp)"
trap 'rm -f "${live}" "${baseline_keys}"' EXIT
grep -v '^[[:space:]]*#' "${BASELINE}" | grep -v '^[[:space:]]*$' | sort -u > "${baseline_keys}"

echo "  baseline entries: $(wc -l < "${baseline_keys}")"
echo "  live findings:    $(wc -l < "${live}")"

rc=0

stale="$(comm -23 "${baseline_keys}" "${live}" || true)"
if [[ -n "${stale}" ]]; then
  echo ""
  echo "STALE BASELINE ENTRIES — these sites are fixed or gone, but their"
  echo "lines are still in the baseline. Delete them in the same commit as"
  echo "the fix. The baseline must only ever shrink:"
  echo "${stale}" | sed 's/^/  /'
  rc=1
fi

fresh="$(comm -13 "${baseline_keys}" "${live}" || true)"
if [[ -n "${fresh}" ]]; then
  echo ""
  echo "NEW GUARD FINDINGS not present in the baseline. Fix the code — do"
  echo "not add these lines to the baseline:"
  echo "${fresh}" | sed 's/^/  /'
  rc=1
fi

if [[ "${rc}" -eq 0 ]]; then
  echo "Guard baseline is exact: no stale entries, no new findings."
fi
exit "${rc}"
