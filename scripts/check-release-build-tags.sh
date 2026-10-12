#!/usr/bin/env bash
# check-release-build-tags.sh — CI guard: no published image is a fixture build.
#
# The exit-test runner identity (spiffe://<td>/platform/e2e-runner) and its
# method policy exist only in a daemon built with the test_fixtures tag
# (internal/server/daemon/e2e_peer_policy.go). A production build compiles
# e2e_peer_policy_stub.go instead, which grants that identity nothing, and
# TestSpiffePeerMethodPolicies_OnlyOperatorsArePoliced holds the closed set of
# policed peers for each build.
#
# That holds only while no published image is built with test_fixtures. This
# guard reads each BUILD_TAGS of the image workflow
# (.github/workflows/gibson-images.yml) and the default of the Dockerfile, and
# fails when one names test_fixtures. The exit tests build their fixture daemon
# in the exit-test workflows and load it into kind; it is never pushed.
#
#   check-release-build-tags.sh             exit 1 on a finding
#   check-release-build-tags.sh --selftest  prove a fixture tag in each place fails
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# judge <image workflow> <Dockerfile> — prints each finding, one per line.
judge() {
  local wf="$1" df="$2"
  grep -nE '^[[:space:]]*BUILD_TAGS[[:space:]]*=' "$wf" | grep -E 'test_fixtures' \
    | sed "s|^|$(basename "$wf"):|" || true
  grep -nE '^ARG[[:space:]]+BUILD_TAGS=' "$df" | grep -E 'test_fixtures' \
    | sed "s|^|$(basename "$df"):|" || true
}

selftest() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  printf '            build_args: |\n              BUILD_TAGS=setec_integration\n' > "$tmp/wf.yml"
  printf 'ARG BUILD_TAGS="setec_integration"\n' > "$tmp/Dockerfile"
  [ -z "$(judge "$tmp/wf.yml" "$tmp/Dockerfile")" ] || { echo "SELFTEST FAIL: a production tag must pass"; return 1; }
  printf '            build_args: |\n              BUILD_TAGS=setec_integration,test_fixtures\n' > "$tmp/wf-bad.yml"
  [ -n "$(judge "$tmp/wf-bad.yml" "$tmp/Dockerfile")" ] || { echo "SELFTEST FAIL: a fixture tag in the image workflow must fail"; return 1; }
  printf 'ARG BUILD_TAGS="test_fixtures"\n' > "$tmp/Dockerfile-bad"
  [ -n "$(judge "$tmp/wf.yml" "$tmp/Dockerfile-bad")" ] || { echo "SELFTEST FAIL: a fixture default in the Dockerfile must fail"; return 1; }
  echo "  ✓ selftest: a fixture tag in the image workflow and in the Dockerfile default each fail"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

WF="$ROOT/.github/workflows/gibson-images.yml"
DF="$ROOT/Dockerfile"
grep -qE '^[[:space:]]*BUILD_TAGS[[:space:]]*=' "$WF" \
  || { echo "check-release-build-tags: $WF names no BUILD_TAGS; this check is blind" >&2; exit 1; }
found="$(judge "$WF" "$DF")"
if [ -n "$found" ]; then
  echo "a published image is built with test_fixtures, which compiles the exit-test runner identity and its method policy:" >&2
  echo "$found" >&2
  exit 1
fi
echo "  ✓ check-release-build-tags: no published image is built with test_fixtures"
