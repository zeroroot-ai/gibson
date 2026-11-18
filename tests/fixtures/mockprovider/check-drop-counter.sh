#!/usr/bin/env bash
# check-drop-counter.sh checks the trace counters of the daemon after the AAIF
# alignment exit test (gibson#1404, point 10 of the exit test).
#
# The daemon counts each model call span that it receives, each span that it
# delivers to a Timeline, and each span that it drops. The check passes when the
# daemon received at least one span, dropped none, and delivered each span that it
# received. A retry counts a span again in both totals, so the difference of the
# two totals is the drop count.
#
# Usage: bash tests/fixtures/mockprovider/check-drop-counter.sh <metrics file>
#        bash tests/fixtures/mockprovider/check-drop-counter.sh --selftest
# Exit codes: 0 the counters are right, 1 they are not, 2 usage.
set -euo pipefail

# sum_of NAME FILE prints the sum of the samples of a metric. It prints 0 when
# the metric has no sample, and "missing" is never printed: the caller decides.
sum_of() {
  awk -v name="$1" '
    $0 !~ /^#/ && ($1 == name || index($1, name "{") == 1) { total += $NF; seen = 1 }
    END { if (seen) printf "%d\n", total; else print "absent" }
  ' "$2"
}

check() {
  local file=$1 requests delivered dropped
  requests=$(sum_of gibson_gateway_llm_requests_total "$file")
  delivered=$(sum_of gibson_gateway_llm_events_delivered_total "$file")
  dropped=$(sum_of gibson_gateway_llm_dropped_total "$file")
  if [ "$requests" = absent ] || [ "$requests" -lt 1 ]; then
    echo "::error::the daemon counted no model call span (gibson_gateway_llm_requests_total is ${requests}), so the drop counter looked at nothing"
    return 1
  fi
  [ "$delivered" = absent ] && delivered=0
  [ "$dropped" = absent ] && dropped=0
  echo "spans received ${requests}, delivered ${delivered}, dropped ${dropped}"
  if [ "$dropped" -ne 0 ]; then
    echo "::error::the daemon dropped ${dropped} model call spans"
    return 1
  fi
  if [ "$requests" -ne "$delivered" ]; then
    echo "::error::the daemon received ${requests} spans and delivered ${delivered}"
    return 1
  fi
}

selftest() {
  local dir rc
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' RETURN
  expect() { # name want file
    set +e
    check "$3" >/dev/null 2>&1
    rc=$?
    set -e
    if [ "$rc" -ne "$2" ]; then
      echo "selftest: case '$1' gave exit $rc, want $2"
      return 1
    fi
  }
  printf 'gibson_gateway_llm_requests_total 4\ngibson_gateway_llm_events_delivered_total 4\n' >"$dir/good"
  printf 'gibson_gateway_llm_requests_total 4\ngibson_gateway_llm_events_delivered_total 3\ngibson_gateway_llm_dropped_total{reason="parse"} 1\n' >"$dir/dropped"
  printf 'gibson_gateway_llm_requests_total 4\ngibson_gateway_llm_events_delivered_total 3\n' >"$dir/undelivered"
  printf '# HELP other a metric\nother_total 9\n' >"$dir/empty"
  expect "all spans delivered" 0 "$dir/good"
  expect "a dropped span" 1 "$dir/dropped"
  expect "an undelivered span" 1 "$dir/undelivered"
  expect "no span counted" 1 "$dir/empty"
  echo "selftest passed"
}

case "${1:-}" in
  --selftest) selftest ;;
  "") echo "usage: $0 <metrics file> | --selftest" >&2; exit 2 ;;
  *) check "$1" ;;
esac
