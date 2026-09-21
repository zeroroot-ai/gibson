#!/usr/bin/env bash
# e2e-suite-verdict.sh — turn one suite's `go test -v` log into one verdict row.
#
# Usage: e2e-suite-verdict.sh <suite> <log-file> <exit-code> <results-file>
#        e2e-suite-verdict.sh --selftest
#
# The cluster e2e lane (exit-test-e2e-cluster.yml, gibson#32) runs every
# cluster-bound suite on one kind cluster and must say, per suite, whether it
# PASSED, FAILED or SKIPPED. A suite that skips is missing coverage, and a
# regex that matches no test is a guard that cannot fail, so both are named
# rather than folded into a green run.
#
# The rule, applied to the `--- PASS|FAIL|SKIP:` lines of a verbose log:
#   FAIL  when any test or subtest failed, or the command exited non-zero
#         (a build error, a panic, a Job that never scheduled), or when no
#         top-level test ran at all and none skipped.
#   SKIP  when no top-level test passed or failed and at least one skipped.
#   PASS  otherwise. Skipped subtests are counted and reported beside it.
#
# Output: one tab-separated row appended to <results-file>:
#   suite  verdict  passed  failed  skipped  note
# The script itself always exits 0 on a verdict; the lane's summary step
# fails the job. --selftest exits non-zero when a fixture gets the wrong
# verdict, which is the failing fixture this guard ships with.
set -euo pipefail

verdict() {
  local suite="$1" log="$2" rc="$3" out="$4"
  local passed failed skipped_top skipped_sub verdict note
  passed=$(grep -c '^--- PASS: ' "$log" || true)
  failed=$(grep -c '^ *--- FAIL: ' "$log" || true)
  skipped_top=$(grep -c '^--- SKIP: ' "$log" || true)
  skipped_sub=$(grep -c '^ \+--- SKIP: ' "$log" || true)
  note=""
  if [ "$failed" -gt 0 ]; then
    verdict=FAIL
    note="$(grep -m1 '^ *--- FAIL: ' "$log" | sed 's/^ *--- FAIL: //; s/ (.*//')"
  elif [ "$rc" != "0" ]; then
    verdict=FAIL
    note="exit code ${rc} with no failed test: the command died before a verdict"
  elif [ "$passed" -eq 0 ] && [ "$skipped_top" -gt 0 ]; then
    verdict=SKIP
    note="$(grep -m1 -A1 '^=== RUN' "$log" | grep -m1 -v '^=== RUN' | sed 's/^ *//' || true)"
    [ -n "$note" ] || note="every top-level test skipped"
  elif [ "$passed" -eq 0 ]; then
    verdict=FAIL
    note="no test ran: the -run selection matched nothing"
  else
    verdict=PASS
    [ "$skipped_sub" -eq 0 ] || note="${skipped_sub} subtest(s) skipped"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$suite" "$verdict" "$passed" "$failed" "$((skipped_top + skipped_sub))" "$note" >> "$out"
  echo "verdict ${suite}: ${verdict} (passed=${passed} failed=${failed} skipped=$((skipped_top + skipped_sub)))${note:+ — $note}"
}

selftest() {
  local dir fail=0
  dir=$(mktemp -d)
  trap 'rm -rf "$dir"' RETURN

  cat > "$dir/pass.log" <<'EOF'
=== RUN   TestOne
=== RUN   TestOne/a
    --- PASS: TestOne/a (0.00s)
--- PASS: TestOne (0.01s)
PASS
EOF
  cat > "$dir/pass-with-skipped-subtest.log" <<'EOF'
=== RUN   TestOne
=== RUN   TestOne/a
    x_test.go:10: no cookie jar
    --- SKIP: TestOne/a (0.00s)
--- PASS: TestOne (0.01s)
PASS
EOF
  cat > "$dir/fail.log" <<'EOF'
=== RUN   TestOne
=== RUN   TestOne/a
    x_test.go:12: expected 403, got 200
    --- FAIL: TestOne/a (0.00s)
--- FAIL: TestOne (0.01s)
FAIL
EOF
  cat > "$dir/skip.log" <<'EOF'
=== RUN   TestOne
    x_test.go:9: GIBSON_TEST_TENANT_ADMIN_TOKEN not set; skipping
--- SKIP: TestOne (0.00s)
PASS
EOF
  : > "$dir/empty.log"
  cat > "$dir/none.log" <<'EOF'
testing: warning: no tests to run
PASS
EOF

  expect() {
    local name="$1" log="$2" rc="$3" want="$4" got
    : > "$dir/results.tsv"
    verdict "$name" "$log" "$rc" "$dir/results.tsv" >/dev/null
    got=$(cut -f2 "$dir/results.tsv")
    if [ "$got" = "$want" ]; then
      echo "selftest ok:   $name -> $got"
    else
      echo "selftest FAIL: $name -> $got, want $want"
      fail=1
    fi
  }
  expect pass                    "$dir/pass.log"                     0 PASS
  expect pass-skipped-subtest    "$dir/pass-with-skipped-subtest.log" 0 PASS
  expect fail                    "$dir/fail.log"                     1 FAIL
  expect fail-even-when-rc-zero  "$dir/fail.log"                     0 FAIL
  expect skip                    "$dir/skip.log"                     0 SKIP
  expect died-before-verdict     "$dir/pass.log"                     2 FAIL
  expect empty-log               "$dir/empty.log"                    0 FAIL
  expect nothing-matched         "$dir/none.log"                     0 FAIL

  # The skipped-subtest count must reach the row, or the summary cannot warn.
  : > "$dir/results.tsv"
  verdict count "$dir/pass-with-skipped-subtest.log" 0 "$dir/results.tsv" >/dev/null
  if [ "$(cut -f5 "$dir/results.tsv")" != "1" ]; then
    echo "selftest FAIL: skipped subtest count not reported"
    fail=1
  fi
  return "$fail"
}

case "${1:-}" in
  --selftest) selftest ;;
  "") echo "usage: $0 <suite> <log-file> <exit-code> <results-file> | --selftest" >&2; exit 2 ;;
  *)
    [ $# -eq 4 ] || { echo "usage: $0 <suite> <log-file> <exit-code> <results-file>" >&2; exit 2; }
    [ -f "$2" ] || : > "$2"
    verdict "$1" "$2" "$3" "$4"
    ;;
esac
