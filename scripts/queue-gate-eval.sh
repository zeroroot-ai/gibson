#!/usr/bin/env bash
# queue-gate-eval.sh — the aggregation logic behind `queue-gate`, the required
# status check for this repo.
#
# WHY THIS IS A SCRIPT
# --------------------
# It used to be six lines inline in go-ci.yml. Inline YAML cannot be run, so it
# could not be tested, so nobody noticed that its `needs:` list named five of
# the nine gate jobs in the file. `fast`, `lint` and `critical-paths` ran, could
# report red, and could not block a merge — `critical-paths` being the job that
# runs `make check-ci-lane-parity` and `make check-build-tags`, i.e. the guards
# that keep the lane-parity invariant documented at the top of go-ci.yml from
# rotting. A guard that cannot fail was guarding the guards.
#
# Same class as gibson#1233 / gibson#1297 / gibson#1368 and the sibling repos'
# gibson-executor#341 and #369: the check exists, is described as
# authoritative, and is arranged so that it never decides anything.
#
# THE SEMANTICS, AND WHY EACH ONE IS WHAT IT IS
# ---------------------------------------------
#   `if: always()` on the job is mandatory. GitHub skips a `needs:` job whenever
#   ANY dependency is skipped, and this repo's gates are lane-split by design.
#   Without it the required context would be ABSENT rather than red — and an
#   absent required context freezes merge-queue entry instead of failing the
#   PR, which is strictly the worse outcome (.github#202).
#
#   `always()` with no result evaluation is a job that passes whenever it runs.
#   So the results are read, explicitly, and the set of results is checked
#   against the set that was expected.
#
#   skipped == pass. Load-bearing: `heavy` is merge_group-only, `fast`/`lint`
#   are pull_request-only, and the Go-heavy jobs are gated on the `changes`
#   filter, so on any given run most gates legitimately do not execute. GitHub
#   reports a skipped job as a skipped CHECK RUN, which satisfies a ruleset;
#   this must agree, or every PR fails.
#
#   failure|cancelled == fail. Cancelled matters — a queue eviction or a
#   timeout cancels siblings, and reading that as "not a failure" would let a
#   half-run suite report green.
#
#   anything else == fail, closed. A result string GitHub has not documented is
#   not evidence of success.
#
#   an empty result set == fail. An aggregator with nothing to aggregate
#   reporting green is the purest form of this whole defect class.
#
# Usage:
#   queue-gate-eval.sh --needs-json '<toJSON(needs)>'
#   queue-gate-eval.sh --selftest
#
# Exit 0 = every gate passed or was skipped. Exit 1 = at least one did not.

set -uo pipefail

evaluate() {
  local json="$1"

  if [ -z "$json" ] || ! jq -e 'type == "object"' >/dev/null 2>&1 <<<"$json"; then
    echo "  not a JSON object -- expected \${{ toJSON(needs) }}"
    return 1
  fi

  local count
  count="$(jq -r 'length' <<<"$json")"
  if [ "$count" -eq 0 ]; then
    echo "  empty needs: -- refusing to report green having gated nothing"
    return 1
  fi

  local failed=0
  while IFS=$'\t' read -r job result; do
    case "$result" in
      success|skipped)
        printf '  pass  %-42s %s\n' "$job" "$result" ;;
      failure|cancelled)
        printf '  FAIL  %-42s %s\n' "$job" "$result"; failed=$((failed + 1)) ;;
      *)
        printf '  FAIL  %-42s %s (unrecognised, failing closed)\n' "$job" "$result"
        failed=$((failed + 1)) ;;
    esac
  done < <(jq -r 'to_entries | sort_by(.key)[] | "\(.key)\t\(.value.result)"' <<<"$json")

  if [ "$failed" -gt 0 ]; then
    echo "  ${failed}/${count} gate(s) failed or were cancelled"
    return 1
  fi
  echo "  all ${count} gate(s) passed or were skipped"
  return 0
}

# --------------------------------------------------------------------------
# Self-test. Mirrors the --selftest convention of check-ci-lane-parity.sh and
# check-build-tags-selected.sh: the guard proves it can fail before it is
# trusted to say anything passed.
# --------------------------------------------------------------------------
selftest() {
  local pass=0 fail=0

  _mk() { # _mk job:result ...
    local out="{}" p j r
    for p in "$@"; do
      j="${p%%:*}"; r="${p##*:}"
      out="$(jq -c --arg j "$j" --arg r "$r" '. + {($j): {result: $r}}' <<<"$out")"
    done
    printf '%s' "$out"
  }

  _case() { # _case <desc> <pass|fail> <json>
    local desc="$1" want="$2" json="$3" got
    if evaluate "$json" >/dev/null 2>&1; then got="pass"; else got="fail"; fi
    if [ "$got" = "$want" ]; then
      echo "  ok    ${desc} -> ${got}"
      pass=$((pass + 1))
    else
      echo "  FAIL  ${desc} -> ${got} (wanted ${want})"
      fail=$((fail + 1))
    fi
  }

  echo "queue-gate-eval --selftest"

  # Controls: the shapes that must NOT block a merge.
  _case "all success"                     pass "$(_mk heavy:success coverage:success)"
  _case "mixed success + skipped (PR)"    pass "$(_mk fast:success heavy:skipped lint:success)"
  _case "every gate skipped"              pass "$(_mk fast:skipped heavy:skipped)"

  # Mutations: each must turn it red.
  _case "MUTATION one failed"             fail "$(_mk fast:success coverage:failure)"
  _case "MUTATION only live gate failed"  fail "$(_mk fast:failure heavy:skipped)"
  _case "MUTATION one cancelled"          fail "$(_mk fast:success heavy:cancelled)"
  _case "MUTATION all failed"             fail "$(_mk fast:failure lint:failure)"
  _case "MUTATION empty needs"            fail "{}"
  _case "MUTATION not an object"          fail "not-json"
  _case "MUTATION unrecognised result"    fail "$(_mk fast:success lint:borked)"

  echo "  ${pass} passed, ${fail} failed"
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  --selftest)
    selftest
    ;;
  --needs-json)
    echo "queue-gate: evaluating every dependency's result"
    evaluate "${2:-}"
    ;;
  *)
    echo "usage: $0 --needs-json '<toJSON(needs)>' | --selftest" >&2
    exit 2
    ;;
esac
