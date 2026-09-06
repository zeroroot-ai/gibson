#!/usr/bin/env bash
# check-queue-gate-coverage.sh — CI guard: the required context must depend on
# every gate in its workflow.
#
# Spec: the class is gibson#1233 / gibson#1368 (a gate that runs, reports, and
# decides nothing); the concrete case is `queue-gate` having shipped with a
# `needs:` list naming five of the nine gate jobs in go-ci.yml. `fast`, `lint`
# and `critical-paths` were outside it, and none of the three is in the
# ruleset's required_status_checks either — so all three could go red on a PR
# that then merged. `critical-paths` runs `make check-ci-lane-parity` and
# `make check-build-tags`, which are the guards that keep the lane-parity
# invariant at the top of go-ci.yml enforceable. They were themselves
# unenforced.
#
# THE PROPERTY
# ------------
# `queue-gate` is the single status check the merge queue requires for this
# workflow. Every other job in the same file is therefore only as blocking as
# `queue-gate`'s `needs:` list says it is. So that list must name all of them.
#
# The complementary direction — a job listed in `needs:` whose result is then
# not evaluated — cannot happen, because queue-gate-eval.sh reads
# `${{ toJSON(needs) }}` wholesale rather than restating job names. Between the
# two, neither half can drift from the other.
#
# WHY IT LIVES HERE AND NOT IN THE RULESET
# ----------------------------------------
# The ruleset's required_status_checks list is in a different repo
# (zeroroot-ai/.github, rulesets/repo/gibson.json). Nothing connects a gate
# added here to that list there, so it falls behind the first time anyone adds
# a job — which is how the list came to name nine contexts while ~20 jobs ran.
# With one aggregated context, the same invariant becomes checkable inside this
# repo, by this script, on every PR.
#
# EXEMPTIONS
# ----------
# Only `changes` (and `queue-gate` itself). `changes` is change detection, not
# a gate: every job it feeds already `needs:` it, so a failure there fails them
# and reaches `queue-gate` that way. Keep the list this short — every entry is
# a hole, and the reason `critical-paths` went unnoticed for as long as it did
# is that nothing forced anyone to justify its absence.
#
# Usage:
#   check-queue-gate-coverage.sh [workflow.yml ...]   (default: go-ci.yml)
#   check-queue-gate-coverage.sh --selftest
#
# Exit 0 = every gate job is covered. Exit 1 = at least one is not.

set -uo pipefail

WORKFLOW_DEFAULT=".github/workflows/go-ci.yml"
AGG="queue-gate"
EXEMPT_CSV="changes"

_check_one() {
  python3 - "$1" "$AGG" "$EXEMPT_CSV" <<'PY'
import sys, yaml

path, agg, exempt_csv = sys.argv[1], sys.argv[2], sys.argv[3]
exempt = {e for e in exempt_csv.split(",") if e} | {agg}

try:
    doc = yaml.safe_load(open(path))
except FileNotFoundError:
    print(f"::error::{path}: no such workflow file")
    sys.exit(1)

jobs = doc.get("jobs") or {}

if agg not in jobs:
    print(f"::error::{path}: no `{agg}` job. This workflow feeds the single "
          f"required status check and must define the aggregator.")
    sys.exit(1)

needs = jobs[agg].get("needs") or []
if isinstance(needs, str):
    needs = [needs]
needs = set(needs)

# `if: always()` is not cosmetic: without it GitHub skips the aggregator
# whenever any dependency is skipped, and an ABSENT required context freezes
# merge-queue entry rather than failing the PR (.github#202). That is a worse
# outcome than a red check, so it is checked here rather than left to review.
cond = str(jobs[agg].get("if") or "")
if "always()" not in cond:
    print(f"::error::{path}: `{agg}` must carry `if: always()` (found: {cond!r}).")
    print(f"::error::A needs: job is skipped when ANY dependency is skipped, so "
          f"without it the required context goes ABSENT — which freezes "
          f"merge-queue entry instead of failing the PR.")
    sys.exit(1)

gates = set(jobs) - exempt
missing = sorted(gates - needs)
phantom = sorted(needs - set(jobs))

rc = 0
if missing:
    print(f"::error::{path}: `{agg}` does not depend on: {', '.join(missing)}")
    print(f"::error::Those jobs run, can report red, and would not block a merge.")
    print(f"::error::Add them to `{agg}`'s needs:, or justify an exemption in "
          f"scripts/check-queue-gate-coverage.sh.")
    rc = 1
if phantom:
    print(f"::error::{path}: `{agg}` lists job(s) that do not exist: "
          f"{', '.join(phantom)}. GitHub fails the workflow at parse time on "
          f"this, so it presents as infrastructure breakage, not a gate failure.")
    rc = 1

if rc == 0:
    print(f"ok  {path}: `{agg}` covers all {len(gates)} gate job(s): "
          f"{', '.join(sorted(gates))}")
sys.exit(rc)
PY
}

# --------------------------------------------------------------------------
# Self-test — same --selftest convention as check-ci-lane-parity.sh and
# check-build-tags-selected.sh. Fixtures, not the real tree, so the assertions
# stay true as go-ci.yml evolves.
# --------------------------------------------------------------------------
_selftest() {
  local dir pass=0 fail=0
  dir="$(mktemp -d)"
  trap 'rm -rf "$dir"' RETURN

  _case() { # _case <desc> <pass|fail> <yaml>
    local desc="$1" want="$2" got
    printf '%s' "$3" > "${dir}/wf.yml"
    if _check_one "${dir}/wf.yml" >/dev/null 2>&1; then got="pass"; else got="fail"; fi
    if [ "$got" = "$want" ]; then
      echo "  ok    ${desc} -> ${got}"; pass=$((pass + 1))
    else
      echo "  FAIL  ${desc} -> ${got} (wanted ${want})"; fail=$((fail + 1))
    fi
  }

  echo "check-queue-gate-coverage --selftest"

  _case "every gate covered (changes exempt)" pass '
on: {pull_request: null, merge_group: null}
jobs:
  changes: {runs-on: ubuntu-latest}
  fast: {runs-on: ubuntu-latest}
  lint: {runs-on: ubuntu-latest}
  queue-gate: {if: "always()", needs: [fast, lint], runs-on: ubuntu-latest}
'

  # THE regression: this is exactly the shape go-ci.yml was in.
  _case "MUTATION a gate missing from needs" fail '
on: {pull_request: null, merge_group: null}
jobs:
  fast: {runs-on: ubuntu-latest}
  lint: {runs-on: ubuntu-latest}
  critical-paths: {runs-on: ubuntu-latest}
  queue-gate: {if: "always()", needs: [fast, lint], runs-on: ubuntu-latest}
'

  _case "MUTATION needs names a nonexistent job" fail '
on: {pull_request: null, merge_group: null}
jobs:
  fast: {runs-on: ubuntu-latest}
  queue-gate: {if: "always()", needs: [fast, deleted], runs-on: ubuntu-latest}
'

  _case "MUTATION needs emptied" fail '
on: {pull_request: null, merge_group: null}
jobs:
  fast: {runs-on: ubuntu-latest}
  queue-gate: {if: "always()", needs: [], runs-on: ubuntu-latest}
'

  _case "MUTATION aggregator deleted" fail '
on: {pull_request: null, merge_group: null}
jobs:
  fast: {runs-on: ubuntu-latest}
'

  # Dropping always() is the subtle one: the workflow still looks correct and
  # the job still exists, but the context goes absent on any run where a gate
  # skipped -- which is most runs.
  _case "MUTATION always() dropped from the aggregator" fail '
on: {pull_request: null, merge_group: null}
jobs:
  fast: {runs-on: ubuntu-latest}
  queue-gate: {needs: [fast], runs-on: ubuntu-latest}
'

  _case "MUTATION always() replaced by a lane condition" fail '
on: {pull_request: null, merge_group: null}
jobs:
  fast: {runs-on: ubuntu-latest}
  queue-gate: {if: "github.event_name == 'merge_group'", needs: [fast], runs-on: ubuntu-latest}
'

  echo "  ${pass} passed, ${fail} failed"
  [ "$fail" -eq 0 ]
}

if [[ "${1:-}" == "--selftest" ]]; then
  _selftest
  exit $?
fi

rc=0
if [ "$#" -eq 0 ]; then
  set -- "$WORKFLOW_DEFAULT"
fi
for wf in "$@"; do
  _check_one "$wf" || rc=1
done
exit $rc
