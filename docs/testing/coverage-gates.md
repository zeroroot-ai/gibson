# Coverage gates

Two blocking CI gates govern test coverage in this repo (gibson#794, E3 /
QUALITY-BARS §4). Together they supersede the former flat 60% bar (ADR-0021).

| Gate | What it checks | Where | Blocking |
|------|----------------|-------|----------|
| Absolute floor | repo-wide total coverage ≥ the committed floor, ratcheting toward **80%** | `scripts/check-coverage-floor.sh` + `.coverage-floor` | yes |
| Diff coverage | **≥85%** of the statement lines a PR changes are covered | `cmd/diff-coverage` | yes |

Both run in the `coverage` job of `.github/workflows/go-ci.yml`, which generates
one repo-wide profile (`make coverage-profile`, with the same redis + envtest
setup as the correctness pass) and feeds it to both gates.

**The job runs on `pull_request` as well as `merge_group` (gibson#1233).** It
used to be merge_group-only. When `check-diff-coverage` failed there, GitHub
evicted the PR from the merge queue and the PR still reported
`mergeStateStatus: CLEAN` with no failing check — the uncovered lines were only
visible in a run on a transient `gh-readonly-queue/...` branch that is not linked
from the PR. Four PRs in one evening cycled in and out of the queue that way. The
gate now fails as an ordinary red check on the PR, before a queue slot is spent.
See [ci-lanes.md](ci-lanes.md) for the full lane table.

## Why a ratchet, not a hard 80%

Repo-wide coverage is ~38% today. Flipping to a hard 80% absolute floor would
red `main` immediately and demand an unreviewable backfill — the kind of
systemic block the workflow rules forbid. So the absolute floor is a **ratchet**:

- `.coverage-floor` holds a single number the total may never drop below.
- It may only ever rise toward 80. As tests land and coverage climbs a point
  above the floor, the gate prints a NOTE; bump `.coverage-floor` in that PR to
  lock the gain in.
- New code carries its own weight via the diff-coverage gate, which is
  incremental by construction (it only looks at changed lines) and so is
  enforced at the full 85% from day one.

This mirrors the repo's existing `lint-deadcode-baseline` and the per-RPC
handler-test baseline (gibson#793).

## Running locally

```bash
make coverage-profile          # writes coverage.out
make check-coverage-floor      # absolute floor
make check-diff-coverage       # 85% on lines changed vs origin/main
# or both at once against an existing profile:
make check-coverage-gates
```

`make coverage-profile` needs the same dependencies as the test suite; without
envtest binaries the operator suites self-skip, lowering the local number
slightly versus CI (the floor's margin absorbs this).

## Responding to a failure

**Diff coverage failed.** The output lists each changed-but-uncovered line as
`file:line`. Add tests that exercise those lines. Lines outside any statement
(comments, blanks, bare declarations) and generated/test files are not counted.

**Absolute floor failed.** Your change dropped total coverage below
`.coverage-floor`. Add tests to restore it. Lowering the floor requires an
explicit, justified edit to `.coverage-floor` in the PR.
