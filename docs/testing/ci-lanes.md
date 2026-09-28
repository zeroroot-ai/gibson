# CI lanes — which gate runs where

## The contract

**A green `pull_request` must mean the merge queue will accept the PR.**

Every gate runs in both the `pull_request` and `merge_group` lanes, with a small
set of declared exceptions. `make check-ci-lane-parity` fails the build if a job
pins itself to one lane without saying why.

## Why this matters

Before this contract, three gates ran only on `merge_group`: the coverage gates,
the `-tags integration` suite, and `go vet` across build-tag variants. When one
failed, GitHub removed the PR from the merge queue and the PR itself still
reported:

```
mergeStateStatus: CLEAN
failing checks:   (none)
```

The failure lived in a run on a transient `gh-readonly-queue/main/pr-<n>-<sha>`
branch, which is not linked from the PR and drops out of the default
`gh run list` view. In one evening, four PRs cycled
`added_to_merge_queue` → `removed_from_merge_queue` repeatedly, each showing
CLEAN. A monitor watching for merges and CI failures stayed silent throughout,
because from the PR's point of view neither ever happened.

The gates were right — every failure they caught was a real defect. The cost was
entirely in *when* they ran and *how* the failure surfaced.

## The table

| Gate | Lane | What it does |
|---|---|---|
| `changes` | PR only | change detection; plumbing, not a gate |
| `fast` | PR only | reusable vet/build/test + mod-tidy drift |
| `lint` | PR only | `make lint` (new-from-merge-base) + `lint-deadcode` |
| `vet-tags` | **both** | `go vet -tags=<leg> ./...` per declared build tag |
| `coverage` | **both** | absolute floor + 85% diff coverage |
| `integration` | **both** | `-tags integration`, testcontainers + envtest |
| `openbao` | **both** | `-tags 'openbao_smoke openbao_integration'`, hermetic testcontainers |
| `critical-paths` | **both** | Tier-3 critical-path manifest guard, plus the two CI guards below |
| `queue-gate` | **both** | native aggregator; the required status check |
| `heavy` | **queue only** | `go test -race ./...` × 2 build tags + govulncheck |
| `security / govulncheck` | **queue only** | govulncheck against the daemon binary |
| `CodeQL / Analyze Go` | **both, path-filtered** | skipped on PRs that touch no security path |
| `e2e-setec-roundtrip` | **queue only** | hardware-gated, self-hosted KVM runner |

The PR-only gates cannot cause a surprise: a PR-only gate blocks queue *entry*,
it does not evict mid-queue.

## The queue-only exceptions, and how they are made visible

Three gates are genuinely too expensive or too hardware-bound to run on every
push. Their absence is surfaced two ways rather than left silent:

1. **A PR job summary.** The `queue-gate` job writes a summary on every PR
   naming what the merge queue will additionally run.

2. **An eviction comment.** `.github/workflows/merge-queue-eviction-report.yml`
   watches every merge-queue-capable workflow. When a merge-group run fails, it
   recovers the PR number from the queue branch name and comments on the PR with
   the failing job names and a link to the run. So an eviction is always
   attributable from the PR alone.

`check-ci-lane-parity` asserts that every workflow with a `merge_group:` trigger
is named in that reporter's `workflows:` list, so a new queue gate cannot be
added without also being reported on.

## Reproducing the queue lane locally

```bash
make test-merge-queue     # the heavy tier: module-wide race, per build tag
```

This is expensive — two module-wide race passes, several GB resident, most of
the machine for minutes. Do not run it alongside `make lint` or another agent's
build. `govulncheck` is deliberately CI-only (see CLAUDE.md).

Everything else the queue runs, the PR already ran.

## Build tags: the "tests that cannot fail" class

`Makefile:BUILD_TAGS` is empty, so `make test`, `make test-race` and
`make coverage-profile` compile **only untagged files**. Every `//go:build <tag>`
suite is invisible to them.

That is how 34 test files under `tests/e2e/` went months without ever being
built. They could not even fail to compile. Five more tags were in
the same state: `test_fixtures`, `openbao_integration`, `openbao_smoke`,
`llm_integration`, `integration_spire`.

Compiling is not running, and the second half of the class is *mistagging*: a
file that needs no infrastructure but carries an infrastructure tag is just as
invisible. Six such files came out from under `e2e`. See
"The `e2e` tag was doing two jobs" below.

The `vet-tags` matrix in `.github/workflows/go-ci.yml` now selects every declared
tag, on both lanes, and `make check-build-tags` fails the build if a
`//go:build <tag>` file appears under a tag no leg selects. **go-ci.yml is the
allowlist** — there is no second list to keep in sync.

```bash
make vet-e2e         # compile the e2e suite only
make vet-tags        # every leg, locally (~1 min each)
make check-build-tags
```

### Compile signal is the floor, not the ceiling

`vet-tags` proves the tagged suites still *build*. Whether they *run* is a
separate question per tag:

| Tag | Compiles | Runs |
|---|---|---|
| `integration` | `vet-tags`, both lanes | `make test-integration`, both lanes (scoped `INTEGRATION_PKG`) |
| `setec_integration` | `vet-tags`, both lanes | `e2e-setec-roundtrip.yml`, self-hosted KVM runner |
| `openbao_smoke`, `openbao_integration` | `vet-tags`, both lanes | `make test-openbao` via the `openbao` job, both lanes (hermetic testcontainers, no live infra) |
| `e2e` | `vet-tags`, both lanes | the cluster-free part was untagged and runs in the default lane. The cluster-bound part runs on `main` and daily in the exit-test workflows (see "Where the cluster-bound `e2e` suites run" below), never on a PR (ADR-0012) |
| `test_fixtures` | `vet-tags`, both lanes | fixture-enabled image build (Dockerfile build-arg) |
| `llm_integration` | `vet-tags`, both lanes | **compile-only, deliberately** — needs a live LLM key (`ANTHROPIC_API_KEY`); spend + secret is an owner decision |
| `integration_spire` | `vet-tags`, both lanes | **compile-only, deliberately** — needs a live SPIRE Workload API socket, only reachable from inside a pod with the spire-agent socket mounted |

Do not delete an unrun suite and do not mark it skipped. Compile-level signal
already catches the common rot (a test referencing an RPC or symbol that no
longer exists); actually running them is tracked separately.

### The `e2e` tag was doing two jobs

`e2e` is supposed to mean *needs a live cluster*. Six files under it needed
nothing at all — they were tagged by proximity, not by dependency, so 54 checks
that a laptop can run in 1.6 seconds ran nowhere for months. They are untagged
now and execute in the default lane on every gate:

| File | What it covers |
|---|---|
| `tests/e2e/auth_test.go` | `config.AuthConfig` validation/defaults, tenant-scoped Redis keys, tenant context |
| `tests/e2e/health_test.go` | `/healthz` + `/readyz` over an in-process `httptest` server |
| `tests/e2e/dashboard_test.go` | OTel span emission against an in-memory exporter |
| `tests/e2e/helpers/console_filter{,_test}.go` | the browser-console allowlist filter |
| `tests/e2e/helpers/manifest_loader{,_test}.go` | the dashboard route-manifest loader |

First execution found three real defects, all of which had been latent since the
files were written:

1. `ConsoleFilter.Filter` short-circuited on `len(cf.entries) == 0`, so an empty
   allowlist leaked warn/info/log noise into the residue instead of filtering
   it. (Its `return msgLevel != "error"` was also unreachable-false.)
2. `TestTenantContext/nil_context` asserted the *legacy* `_system` fallback for
   `auth.TenantStringFromContext(nil)`. The SDK deliberately returns `""` so a
   missing identity is never promoted to the privileged system tenant; the
   assertion now pins that fail-closed contract.
3. `TestE2ECleanup` read its tracer from the process-global provider while
   asserting on a locally-built exporter, so the span it recorded could never
   arrive. `TestMissionSummarySpan` above it was the one mutating the global.

### Where the cluster-bound `e2e` suites run

The rest of the `e2e` tag needs a live cluster. The venue is an ephemeral
kind cluster on `ubuntu-latest`, brought up through hosted's
`make substrate ENV=kind` and `make recreate ENV=kind` (charts `main`,
`RUNG=ci`) with Envoy, Zitadel, SPIRE and a test-mode daemon. Per ADR-0012
these workflows run on `main` and on a schedule, never on a pull request.
They feed the launch scorecard and block nothing.

Two ways a suite reaches the cluster:

- **In-cluster.** The daemon's gRPC listener speaks SPIFFE mTLS only, so a
  suite that dials it runs as a Kubernetes Job with the runner's SVID
  (`.github/scripts/run-e2e-job.sh`). The test-mode daemon reads the tenant
  from `x-gibson-identity-tenant` for that SVID
  (`internal/server/daemon/e2e_peer_policy.go`). There is no tenant admin
  JWT in this venue. The SVID is the identity.
- **On the runner.** A suite that drives `kubectl`, port-forwards, or reads
  files a browser driver wrote runs as `go test -tags=e2e` with the
  cluster's kubeconfig.

| Suite | Workflow | How it runs |
|---|---|---|
| `tool_dispatch_test.go` | `exit-test-tool-dispatch.yml` | in-cluster Job, `TestToolDispatch` |
| `plugin_secret_revocation_test.go` | `exit-test-tool-dispatch.yml` | in-cluster Job, `TestPluginSecretRevocation` |
| `sandboxed_agent_dispatch_test.go` | `exit-test-sandboxed-dispatch.yml` | in-cluster Job |
| `bank_test.go` | `exit-test-bank.yml` | in-cluster Job, gated on a repository variable and a real key |
| `tests/e2e/secrets/*` (5 files, 4 tests) | `exit-test-e2e-cluster.yml` | in-cluster Job, `secrets.test` binary. Reads SKIP until gibson#213 moves the suites to the SVID path |
| `plugin_e2e_test.go` | `exit-test-e2e-cluster.yml` | SKIP by design: needs a debug-plugin subprocess and a human-minted bootstrap token. The plugin path is proven by `plugin_secret_revocation_test.go` |
| `mission_finding_per_tenant_e2e_test.go` | `exit-test-e2e-cluster.yml` | on the runner, `kubectl`-driven |
| `audit_v4_foundation_test.go` `live_*` | `exit-test-e2e-cluster.yml` | on the runner, port-forwards at the suite's NodePort constants. Reads FAIL until gibson#214 makes the suite drive its own mission |
| `signup_full_chain_test.go`, `login_full_chain_test.go`, `dashboard_smoke_test.go` | `exit-test-e2e-cluster.yml` | SKIP: the Go half reads files the dashboard repository's Playwright specs write, and no browser runs on the venue yet (gibson#215). hosted's `exit-test-signup.yml` proves the signup chain |
| `operators/tenant/test/e2e` | `exit-test-e2e-cluster.yml` | on the runner through `make test-e2e`, on a kind cluster of its own, with `plans.yaml` copied from the charts checkout |

`exit-test-e2e-cluster.yml` writes one verdict row per suite
(`.github/scripts/e2e-suite-verdict.sh`): PASS, FAIL or SKIP, with the
skipped subtest count. Any FAIL fails the run. Every SKIP is a warning,
because a skip is coverage the lane does not have. A suite whose step never
ran counts as FAIL. The rows and every suite's log are uploaded as the
`e2e-cluster-<run id>` artifact.

The per-suite state after each run is recorded on zeroroot-ai/gibson#32
until every suite passes or has its own issue.

Do not delete an unrun suite and do not mark one skipped.

### Redis-backed suites (no build tag)

`internal/engine/state` is untagged, so it is part of the default build — but
its integration tests need a live Redis Stack (RediSearch + RedisJSON). They
probe `localhost:6379` and skip when it is unreachable (see
`requireTenantStoreRedis` / `main_test.go`; the bare `t.Skip` they used to open
with was removed). The `coverage` job provisions a
`redis/redis-stack-server` service on `localhost:6379` and runs `go test ./...`
(no `-short`), so these tests — including the `TestTenantScopedStore_*`
tenant-isolation trio — execute there on **both** lanes. `heavy`
and `vet-tags` do **not** provision Redis, so the same suites self-skip under
those jobs by design.

## Wall-clock latency assertions in the default lane

`TestBuilderBuild_P95Budget_50c_100r` (`internal/platform/manifest/builder_bench_test.go`)
asserts a 100ms p95 budget on manifest builds. It is untagged, so it runs in the
default lane on shared GitHub-hosted runners, where absolute wall-clock bounds
are exposed to runner contention.

**Decision:** keep the test in the default lane, but assert a real
p95 over ≥100 samples (`slices.Sort` + index at `len*0.95`) instead of the max
of 20 samples. A single contended sample no longer fails the gate; five
concurrent slow samples out of 100 would have to land above budget, which is a
real regression signal, not scheduler noise. Locally the build runs ~4000x under
budget, so the margin is algorithmic, not tuned to hardware.

If this still flakes, the recorded next step is to convert it to a `Benchmark*`
with `benchstat` regression detection in a dedicated lane and keep only a coarse
order-of-magnitude smoke bound here — do **not** raise the 100ms constant.

## Adding a job to go-ci.yml

Run it in both lanes:

```yaml
  my-gate:
    needs: changes
    if: github.event_name == 'merge_group' || (github.event_name == 'pull_request' && needs.changes.outputs.go == 'true')
```

If it genuinely cannot, declare it — the guard requires a
`# lane-exception: <reason>` comment in the contiguous comment block immediately
above the `if:`, and the reason must say both why it cannot run in both lanes
and how its absence is made visible on the PR.
