# CLAUDE.md — `core/gibson/`

Guidance for Claude Code working inside the Gibson daemon. Keep this file in sync with the code; it is the first thing the agent reads before editing this module.

## Project Overview

Gibson is the Kubernetes-native AI-agent orchestration **daemon** — a single Go 1.25 binary that exposes gRPC (`:50002`), runs mission DAGs, brokers multi-provider LLM calls, manages a Redis-backed component registry (agents/tools/plugins), and persists discoveries into a Neo4j knowledge graph. All components connect **into** this daemon; agents never touch Redis / Neo4j / LLM providers directly.

## Build & Test

```bash
make bin                    # bin/gibson (CGO_ENABLED=0, ldflags inject Version/GitCommit/BuildTime)
make test / test-race       # unit / race
make test-coverage          # enforces 90% via scripts/check-coverage.sh
make lint                   # golangci-lint
make check                  # fmt + vet + lint + test-race (pre-commit gate)
make proto / proto-clean    # regenerate local daemon proto via Buf
make check-authz [INTEGRATION=1]   # authz tests, +Docker for FGA testcontainers
go test -v -run TestName ./internal/path/...
```

Test file conventions: `*_test.go` (unit), `*_integration_test.go` (testcontainers for Redis / Neo4j / FGA), `*_e2e_test.go`. `testify/assert`. Mocks live beside the code they mock.

## Directory Map (AI reference)

```
cmd/gibson/          CLI entry (cobra). root.go, daemon.go, config.go, cutover_v4.go, authz/, mode/, internal/ (output/err helpers), templates/, testdata/
internal/
  daemon/            Lifecycle: daemon.go (New/Start), grpc.go, infrastructure.go, signals.go, checkpoint_manager.go, eventbus*.go, event_stream_redis.go, credential_store.go, health_state.go
  daemon/api/        DaemonServer impl for BOTH DaemonService (proto in SDK) + DaemonAdminService (proto local). server.go (~3000 LOC) + split handlers: server_{agentauth,alerts,audit,chat,quota,user,prod_handlers}.go, findings_export.go, credentials.go
  daemon/api/gibson/daemon/admin/v1/   daemon_admin.proto — the ONLY proto file owned by this module
  orchestrator/      Mission DAG executor: act / think / observe / recall / reflect stages, decision logic, error recovery, embedding cache
  mission/           YAML parse + validate + load, MissionService, Redis stores (definitions, runs, events), checkpoint codec/manager, inline_processor (inline:// targets), controller state machine
  missiondraft/      Redis-backed 30-day mission YAML drafts
  checkpoint/        Mission pause/resume: codec, retention, blob store (Redis + optional S3)
  harness/           AgentHarness interface + CallbackServer (HarnessCallbackService gRPC), HarnessFactory, OTel middleware, compliance middleware
  component/         Redis component registry (30s TTL), lifecycle, load balancer (RoundRobin/Random/LeastConnection), circuit breaker, gRPC pool + per-kind clients (agent/tool/plugin), PluginAccessStore, ToolAccessStore, AgentAccessStore, quota
  agent/             Agent descriptor introspection, stream manager
  tool/              Tool metadata, registry helpers
  plugin/            Plugin metadata, registry helpers
  agentauth/         Agent Auth Protocol: mint agent JWTs, FGA capability grant bridge
  auth/              5-path authN: API key (gsk_), OIDC JWT (any compliant IdP), K8s SA, SPIFFE/SPIRE, Better Auth session tokens (better_auth.go); FGA gRPC interceptor + fga_rpc_registry.go declarative RPC→(type,relation) map; audit.go
  authz/             OpenFGA HTTP client wrapper, noopAuthorizer, envelope HMAC signer, model.fga (schema 1.1)
  llm/               Slot resolver, provider registry (Anthropic/OpenAI/Gemini/Ollama), rate limiter, pricing, embedding provider + cache, JSON extractor, tool-use tracker, error recovery
  memory/            3-tier: working (in-process), mission (Redis), longterm (vector store); MemoryFactory, TracedMemoryManager, embedder/ (OpenAI/Ollama/local), token counting
  graphrag/          Neo4j GraphStore (+ traced), loader/ (persist DiscoveryResult protos), processor/ (DiscoveryProcessor handles tool proto field 100), intelligence/ (graph queries for agent context), schema/, query.go, graph_bootstrap.go
  neo4j/             Thin Neo4j client + schema migration runner
  finding/           Finding persistence, lifecycle, evidence tracking
  crypto/            AES-256-GCM + KeyProvider: k8s secret / Vault / AWS SM / Azure KV / GCP SM (factory)
  config/            Loader, schema, validation, env var substitution `${VAR:-default}`
  state/             Redis client wrapper, TenantScopedStore (tenant-prefixed keys)
  database/          Redis DAOs (TargetDAO, CredentialDAO, …)
  events/            In-process pub/sub primitives (bus lives in internal/daemon)
  observability/     slog logger, OTel stack (tracer/meter/logger providers), OTLP exporters, attributes helpers
  audit/             Audit writer, Loki client, Redis audit stream consumers
  impersonation/     Tenant impersonation token issuer (platform-operator only)
  onboarding/        Redis-backed tenant onboarding state
  guardrail/         Policy/compliance gates enforced inside the mission loop
  contextkeys/       Shared ctx keys (AgentRunID, ToolExecutionID, MissionRunID, AgentName, MissionID) — exists to break import cycles
  schema/            Shared mission / graphrag schema types (task, result, finding, target, endpoint)
  types/             Core domain types (Mission, Target, Agent, Task, Result, Finding)
  plan/              Mission planning helpers used by orchestrator
  prompt/            Prompt template management
  payload/           Compliance payload definitions
  attack/            Ad-hoc attack runner (outside mission DAG)
  eval/              Agent/mission evaluation harness (lightly integrated)
  cutover/v4/        V4 audit-foundation migration support (legacy, still referenced by CLI cutover_v4.go)
  testing/           Test fixtures shared across packages
  version/           Build-time version info (set via ldflags)
pkg/version/         Same version pkg re-exported for external consumers
api/                 (no .proto here; intentionally empty placeholder — the repo's proto lives under internal/daemon/api/…)
sdk/                 Shared graphrag + manifest helpers used by this daemon and SDK tests
models/huggingface/  Embedding model metadata
configs/             gibson.yaml template
scripts/             check-coverage.sh etc.
tests/               integration + e2e tests (cross-package)
```

## Daemon Startup Pipeline (`internal/daemon/daemon.go` → `Start()`)

Phased init — later phases depend on earlier. Reordering is breaking.

1. **State client (Redis)** — REQUIRED. Retry loop; initialises Redis event stream.
2. **Authorizer** — OpenFGA client or noop (see Authz table below).
3. **Dashboard Postgres pool** — optional; non-fatal if missing (used for audit_log reads, tenant state).
4. **Component registry + lifecycle** — Redis, 30 s TTL heartbeat. Registry adapter wires discovery callbacks.
5. **Mission stack** — `MissionService`, `MissionStore`, `MissionRunStore`, `EventStore`, `InlineConfigProcessor`, `CheckpointManager`.
6. **Quota manager** — per-tenant caps (missions / agents / findings).
7. **Infrastructure bundle** — DAG executor, finding store, LLM registry, memory factory, harness factory, OTel stack, GraphRAG store + discovery processor.
8. **Credential store** — KeyProvider + CredentialDAO (optional; enabled if `security.key_provider` set).
9. **Access stores** — Tool / Agent / Plugin opt-in (Redis).
10. **gRPC server** (`grpc.go`) — auth interceptors (conditional on `auth.IsAuthEnabled()`), FGA interceptor (conditional on authz.enabled), SPIFFE mTLS (optional), registers DaemonService + DaemonAdminService + ComponentService + HarnessCallbackService, Redis daemon registration for CLI discovery.
11. **Event bus** — in-process pub/sub + per-tenant Redis Streams bridge.
12. **Health server** on `:8080` — `/healthz` liveness, `/readyz` readiness (FGA probe with 10 s TTL cache when authz enabled).
13. **Signal handler** — 4-phase graceful shutdown: PreShutdown → Checkpoint (save active missions to Redis via `DaemonMissionCheckpointer`) → Wait (drain) → Terminate.

## gRPC Surface

Two Gibson-owned services plus one re-exported SDK service plus the harness callback service. **Public** = on the main daemon port; **Admin** = same port but FGA-gated to platform-operator role.

| Service | Proto source | Purpose |
|---|---|---|
| `gibson.daemon.v1.DaemonService` | **SDK** (`sdk/api/gen/gibson/daemon/v1`, alias `daemonpb`) | Public mission / component / agent control plane. RPCs: Connect, Ping, Status, RunMission (stream), StopMission, Pause/ResumeMission, List/Get Mission{History,Checkpoints}, ListAgents, GetAgentStatus, ListTools, ListPlugins, QueryPlugin, Subscribe (stream), Start/StopComponent, Install/Uninstall/Update/CreateMission, ListMissionDefinitions, Show/Build/Update/UninstallComponent, GetComponentLogs (stream), InstallAllComponent, GetMyPermissions |
| `gibson.daemon.admin.v1.DaemonAdminService` | **Local** (`internal/daemon/api/gibson/daemon/admin/v1/daemon_admin.proto`) | Privileged ops: Shutdown, ImpersonateTenant, {Get,Set,Delete}TenantLangfuseCredentials, {Get,Update}OnboardingState, {Create,List,Revoke}APIKey, ListAuditEvents, agent-auth (RegisterAgentAuth, ExecuteAgentCapability, GetAgentAuthStatus, RevokeAgentAuth, ListAgentAuthAgents, ListAgentCapabilities, CreateHostRegistrationToken, ListComponentGrants, BatchGrantComponentAccessV2, ListAuditLog), tenant quota/sessions/alerts/conversations, findings export, mission drafts, user-profile RPCs (ResetPassword / RevokeUserSessions / SuspendMember — some stubbed, see Implementation Status below). |
| `gibson.component.v1.ComponentService` | SDK | `RegisterComponent`, `PollWork` (stream), `SubmitResult`, heartbeat. Called by every agent / tool / plugin. |
| `gibson.harness.v1.HarnessCallbackService` | SDK | Agent → daemon callbacks: `ExecuteLLM`, `SubmitFinding`, `Store/GetMemory`, `ExecuteTool`, `QueryPlugin`, `GetCredential`. Runs on `:50001` via `harness.CallbackManager`. |

**Implementation status within DaemonAdminService** — core admin RPCs (authz, audit, API keys, impersonation, Langfuse creds, agent-auth, onboarding) are fully wired. The `prod-unimplemented-apis` / `prod-feature-wiring` spec tracked stubs are in `server_prod_handlers.go` (ResetPassword, RevokeUserSessions, SuspendMember, Get/UpdateUserProfile, ExportFindings, SaveMissionDraft/ListMissionDrafts, GetUserSessions, Alerts, Conversations) — they return valid empty/stub responses and are enforced by `TestNewRPCsNotUnimplemented` (`server_integration_test.go`) to never emit `codes.Unimplemented`.

## Feature Catalog — what's wired and where

| Feature | Primary pkg | Wired-in status | Key deps |
|---|---|---|---|
| Mission orchestration (DAG act/think/observe/recall/reflect) | `internal/orchestrator/` + `internal/mission/` | ✅ Active | Redis, LLM, harness, GraphRAG |
| Mission pause/resume | `internal/mission/checkpoint*.go` + `internal/checkpoint/` | ✅ Active | Redis + optional S3 blob store |
| Component registry + load balancing | `internal/component/` | ✅ Active | Redis, component gRPC |
| Agent harness (unified capability API) | `internal/harness/` | ✅ Active | LLM registry, memory, finding store, plugin access |
| 3-tier memory | `internal/memory/` | ✅ Active | Redis + vector store + embedder |
| LLM multi-provider slot resolution | `internal/llm/` | ✅ Active | provider API keys |
| GraphRAG ingest (proto field 100 → Neo4j) | `internal/graphrag/` | ✅ Active | Neo4j |
| GraphRAG intelligence queries (agent recall) | `internal/graphrag/intelligence/` | ✅ Active | Neo4j |
| 4-path authN (apikey / OIDC / K8s SA / SPIFFE) | `internal/auth/` | ✅ Active | Redis (apikey store), OIDC issuer, SPIRE (optional) |
| OpenFGA authZ | `internal/authz/` + `internal/auth/fga_authz_interceptor.go` | ✅ Active | FGA HTTP `gibson-fga:8080` |
| Agent Auth Protocol (JWT mint + FGA bridge) | `internal/agentauth/` | ✅ Active (dispatch of `ExecuteAgentCapability` is a thin stub — FGA check works, execution forwarding is minimal) | FGA |
| Plugin config encryption (AES-256-GCM) | `internal/crypto/` | ✅ Active if `security.key_provider` set | k8s/Vault/AWS/Azure/GCP |
| Event streaming (`Subscribe` RPC) | `internal/daemon/eventbus*.go` + `internal/events/` | ✅ Active | Redis Streams (optional; in-process fallback) |
| Audit logging | `internal/audit/` | ✅ Wired, low usage | Redis stream + Loki + Postgres |
| Health probes | `internal/daemon/health_state.go` + SDK `healthhttp` | ✅ Active | FGA (for `/readyz` if authz on) |
| Observability (logs / traces / metrics) | `internal/observability/` | ✅ Active | OTLP collector (optional) |
| Tenant impersonation | `internal/impersonation/` | ✅ Active, minimal callers | FGA role check |
| Onboarding state | `internal/onboarding/` | ✅ Active, minimal callers | Redis |
| Guardrails | `internal/guardrail/` | ✅ Active inside mission loop | — |
| Eval harness | `internal/eval/` | ⚠️ Lightly integrated; only orchestrator touches it | — |
| Ad-hoc attack runner | `internal/attack/` | ⚠️ Called outside mission DAG; niche | — |
| V4 cutover / migration | `internal/cutover/v4/` | ⚠️ Kept for backward-compat; invoked only by CLI `cutover_v4.go` | — |

## CLI (`cmd/gibson/`)

Commands are classified in `cmd/gibson/mode/registry.go`:

- **Standalone** (no daemon conn): `version`, `completion`, `config {show,get,set,validate}`, `authz {check,write,model-info}`
- **Daemon** (lifecycle): `daemon {start,stop,status,restart}`
- **Client** (default): every other command talks to the running daemon via gRPC (discovered through Redis registration). `cutover_v4` is a client-mode legacy migration command.

Global flags: `--home`, `--config`, `--verbose`, `--output-format`.

## Authorization (OpenFGA) — Startup Behaviour Matrix

| `authz.enabled` | FGA reachable | `require_ready` | Result |
|---|---|---|---|
| false | — | — | noop authorizer, INFO log |
| true | yes | — | FGA authorizer, INFO log |
| true | no | true | daemon fails to start (production) |
| true | no | false | noop authorizer, WARN log (dev) |

- FGA endpoint is **HTTP** at `gibson-fga:8080` (not gRPC 8081).
- Per-RPC `(object_type, relation)` mapping is declarative in `internal/auth/fga_rpc_registry.go`; changes to that map are load-bearing — `fga_rpc_coverage_test.go` asserts every RPC has a rule.
- `internal/authz/model.fga` is schema 1.1 with types `user`, `tenant`, `component`, `system_tenant`. Provisioned by the `gibson-fga-init` k8s Job on helm install/upgrade.
- Store/model IDs resolved in order: config file → ConfigMap `gibson/gibson-fga-config` → env `GIBSON_AUTHZ_FGA_STORE_ID` / `..._MODEL_ID`.

## Multi-Tenancy Rules

- `_system` is the platform-tenant; hosts plugins available to every tenant.
- `ComponentService` reads tenant from auth metadata via `auth.TenantFromContext()`.
- Registry exposes `Discover`, `DiscoverAll`, `DiscoverTenantOnly`, `DiscoverSystemOnly` — pick deliberately; `DiscoverAll` leaks system components into tenant listings.
- **Tenant create/provision/deprovision is NOT in this daemon.** It moved to the external `gibson-tenant-operator`. Gibson is a read-consumer of tenant state. Do not add tenant lifecycle RPCs here.

## Proto / Generated Code

This module owns **exactly one** proto file:

- `internal/daemon/api/gibson/daemon/admin/v1/daemon_admin.proto` — package `gibson.daemon.admin.v1`, `go_package` points back into `internal/daemon/api`, so the generated `daemon_admin.pb.go` + `daemon_admin_grpc.pb.go` live alongside `server.go`.

Everything else (`gibson.daemon.v1`, `gibson.component.v1`, `gibson.harness.v1`, `gibson.agent.v1`, `gibson.tool.v1`, `gibson.plugin.v1`, `gibson.graphrag.v1`, `gibson.types.v1`, `gibson.common.v1`, `gibson.workflow.v1`, `taxonomy.v1`, `intelligence.v1`, tool-specific `toolspb`) is **consumed** from the SDK (`github.com/zero-day-ai/sdk/api/gen/...`). Gibson imports those generated Go types — never hand-writes them, never duplicates the proto files here.

`make proto` runs `npx --prefix ../../enterprise/dashboard buf generate`, so the dashboard sibling checkout must exist. `buf lint` uses the STANDARD ruleset, no exceptions. When you add an admin RPC: regenerate Go here, then regenerate TypeScript in the dashboard repo.

## Dead / Legacy Code (verified 2026-04-15)

Pay attention to these when refactoring — they look load-bearing but generally aren't. Confirm with grep before deleting; some are kept intentionally.

| Path | Reality | Recommendation |
|---|---|---|
| `internal/util/` | Only `paths.go` + test | Keep; used by config loader |
| `internal/cutover/v4/` | Audit-foundation migration used by the `gibson cutover-v4` CLI | Keep until all deployments have cut over; then remove alongside the CLI command. |
| Stub RPCs in `server_prod_handlers.go` (ResetPassword, RevokeUserSessions, SuspendMember, Get/UpdateUserProfile, ExportFindings, mission drafts, GetUserSessions, Alerts, Conversations) | Intentional — tracked under `prod-unimplemented-apis` and `prod-feature-wiring` specs; test-enforced to return non-Unimplemented | Implement per-spec; don't delete. |

## Tracked Security Advisories (awaiting upstream fix)

Dependabot advisories against this module that have no patched release available yet. Revisit when the upstream target ships.

| Advisory | Severity | Current pin | Target pin | Trigger |
|---|---|---|---|---|
| [GHSA-x744-4wpc-v9h2](https://github.com/advisories/GHSA-x744-4wpc-v9h2) — Moby AuthZ plugin bypass via oversized request bodies | HIGH | `github.com/docker/docker v28.5.2+incompatible` (indirect) | `v29.3.1+incompatible` (unreleased as of 2026-04-15) | `go get github.com/docker/docker@latest` once 29.3.1 ships |
| [GHSA-pxq6-2prw-chj9](https://github.com/advisories/GHSA-pxq6-2prw-chj9) — Moby plugin privilege off-by-one | MEDIUM | `github.com/docker/docker v28.5.2+incompatible` (indirect) | `v29.3.1+incompatible` | same as above |

## Critical Rules

- **GitHub-only imports.** No `replace` directives to local paths, no `file://` refs. Local replace causes proto descriptor mismatches and daemon panics. Use `go work` if you must iterate on the SDK locally.
- **No tool / plugin / agent modules in `go.mod`.** Gibson depends on the SDK only. Tool proto types for extraction come from the SDK's `toolspb`.
- **Proto field 100** in every tool response is reserved for `gibson.graphrag.v1.DiscoveryResult`. Do not repurpose it.
- **`component.yaml`** defines agent/tool/plugin metadata for registry discovery — loadable without booting the binary.
- **Never hand-write proto message types or gRPC stubs.** Always `buf generate`.
- **GitOps for Kubernetes.** No `kubectl patch`, no live ConfigMap edits, no ad-hoc mutation — go through Helm values / manifest commits unless the session is explicitly authorised for a one-off.
- **Do not add tenant lifecycle RPCs here.** Those belong to `gibson-tenant-operator`.
- **Structured logging with `log/slog`** + context propagation; no `fmt.Println` in daemon paths.
- **`CGO_ENABLED=0`** for all builds; Go 1.25.

## Configuration (`configs/gibson.yaml` or `~/.gibson/config.yaml`)

Key sections: `core` (home/data/cache dirs, parallel_limit), `security` (encryption algo, `key_provider` = k8s/vault/aws/azure/gcp), `llm` (default_provider + providers), `memory` (embedder + vector store), `logging`, `tracing`, `metrics`, `registry`, `callback`, `daemon` (grpc addr), `health`, `redis` (REQUIRED), `plugins`, `auth` (OIDC issuers, K8s SA, SPIFFE, better-auth, local users), `authz` (FGA store/model IDs, `require_ready`), `checkpoint` (redis or s3 blob backend), `observability` / `otel_observability`, `dashboard_postgres` (optional; non-fatal if missing). Env var substitution: `${VAR:-default}`.

## Infrastructure Dependencies

- **Redis** — required. state, queues, mission memory, daemon registration, plugin/credential storage, component registry, event streams, audit stream.
- **Neo4j 5.x** — GraphRAG knowledge graph (only required if GraphRAG is exercised).
- **OpenFGA** — authZ (HTTP `gibson-fga:8080`); required when `authz.enabled=true && authz.require_ready=true`.
- **PostgreSQL** (dashboard DB) — optional; audit_log reads, tenant state. Non-fatal if missing.
- **ClickHouse** — only via Langfuse (not a direct dep).
- **SPIRE** — optional; workload identity for daemon-to-daemon mTLS.
- **OTLP collector** — optional; falls back to stdio logging.

Redis key patterns: `plugin-access:tenant:name`, `plugin-config:tenant:name`, `plugin-schema:name`, `mission:run:*`, `component:registry:*`, `audit:stream:<tenant>`.

## Secrets & Pre-commit

Pre-commit runs gitleaks + large-file + private-key checks (`.pre-commit-config.yaml`, `.gitleaks.toml` at repo root). `.env.local`, `.env.production`, `.env.staging` are gitignored and path-blocked — use `.env.example`. Don't allow-list findings; fix the content.

## Spec Workflow

This module drives design via `.spec-workflow/` at the repo root (requirements / design / tasks). Active specs touching this daemon currently include the FGA authZ migration, `prod-unimplemented-apis`, `prod-feature-wiring`, agent-auth FGA integration, and auth refactor. Completed specs are not retained as documents — shipped code and commit history are the source of truth.
