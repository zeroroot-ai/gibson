# GIBSON.md — Per-File Audit of `core/gibson/`

Code-only audit. Method: import tracing from the six `cmd/` binary entry points (`gibson`, `gibson-migrate`, `gen-fga-model-json`, `lowercase-tenant-owner`, `route-drift`, `fixtures-lint`), plus `core/sdk/cmd/*` and `core/ext-authz/cmd/*` as additional shipping binaries in core/*. No documentation, no comments-as-truth.

Date: 2026-04-27.

## TL;DR — high-confidence deletion candidates

The agent reachability analysis flagged these for deletion (zero callers from any binary entry point, no test failures expected):

| Path | LOC | Reason |
|---|---|---|
| `internal/orchestrator/recall.go` | 361 | `MemoryRecaller` is passed as `nil` stub at `mission_manager.go:783`; never instantiated. |
| `internal/orchestrator/reflect.go` | 586 | `ReflectionEngine` is passed as `nil` stub at `mission_manager.go:783`; never instantiated. |
| `internal/orchestrator/eval.go` | 227 | `WithEvalOptions` declared but never called from daemon. Wraps eval factory that no live path uses. |
| `internal/eval/` (entire package, 10 files) | ~1000 | Scaffolding-only. No daemon code calls `WithEvalOptions`, `GetEvalResults`, or `FinalizeEvalResults`. Imports only from `internal/orchestrator/eval.go` (also dead) and tests. |
| `internal/schema/` (entire package, 7 files) | — | Duplicates `core/sdk/schema/`. Gibson imports the SDK version, never the internal one. |
| `internal/memory/legacy_sqlite.go` | — | Pre-Redis SQLite memory backend. Zero imports. |
| `internal/database/legacy_sqlite.go` | — | Phase C SQLite vestige. Zero callers. |
| `internal/util/paths.go` | — | `ExpandPath`/`MustExpandPath` exported but zero callers in production. Config loader uses stdlib instead. |
| `internal/db/` | 0 .go | Directory exists but no Go files — only SQL migrations that aren't embedded from here. Superseded by `internal/datapool/` + `migrations/` at the repo root. |

## Medium-confidence deletion candidates (verify before cutting)

| Path | Why it might be dead | Check before deleting |
|---|---|---|
| `internal/finding/compat.go` | Backward-compat shim; no production callers found by grep. | Search for `UnmarshalFinding` callers across all branches. |
| `internal/checkpoint/sdk_conversion.go` | Exports `ToSDK`/`FromSDK` but no live callers. | Whether the SDK ever exposes checkpoint export to external clients. |
| `internal/mission/event_store.go` | Interface-only, no implementations in package; likely superseded by `event_store_conn.go`. | Confirm no external consumer (gibson or beyond) implements `EventStore`. |
| `internal/graphrag/query.go` | Minimal "deprecated stub" per code shape. | Whether anything still imports it. |
| `internal/observability/config_demo.go` | Build-tag `ignore` — examples-only. | Decide if examples are wanted at all in `internal/`. |
| `internal/database/credential_dao_postgres.go` | Phase C legacy; Phase D credential storage is via datapool. | Whether any RPC handler still hits this directly. |
| `internal/database/session_dao_redis.go` | Unclear if Phase D mission flow still uses it (vs datapool). | Grep for `SessionDAO` callers. |
| `internal/audit/loki_client.go`, `query.go`, `writer.go` | Postgres + Loki audit sinks are optional and only wired conditionally. | Decide whether to keep optional sinks at all (Redis stream is the always-on sink). |

## Stub RPCs (intentional `codes.Unimplemented`)

These are tracked stubs — decide for each: implement or delete.

| RPC | File | Notes |
|---|---|---|
| `RevokeUserSessions` | `internal/daemon/api/server_prod_handlers.go` | Session mgmt is in dashboard / Better Auth / Zitadel. |
| `GetUserProfile` | `internal/daemon/api/server_prod_handlers.go` | Same. |
| `UpdateUserProfile` | `internal/daemon/api/server_prod_handlers.go` | Same. |
| `GetUserSessions` | `internal/daemon/api/server_user.go` | Same. |

## Build-tag gated (NOT in default release binary)

| Path | Tag | Notes |
|---|---|---|
| `internal/daemon/sandboxed_setec_adapter.go` | `setec_integration` | Active when tag set. |
| `internal/daemon/sandboxed_setec_disabled.go` | (negation) | No-op stub when tag absent. **Both files always compile**, only one body is non-empty. |
| `internal/daemon/fixture_mock_llm_register.go` | `test_fixtures` | Mock LLM provider registration for E2E tests. |
| `internal/daemon/fixture_mock_llm_register_stub.go` | (negation) | No-op for production builds. |
| `internal/harness/callback_integration_test.go`, `callback_resolver_integration_test.go`, `e2e_tool_test.go`, `graphrag_bridge_integration_test.go` | `integration` | Integration tests, not run by default. |
| `internal/harness/integration_test.go`, `schema_gen_test.go`, `structured_test.go` | `*_disabled` | Disabled tests pending removed `JSONSchema` dependency. |

---

# Per-file tables

## `cmd/`, `pkg/`, `sdk/`, `tests/`, `scripts/`, `tools/`, `migrations/`, `build/`, top-level (~96 files)

| File | Purpose | Reachable from binary? | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `cmd/gibson/main.go` | Daemon entry point with signal handling and config loading | KEEP (gibson) | Yes | **KEEP** | Primary shipping binary; imports internal/daemon, internal/config, pkg/version |
| `cmd/gibson/main_test.go` | Tests for main.run() with factories | n/a | self | **TEST-ONLY** | |
| `cmd/gibson-migrate/main.go` | CLI: apply/query schema migrations across tenant DBs | KEEP (gibson-migrate) | n/a | **KEEP** | Imports runner, datapool/admin |
| `cmd/gibson-migrate/internal/runner/neo4j.go` | Neo4j migration runner | KEEP | yes | **KEEP** | |
| `cmd/gibson-migrate/internal/runner/postgres.go` | Postgres migration runner | KEEP | yes | **KEEP** | |
| `cmd/gibson-migrate/internal/runner/runner_test.go` | Tests for migration runner | n/a | self | **TEST-ONLY** | |
| `cmd/fixtures-lint/main.go` | CI lint: `GIBSON_TEST_FIXTURES_ENABLED` not set in prod | KEEP (fixtures-lint) | n/a | **KEEP** | Stdlib only |
| `cmd/gen-fga-model-json/main.go` | Convert OpenFGA DSL → JSON | KEEP (gen-fga-model-json) | n/a | **KEEP** | Stdlib + openfga; called by Helm sync |
| `cmd/lowercase-tenant-owner/main.go` | Hook: lowercase Tenant CR `spec.owner` for case-insensitive lookup | KEEP (lowercase-tenant-owner) | n/a | **KEEP** | k8s-only client |
| `cmd/route-drift/main.go` | CI: detect dashboard routes added without manifest entry | KEEP (route-drift) | n/a | **KEEP** | Stdlib only |
| `pkg/version/version.go` | Build-time version (Version/GitCommit/BuildTime ldflags) | KEEP | yes | **KEEP** | Imported by cmd/gibson/main.go |
| `pkg/version/version_test.go` | Tests for version.String/Info | n/a | self | **TEST-ONLY** | |
| `sdk/graphrag/constants.go` | Shared graphrag schema constants | Internal use | n/a | **KEEP** | Used by `internal/graphrag/` |
| `sdk/manifest/types.go` | AgentManifest/ToolManifest/PluginManifest types | Internal use | n/a | **KEEP** | Component manifest shared types |
| `sdk/manifest/errors.go` | Manifest validation errors | Internal use | n/a | **KEEP** | |
| `sdk/proto/types.proto` | Possibly vestigial proto file post-`decouple-sdk-from-tool-protos` spec | unknown | n/a | **UNCERTAIN** | Verify against `buf generate` output |
| `migrations/migrations.go` | Embeds `migrations/postgres` and `migrations/neo4j` | KEEP (gibson-migrate) | n/a | **KEEP** | |
| `migrations/postgres/{001,002,003,004}_*.{up,down}.sql` | Postgres migrations (credentials, provider_configs, missions, findings) | embedded | n/a | **CONFIG/DATA** | |
| `migrations/neo4j/001_initial_constraints.up.cypher` | Neo4j initial constraints | embedded | n/a | **CONFIG/DATA** | |
| `migrations/neo4j/.gitkeep` | Placeholder | n/a | n/a | **CONFIG/DATA** | |
| `tools/gibsoncheck/main.go` | go/vet-style analyzer for build guards | TOOL-ONLY | n/a | **TOOL-ONLY** | Used in CI, not shipped in daemon |
| `tools/gibsoncheck/checks/admin_pool_acquire.go` | Forbid manual admin pool construction | TOOL-ONLY | yes | **TOOL-ONLY** | |
| `tools/gibsoncheck/checks/forbidden_imports.go` | Forbid certain import paths | TOOL-ONLY | yes | **TOOL-ONLY** | |
| `tools/gibsoncheck/checks/forbid_raw_store_imports.go` | Forbid direct Redis client imports | TOOL-ONLY | yes | **TOOL-ONLY** | |
| `tools/gibsoncheck/checks/forbid_redis_client_construction.go` | Forbid `redis.NewClient()` (use datapool) | TOOL-ONLY | yes | **TOOL-ONLY** | |
| `tools/gibsoncheck/checks/forbid_redis_key_prefix.go` | Forbid Redis keys without tenant scope | TOOL-ONLY | yes | **TOOL-ONLY** | |
| `tools/gibsoncheck/checks/no_trust_localhost.go` | Forbid localhost trust in TLS configs | TOOL-ONLY | testdata only | **TOOL-ONLY** | |
| `tools/gibsoncheck/checks/tenant_from_context.go` | Enforce `TenantFromContext()` for tenant extraction | TOOL-ONLY | testdata only | **TOOL-ONLY** | |
| `tools/gibsoncheck/checks/*_test.go` (~6 files) | Check tests | n/a | self | **TEST-ONLY** | |
| `tools/gibsoncheck/checks/testdata/...` (~15 files) | Analyzer test fixtures | TOOL-ONLY | n/a | **CONFIG/DATA** | |
| `tests/e2e/audit_v4_foundation_test.go` | E2E: audit logging foundation | n/a | self | **TEST-ONLY** | |
| `tests/e2e/auth_test.go` | E2E: OIDC/SPIFFE/JWT-SVID flow | n/a | self | **TEST-ONLY** | |
| `tests/e2e/checkpoint_e2e_test.go` | E2E: mission pause/resume | n/a | self | **TEST-ONLY** | |
| `tests/e2e/dashboard_smoke_test.go` | E2E: dashboard health/status | n/a | self | **TEST-ONLY** | |
| `tests/e2e/dashboard_test.go` | E2E: dashboard routes/auth/forms | n/a | self | **TEST-ONLY** | |
| `tests/e2e/health_test.go` | E2E: `/healthz` `/readyz` | n/a | self | **TEST-ONLY** | |
| `tests/e2e/login_full_chain_test.go` | E2E: login chain | n/a | self | **TEST-ONLY** | |
| `tests/e2e/mission_finding_per_tenant_e2e_test.go` | E2E: per-tenant finding isolation | n/a | self | **TEST-ONLY** | |
| `tests/e2e/mission_run_test.go` | E2E: mission DAG | n/a | self | **TEST-ONLY** | |
| `tests/e2e/signup_full_chain_test.go` | E2E: signup chain | n/a | self | **TEST-ONLY** | |
| `tests/e2e/fixtures/agents/probe/*` (6 files) | Probe agent fixture | n/a | self | **TEST-ONLY** | |
| `tests/e2e/fixtures/providers/mock-llm/{provider.go,responses.yaml}` | Mock LLM fixture (env-gated) | n/a | n/a | **TEST-ONLY** | |
| `tests/e2e/fixtures/targets/test-target/*` (5 files) | Test target fixture | n/a | n/a | **TEST-ONLY** | |
| `tests/e2e/helpers/*.go` (~17 files) | E2E test helpers | n/a | self | **TEST-ONLY** | |
| `tests/e2e/manifests/dashboard-routes.yaml` | Route manifest for drift checker | n/a | n/a | **CONFIG/DATA** | |
| `tests/integration/checkpoint/{blob_store,redis,retention,thread}_test.go` | Integration: checkpoint subsystem | n/a | self | **TEST-ONLY** | |
| `tests/integration/compliance_*_test.go` (4 files) | Integration: compliance | n/a | self | **TEST-ONLY** | |
| `tests/integration/component_lifecycle_test.go` | Integration: component lifecycle | n/a | self | **TEST-ONLY** | |
| `tests/integration/finding_compliance_mappings_test.go` | Integration: finding↔compliance | n/a | self | **TEST-ONLY** | |
| `tests/integration/per_tenant_finding_idor_test.go` | Integration: tenant finding isolation | n/a | self | **TEST-ONLY** | |
| `tests/integration/per_tenant_mission_isolation_test.go` | Integration: tenant mission isolation | n/a | self | **TEST-ONLY** | |
| `tests/integration/provider_config_test.go` | Integration: provider config CRUD | n/a | self | **TEST-ONLY** | |
| `tests/integration/recover_running_missions_test.go` | Integration: mission recovery | n/a | self | **TEST-ONLY** | |
| `tests/integration/remote_tool_dispatch_test.go` | Integration: tool dispatch | n/a | self | **TEST-ONLY** | |
| `scripts/check-coverage.sh` | 90% coverage gate | n/a | n/a | **CONFIG/DATA** | |
| `scripts/check-no-redis-prefix.sh` | Lint: enforce tenant-prefixed Redis keys | n/a | n/a | **CONFIG/DATA** | |
| `scripts/check-no-tenant-id-column.sh` | Lint: forbid `tenant_id` columns (use per-tenant DBs) | n/a | n/a | **CONFIG/DATA** | |
| `scripts/create_verbose_package.sh` | Verbose-output build helper | n/a | n/a | **CONFIG/DATA** | |
| `scripts/verify-graph-intelligence.sh` | Verify intelligence wiring | n/a | n/a | **CONFIG/DATA** | |
| `build/Dockerfile` | Alternative build image | n/a | n/a | **CONFIG/DATA** | |
| `Dockerfile` | Production daemon image (CGO_ENABLED=0) | n/a | n/a | **CONFIG/DATA** | |
| `Makefile` | Build targets | n/a | n/a | **CONFIG/DATA** | |
| `buf.gen.yaml`, `buf.yaml` | Proto codegen config | n/a | n/a | **CONFIG/DATA** | |
| `.dockerignore`, `.gitignore`, `.golangci.yml` | Standard configs | n/a | n/a | **CONFIG/DATA** | |
| `.github/workflows/*.yml` (5 files) | CI: build, e2e, gibsoncheck, daemon, reusable | n/a | n/a | **CONFIG/DATA** | |
| `.github/dependabot.yml` | Dependabot | n/a | n/a | **CONFIG/DATA** | |
| `CODEOWNERS` | GitHub code owners | n/a | n/a | **CONFIG/DATA** | |
| `go.mod`, `go.sum` | Dependencies | n/a | n/a | **CONFIG/DATA** | |
| `LICENSE` | Apache 2.0 | n/a | n/a | **CONFIG/DATA** | |
| `gibson` | Compiled binary in tree (likely should be `.gitignore`d) | n/a | n/a | **DEAD** | Compiled artifact; should not be committed. |

## `internal/daemon/` (~143 files)

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/daemon/daemon.go` | Lifecycle: bootstrap → subsystems via errgroup | Yes | yes | **KEEP** | 1454 LOC; entry from cmd/gibson/main.go |
| `internal/daemon/grpc.go` | gRPC server lifecycle, mTLS, interceptor chain, service registration | Yes | yes | **KEEP** | 1877 LOC; registers all 5 services |
| `internal/daemon/health_subsystem.go` | HTTP health server lifecycle wrapper | Yes | n/a | **KEEP** | 47 LOC |
| `internal/daemon/health_state.go` | Shutdown state for `/readyz` | Yes | n/a | **KEEP** | |
| `internal/daemon/eventbus.go` | In-process pub/sub | Yes | yes | **KEEP** | 408 LOC |
| `internal/daemon/event_stream_redis.go` | Redis Streams bridge for events | Yes | n/a | **KEEP** | 308 LOC |
| `internal/daemon/eventbus_adapter.go` | Adapters: harness↔EventBus, orchestrator→EventBus | Yes | yes | **KEEP** | 581 LOC; 3 adapters |
| `internal/daemon/authz_init.go` | FGA vs noop authorizer init | Yes | yes | **KEEP** | |
| `internal/daemon/harness_init.go` | Harness factory wiring | Yes | yes | **KEEP** | |
| `internal/daemon/infrastructure.go` | Central infra bundle (DAG, finding store, LLM, harness, memory, GraphRAG, OTel) | Yes | yes | **KEEP** | 807 LOC |
| `internal/daemon/log_tailer.go` | Component log tailing (fsnotify) | Yes | yes | **KEEP** | 420 LOC |
| `internal/daemon/log_watcher.go` | Per-component file watcher | Yes | yes | **KEEP** | 347 LOC |
| `internal/daemon/log_buffer.go` | Ring buffer for logs | Yes | yes | **KEEP** | |
| `internal/daemon/catalog_refresher_init.go` | Setec tool catalog refresher bootstrap | Yes | n/a | **KEEP** | If `toolRunner.enabled` |
| `internal/daemon/catalog_refresher_subsystem.go` | Subsystem wrapper for refresher | Yes | yes | **KEEP** | |
| `internal/daemon/catalog_refresher.go` | `CatalogFanout`: launches `gibson-runner --list-tools`, syncs to registry | Yes | yes | **KEEP** | 474 LOC |
| `internal/daemon/mission_manager.go` | Mission lifecycle state machine | Yes | yes | **KEEP** | 1731 LOC |
| `internal/daemon/mission_lifecycle.go` | Mission state transitions | Yes | n/a | **KEEP** | |
| `internal/daemon/mission_harness_adapter.go` | Mission store ↔ harness MissionOperator adapter | Yes | n/a | **KEEP** | 401 LOC |
| `internal/daemon/list_missions.go` | Mission listing helper | Yes | n/a | **KEEP** | |
| `internal/daemon/agent_shutdown.go` | Agent notifier for graceful shutdown | Yes | n/a | **KEEP** | |
| `internal/daemon/checkpoint.go` | DaemonMissionCheckpointer | Yes | n/a | **KEEP** | |
| `internal/daemon/shutdown.go` | 5-phase shutdown coordinator | Yes | yes | **KEEP** | |
| `internal/daemon/shutdown_phases.go` | Phase implementations | Yes | n/a | **KEEP** | |
| `internal/daemon/shutdown_checkpoint.go` | Checkpoint phase | Yes | n/a | **KEEP** | |
| `internal/daemon/shutdown_types.go` | Shutdown types | Yes | n/a | **KEEP** | |
| `internal/daemon/component_lifecycle.go` | Component register/heartbeat/load-balance | Yes | yes (integration) | **KEEP** | |
| `internal/daemon/recover_missions.go` | Crash recovery for paused/stuck missions | Yes | n/a | **KEEP** | |
| `internal/daemon/startup_migration_check.go` | Neo4j schema migration validator at boot | Yes | yes | **KEEP** | |
| `internal/daemon/startup_migration_db.go` | Adds tenant_id column/constraints | Yes | n/a | **KEEP** | |
| `internal/daemon/credential_store.go` | Per-tenant credential store (Pool + KeyProvider) | Yes | yes | **KEEP** | |
| `internal/daemon/memory_factory.go` | 3-tier memory factory | Yes | yes | **KEEP** | 404 LOC |
| `internal/daemon/slot_manager.go` | LLM slot resolver (multi-provider fallback) | Yes | yes | **KEEP** | 465 LOC |
| `internal/daemon/options.go` | Daemon functional options | Yes | yes | **KEEP** | |
| `internal/daemon/types.go` | Daemon-local interface defs | Yes | n/a | **KEEP** | |
| `internal/daemon/interfaces.go` | Shutdown interfaces | Yes | n/a | **KEEP** | |
| `internal/daemon/network_policy_check.go` | K8s NetworkPolicy validator (Setec) | Yes | yes | **KEEP** | |
| `internal/daemon/redis_info.go` | Redis daemon registration | Yes | n/a | **KEEP** | |
| `internal/daemon/observability.go` | Observability setup | Yes | n/a | **KEEP** | |
| `internal/daemon/otel_adapter.go` | OTLP exporters | Yes | n/a | **KEEP** | |
| `internal/daemon/graph_bootstrap.go` | Neo4j schema init | Yes | yes | **KEEP** | |
| `internal/daemon/graph_event.go` | Graph event types | Yes | n/a | **KEEP** | |
| `internal/daemon/discovery_adapter.go` | DiscoveryProcessor → Neo4j adapter | Yes | n/a | **KEEP** | |
| `internal/daemon/graphrag_bridge.go` | GraphRAG store adapter | Yes | n/a | **KEEP** | 216 LOC |
| `internal/daemon/sandboxed_setec_adapter.go` | Setec microVM tool dispatch | Yes (with tag) | n/a | **KEEP-GATED** | Build tag `setec_integration` |
| `internal/daemon/sandboxed_setec_disabled.go` | No-op stub when tag absent | Yes | n/a | **KEEP** | |
| `internal/daemon/capabilitygrant_dispatcher.go` | Work queue dispatcher | Yes | n/a | **KEEP** | |
| `internal/daemon/harness_callback_authz.go` | Mission authz store ↔ harness authz | Yes | n/a | **KEEP** | |
| `internal/daemon/compliance_sink_adapter.go` | Compliance event sink | Yes | n/a | **KEEP** | |
| `internal/daemon/manifest_loader.go` | Manifest resolver helper | Yes | n/a | **KEEP** | |
| `internal/daemon/test_helpers.go` | Shared test fixtures | yes (test) | n/a | **KEEP** | 477 LOC |
| `internal/daemon/daemon_status_helper.go` | Daemon status query | Yes | n/a | **KEEP** | |
| `internal/daemon/pool_providerconfig.go` | Per-tenant provider config resolver | Yes | n/a | **KEEP** | |
| `internal/daemon/client/admin.go` | Admin gRPC client for Shutdown/Ping | Yes | n/a | **KEEP** | |
| `internal/daemon/middleware/deprecated_rpc.go` | `x-deprecated` response header interceptor | Yes | yes | **KEEP** | |
| `internal/daemon/api/server.go` | DaemonServer (DaemonService + DaemonAdminService dispatcher) | Yes | yes | **KEEP** | 2766 LOC |
| `internal/daemon/api/server_prod_handlers.go` | Stub handlers for not-yet-implemented admin RPCs | Yes | yes | **KEEP/STUB** | Contains the 4 stub RPCs flagged above |
| `internal/daemon/api/server_audit.go` | `ListAuditEvents` | Yes | n/a | **KEEP** | 260 LOC |
| `internal/daemon/api/server_budget.go` | LLM budget RPCs | Yes | n/a | **KEEP** | 350 LOC |
| `internal/daemon/api/server_capabilitygrant.go` | Capability grant RPC handlers | Yes | n/a | **KEEP** | 539 LOC |
| `internal/daemon/api/server_capabilitygrant_renew.go` | RenewCapabilityGrant | Yes | n/a | **KEEP** | |
| `internal/daemon/api/server_chat.go` | Chat/conversation RPCs (active) | Yes | n/a | **KEEP** | 257 LOC |
| `internal/daemon/api/server_entitlements.go` | Tenant quota/entitlement RPCs | Yes | n/a | **KEEP** | |
| `internal/daemon/api/server_entitlements_audit.go` | Entitlement audit trail | Yes | yes | **KEEP** | |
| `internal/daemon/api/server_alerts.go` | Alert RPCs | Yes | yes | **KEEP** | |
| `internal/daemon/api/server_model_access.go` | Model access RPCs (`GetSupportedModels`, etc.) | Yes | n/a | **KEEP** | |
| `internal/daemon/api/server_quota.go` | Quota RPCs | Yes | yes | **KEEP** | |
| `internal/daemon/api/server_usage.go` | Usage reporting RPC | Yes | n/a | **KEEP** | |
| `internal/daemon/api/server_user.go` | User profile stub | Yes | yes | **KEEP/STUB** | Contains `GetUserSessions` stub |
| `internal/daemon/api/server_providers.go` | `GetSupportedProviders` | Yes | yes | **KEEP** | |
| `internal/daemon/api/server_provider_config.go` | Provider credential CRUD RPCs | Yes | yes | **KEEP** | 580 LOC |
| `internal/daemon/api/server_provider_exec.go` | `ExecuteLLM`/`StreamLLM`/`GetProviderHealth` | Yes | yes | **KEEP** | 594 LOC |
| `internal/daemon/api/credentials.go` | Credential CRUD handler | Yes | yes | **KEEP** | |
| `internal/daemon/api/llm_config.go` | LLM config handler | Yes | yes | **KEEP** | 506 LOC |
| `internal/daemon/api/manifest_handler.go` | Manifest loading/caching | Yes | n/a | **KEEP** | |
| `internal/daemon/api/findings_export.go` | Export findings to JSON/CSV/SARIF/HTML | Yes | n/a | **KEEP** | |
| `internal/daemon/api/typed_value_helpers.go` | Proto TypedValue helpers | Yes | n/a | **KEEP** | |
| `internal/daemon/api/daemon_admin.pb.go` | Generated proto code | Yes | n/a | **CODEGEN** | 13208 LOC |
| `internal/daemon/api/daemon_admin_grpc.pb.go` | Generated gRPC stubs | Yes | n/a | **CODEGEN** | 2561 LOC |
| `internal/daemon/api/gibson/daemon/admin/v1/daemon_admin.proto` | Local admin proto source | Yes | n/a | **CODEGEN** | The only proto owned by this repo |
| `internal/daemon/api/proto_coverage_test.go` | Enforces no `Unimplemented` from prod handlers | n/a | self | **TEST-ONLY** | |
| `internal/daemon/api/*_test.go` (~16 files) | Per-handler unit tests | n/a | self | **TEST-ONLY** | |
| `internal/daemon/*_test.go` (~25 files) | Daemon unit/integration tests | n/a | self | **TEST-ONLY** | Includes mtls_handshake_test, subscribe_integration_test, etc. |
| `internal/daemon/fixture_mock_llm_register.go` | Mock LLM provider registration (build-tag) | Yes (with tag) | n/a | **KEEP-GATED** | Tag `test_fixtures` |
| `internal/daemon/fixture_mock_llm_register_stub.go` | No-op for production | Yes | n/a | **KEEP** | |

## `internal/harness/` (113 files)

| File | Purpose | Reachable (default) | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/harness/callback_manager.go` | Lifecycle for callback gRPC server + registry | Yes | yes | **KEEP** | |
| `internal/harness/callback_registry.go` | mission:agent → harness lookup | Yes | yes | **KEEP** | |
| `internal/harness/callback_server.go` | gRPC server hosting `HarnessCallbackService` | Yes | yes | **KEEP** | |
| `internal/harness/callback_service.go` | Service impl: ExecuteLLM, SubmitFinding, ExecuteTool, GetMemory, QueryPlugin, GetCredential | Yes | yes | **KEEP** | |
| `internal/harness/callback_service_streaming.go` | `CallToolProtoStream` bidirectional streaming | Yes | yes | **KEEP** | |
| `internal/harness/checkpoint_methods.go` | CheckpointAccess for agents | Yes | yes | **KEEP** | |
| `internal/harness/classifier.go` | CategoryClassifier for compliance tag normalization | Yes | yes | **KEEP** | |
| `internal/harness/compliance_action_table.go` | Method→action/effect mapping | Yes | yes | **KEEP** | |
| `internal/harness/compliance_agent_provider.go` | MetadataProvider precedence-3 (agent) | Yes | yes | **KEEP** | |
| `internal/harness/compliance_evaluator.go` | Catalog rule evaluator | Yes | yes | **KEEP** | |
| `internal/harness/compliance_health.go` | Compliance state → health probe | Yes | n/a | **KEEP** | |
| `internal/harness/compliance_metadata_provider.go` | 4-tier precedence interface | Yes | n/a | **KEEP** | |
| `internal/harness/compliance_metrics.go` | Prometheus metrics | Yes | yes | **KEEP** | |
| `internal/harness/compliance_middleware.go` | Wraps AgentHarness; emits compliance signals | Yes | yes | **KEEP** | |
| `internal/harness/compliance_middleware_methods.go` | Method delegation | Yes | n/a | **KEEP** | |
| `internal/harness/compliance_reserved_keys.go` | Closed vocab validator for reserved tag keys | Yes | n/a | **KEEP** | |
| `internal/harness/compliance_resource_resolver.go` | Resolves resource metadata from GraphRAG | Yes | yes | **KEEP** | |
| `internal/harness/compliance_rule_registry.go` | Catalog loader + tenant rule-id collision guard | Yes | yes | **KEEP** | |
| `internal/harness/compliance_signal_sink.go` | Packs signals into DiscoveryResult field 101 | Yes | n/a | **KEEP** | |
| `internal/harness/compliance_size_enforcer.go` | 1024 tags / 100 KiB cap | Yes | n/a | **KEEP** | |
| `internal/harness/compliance_tag_merger.go` | Precedence-aware tag merging | Yes | yes | **KEEP** | |
| `internal/harness/compliance_test_helpers.go` | Shared test fixtures | n/a | n/a | **KEEP** | Used by tests |
| `internal/harness/compliance_tool_provider.go` | MetadataProvider precedence-2 (tool) | Yes | n/a | **KEEP** | |
| `internal/harness/config.go` | HarnessConfig DI container | Yes | yes | **KEEP** | |
| `internal/harness/context.go` | MissionContext (mission/tenant/target metadata) | Yes | yes | **KEEP** | |
| `internal/harness/data_policy_enforcer.go` | Data residency on graph queries | Yes | yes | **KEEP** | |
| `internal/harness/descriptors.go` | Lightweight ToolDescriptor | Yes | n/a | **KEEP** | |
| `internal/harness/errors.go` | Harness error codes | Yes | n/a | **KEEP** | |
| `internal/harness/factory.go` | HarnessFactory function type | Yes | yes | **KEEP** | |
| `internal/harness/filter.go` | FindingFilter DSL | Yes | yes | **KEEP** | |
| `internal/harness/finding_store.go` | FindingStore interface | Yes | yes | **KEEP** | |
| `internal/harness/graphrag_adapters.go` | SDK ↔ internal GraphNode conversion | Yes | yes | **KEEP** | |
| `internal/harness/graphrag_bridge.go` | Async graph ingest bridge | Yes | yes | **KEEP** | |
| `internal/harness/graphrag_noop.go` | No-op GraphRAGBridge fallback | Yes | n/a | **KEEP** | |
| `internal/harness/graphrag_query_bridge.go` | Path C: agent queries for prior findings | Yes | yes | **KEEP** | |
| `internal/harness/harness_callback_authorize.go` | Authz metrics + signals for component calls | Yes | n/a | **KEEP** | |
| `internal/harness/harness.go` | EventLogger interface + core types | Yes | n/a | **KEEP** | |
| `internal/harness/implementation.go` | DefaultAgentHarness production impl | Yes | n/a | **KEEP** | Main impl |
| `internal/harness/limits.go` | MissionLister: cap nested mission spawn | Yes | yes | **KEEP** | |
| `internal/harness/metadata_injector.go` | Inject mission/tenant/target into Neo4j nodes | Yes | n/a | **KEEP** | |
| `internal/harness/metrics.go` | MetricsRecorder interface | Yes | n/a | **KEEP** | |
| `internal/harness/middleware/events.go` | Event emission middleware | Yes | yes | **KEEP** | |
| `internal/harness/middleware_harness.go` | Middleware-wrapped AgentHarness | Yes | n/a | **KEEP** | |
| `internal/harness/middleware/logging.go` | LoggingMiddleware (PII redaction) | Yes | n/a | **KEEP** | |
| `internal/harness/middleware/middleware.go` | Middleware composition | Yes | n/a | **KEEP** | |
| `internal/harness/middleware/streaming.go` | StreamSender interface | Yes | yes | **KEEP** | |
| `internal/harness/middleware/tracing.go` | OTel span middleware | Yes | n/a | **KEEP** | |
| `internal/harness/mission_context_provider.go` | Mission metadata loader | Yes | yes | **KEEP** | |
| `internal/harness/mission.go` | Sub-agent delegation methods | Yes | yes | **KEEP** | |
| `internal/harness/mission_operator_adapter.go` | Daemon MissionOperator → harness MissionClientIface | Yes | n/a | **KEEP** | |
| `internal/harness/options.go` | CompletionOption builder | Yes | yes | **KEEP** | |
| `internal/harness/queue.go` | QueueManager (Redis queue) | Yes | yes | **KEEP** | |
| `internal/harness/relationship_resolver.go` | Graph relationship builder | Yes | n/a | **KEEP** | |
| `internal/harness/sandboxed/executor.go` | Setec microVM tool executor | Yes | yes | **KEEP** | |
| `internal/harness/sandboxed/registry.go` | Sandboxed tool spec registry | Yes | n/a | **KEEP** | |
| `internal/harness/schema_convert.go` | SDK schema.JSON → callback proto | Yes | n/a | **KEEP** | |
| `internal/harness/schema_gen.go` | JSONSchema from Go reflection | Yes | n/a | **KEEP** | |
| `internal/harness/sdk_types.go` | SDK-compat types | Yes | n/a | **KEEP** | |
| `internal/harness/structured.go` | Structured-output tracing attrs | Yes | n/a | **KEEP** | |
| `internal/harness/taxonomy.go` | TaxonomyIntrospector (MITRE) | Yes | yes | **KEEP** | |
| `internal/harness/toolerr_defaults.go` | Tool-specific error recovery hints | Yes | n/a | **KEEP** | |
| `internal/harness/tool_validator.go` | Tool descriptor validator | Yes | yes | **KEEP** | |
| `internal/harness/callback_integration_test.go` | External agent callback integration | Yes (with tag) | self | **TEST-ONLY (gated)** | `integration` tag |
| `internal/harness/callback_resolver_integration_test.go` | Resolver pattern integration | Yes (with tag) | self | **TEST-ONLY (gated)** | `integration` tag |
| `internal/harness/e2e_tool_test.go` | E2E tool execution | Yes (with tag) | self | **TEST-ONLY (gated)** | `integration` tag |
| `internal/harness/graphrag_bridge_integration_test.go` | Neo4j bridge integration | Yes (with tag) | self | **TEST-ONLY (gated)** | `integration` tag |
| `internal/harness/integration_test.go` | Disabled (JSONSchema dep removed) | n/a | self | **TEST-ONLY (DISABLED)** | `integration_test_disabled` tag |
| `internal/harness/schema_gen_test.go` | Disabled | n/a | self | **TEST-ONLY (DISABLED)** | `schema_gen_test_disabled` tag |
| `internal/harness/structured_test.go` | Disabled | n/a | self | **TEST-ONLY (DISABLED)** | `structured_test_disabled` tag |
| `internal/harness/*_test.go` (~44 default-suite tests) | Unit tests | n/a | self | **TEST-ONLY** | |

## `internal/component/`, `internal/agent/`, `internal/tool/`, `internal/plugin/`, `internal/reconciler/` (~132 files)

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/component/adapter.go` | Unified discovery + delegation via gRPC | Yes | yes | **KEEP** | RegistryAdapter wired in daemon.Start |
| `internal/component/agent_access.go` | Tenant agent-execution authorization | Yes | n/a | **KEEP** | `NewRedisAgentAccessStore` |
| `internal/component/attributes.go` | Observability attribute keys | Yes | yes | **KEEP** | |
| `internal/component/auth_config.go` | gRPC auth config (bearer token) | Yes | n/a | **KEEP** | |
| `internal/component/build/build.go` | Build executor for external components | Yes | yes | **KEEP** | git clone → build → start |
| `internal/component/build/mock.go` | Mock BuildExecutor | Yes | yes | **KEEP** | |
| `internal/component/circuit_breaker.go` | Circuit breaker for gRPC pool | Yes | n/a | **KEEP** | 401 LOC, untested — risk |
| `internal/component/component_store.go` | Persistent component metadata interface | Yes | n/a | **KEEP** | |
| `internal/component/config.go` | Component config schema | Yes | yes | **KEEP** | |
| `internal/component/credentials.go` | Per-RPC bearer token creds | Yes | n/a | **KEEP** | |
| `internal/component/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/component/errors.go` | Sentinel errors | Yes | yes | **KEEP** | |
| `internal/component/finding_submitter.go` | Routes findings to per-tenant pool + Neo4j | Yes | n/a | **KEEP** | |
| `internal/component/git/git.go` | Git operations interface | Yes | yes | **KEEP** | |
| `internal/component/git/mock.go` | Mock GitOperations | Yes | yes | **KEEP** | |
| `internal/component/grpc_agent_client.go` | gRPC client implementing agent.Agent | Yes | n/a | **KEEP** | |
| `internal/component/grpc_plugin_client.go` | gRPC client implementing plugin.Plugin | Yes | n/a | **KEEP** | |
| `internal/component/grpc_pool.go` | Connection pool with circuit breaker | Yes | yes | **KEEP** | |
| `internal/component/grpc_tool_client.go` | gRPC client implementing tool.Tool | Yes | n/a | **KEEP** | |
| `internal/component/health.go` | Health status helpers | Yes | n/a | **KEEP** | |
| `internal/component/installer.go` | git clone, build, start, health check pipeline | Yes | n/a | **KEEP** | 2470 LOC, untested — high risk |
| `internal/component/interfaces_harness.go` | Narrow harness deps (GraphRAGQuerier, MemoryStore) | Yes | n/a | **KEEP** | |
| `internal/component/lifecycle.go` | Component lifecycle FSM | Yes | n/a | **KEEP** | |
| `internal/component/llm_adapter.go` | Component LLMCompleter → daemon LLMRegistry | Yes | yes | **KEEP** | |
| `internal/component/load_balancer.go` | RoundRobin/Random/LeastConnection (only RR currently configured) | Yes | yes | **KEEP** | |
| `internal/component/log_parser.go` | Parse error-level log entries | Yes | yes | **KEEP** | |
| `internal/component/log_rotator.go` | Log rotation interface | Yes | yes | **KEEP** | |
| `internal/component/log_writer.go` | Persistent log writer | Yes | yes | **KEEP** | |
| `internal/component/manifest.go` | component.yaml parser | Yes | yes | **KEEP** | |
| `internal/component/memory_resolver.go` | work_id → mission-scoped memory | Yes | yes | **KEEP** | |
| `internal/component/mission_context.go` | work_id → mission context | Yes | yes | **KEEP** | |
| `internal/component/plugin_access.go` | Tenant plugin authorization + encrypted config | Yes | yes | **KEEP** | If keyProvider configured |
| `internal/component/process.go` | Process state checks | Yes | yes | **KEEP** | |
| `internal/component/quota.go` | Per-tenant quota enforcement | Yes | yes | **KEEP** | |
| `internal/component/registry.go` | Redis registry, 30s TTL | Yes | yes | **KEEP** | Core bootstrap |
| `internal/component/resolver/capabilities.go` | Capability matching for component selection | Yes | n/a | **KEEP** | |
| `internal/component/resolver/config_merge.go` | Config merge for dependency composition | Yes | n/a | **KEEP** | |
| `internal/component/resolver/cycles.go` | Dependency cycle detection | Yes | n/a | **KEEP** | |
| `internal/component/resolver/manifest_loader.go` | Manifest loader for resolver | Yes | yes | **KEEP** | |
| `internal/component/resolver/prometheus.go` | Prometheus instant queries for scoring | Yes | yes | **KEEP** | |
| `internal/component/resolver/resolver.go` | Dependency resolver | Yes | yes | **KEEP** | |
| `internal/component/resolver/scoring.go` | Health/latency/load scoring | Yes | yes | **KEEP** | |
| `internal/component/resolver/tree.go` | Dependency tree | Yes | yes | **KEEP** | |
| `internal/component/resolver/validation.go` | Constraint validation | Yes | yes | **KEEP** | |
| `internal/component/resolver/version.go` | Version constraint matching | Yes | yes | **KEEP** | |
| `internal/component/service.go` | ComponentServiceServer gRPC handler | Yes | n/a | **KEEP** | |
| `internal/component/service_context.go` | GetCredential/SetContext handlers | Yes | n/a | **KEEP** | |
| `internal/component/service_delegation.go` | DelegateToAgent | Yes | n/a | **KEEP** | |
| `internal/component/service_findings.go` | GetFindings | Yes | n/a | **KEEP** | |
| `internal/component/service_graphrag.go` | QueryNodes (Neo4j) | Yes | n/a | **KEEP** | |
| `internal/component/service_llm.go` | ExecuteLLM/StreamLLM | Yes | n/a | **KEEP** | |
| `internal/component/service_memory_ext.go` | Memory{Get,Set,Delete,Search} | Yes | n/a | **KEEP** | |
| `internal/component/service_missions.go` | CreateMission/RunMission for sub-missions | Yes | n/a | **KEEP** | |
| `internal/component/service_tools.go` | Tool exec + queueing | Yes | n/a | **KEEP** | |
| `internal/component/status_checker.go` | Aggregate status (process + logs + health) | Yes | yes | **KEEP** | |
| `internal/component/status_types.go` | Status types | Yes | n/a | **KEEP** | |
| `internal/component/target_type.go` | Re-export `types.TargetType` | Yes | n/a | **KEEP** | |
| `internal/component/technique_type.go` | Re-export `types.TechniqueType` | Yes | n/a | **KEEP** | |
| `internal/component/tls.go` | TLS for gRPC component connections | Yes | n/a | **KEEP** | |
| `internal/component/tool_access.go` | Tenant tool-execution authorization | Yes | n/a | **KEEP** | |
| `internal/component/types.go` | Core types (ComponentKind, ComponentInfo, ServiceInfo) | Yes | yes | **KEEP** | |
| `internal/component/work_queue.go` | Redis Streams work queue (PollWork) | Yes | yes | **KEEP** | |
| `internal/component/*_test.go` (~25 files) | Unit/integration tests | n/a | self | **TEST-ONLY** | |
| `internal/agent/config.go` | Agent descriptor schema | Yes | n/a | **KEEP** | |
| `internal/agent/delegation.go` | AgentDelegator | Yes | yes | **KEEP** | |
| `internal/agent/grpc_client.go` | gRPC agent client | Yes | yes | **KEEP** | |
| `internal/agent/interface.go` | Agent interface | Yes | n/a | **KEEP** | |
| `internal/agent/proto_convert.go` | Task/Result ↔ proto | Yes | n/a | **KEEP** | Untested |
| `internal/agent/slot.go` | LLM slot reqs | Yes | yes | **KEEP** | |
| `internal/agent/stream_client.go` | Per-agent bidi stream | Yes | yes | **KEEP** | |
| `internal/agent/stream_manager.go` | Multi-agent stream manager | Yes | yes | **KEEP** | |
| `internal/agent/types.go` | Agent Task/Result types | Yes | yes | **KEEP** | |
| `internal/agent/*_test.go` (~7 files) | Unit tests | n/a | self | **TEST-ONLY** | |
| `internal/tool/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/tool/errors.go` | Sentinel errors | Yes | n/a | **KEEP** | Untested |
| `internal/tool/interface.go` | Tool interface | Yes | n/a | **KEEP** | |
| `internal/tool/types.go` | ToolDescriptor + metadata | Yes | n/a | **KEEP** | |
| `internal/plugin/interface.go` | Plugin interface | Yes | n/a | **KEEP** | |
| `internal/plugin/registry.go` | Plugin registry | Yes | n/a | **KEEP** | |
| `internal/plugin/types.go` | PluginConfig + metadata | Yes | n/a | **KEEP** | |
| `internal/plugin/*_test.go` (2 files) | Unit tests | n/a | self | **TEST-ONLY** | |
| `internal/reconciler/catalog_fanout.go` | 60s catalog reconciler (platform → tenant tuples) | Yes | n/a | **KEEP** | Untested |

## `internal/orchestrator/`, `internal/plan/`, `internal/prompt/`, `internal/eval/`, `internal/guardrail/` (~178 files)

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/orchestrator/orchestrator.go` | Observe → Think → Act loop | Yes | yes | **KEEP** | |
| `internal/orchestrator/observe.go` | Observer stage | Yes | yes | **KEEP** | |
| `internal/orchestrator/think.go` | Thinker stage (LLM decision) | Yes | yes | **KEEP** | |
| `internal/orchestrator/act.go` | Actor stage (dispatch + checkpoints + escalation) | Yes | yes | **KEEP** | |
| `internal/orchestrator/inventory_builder.go` | Component discovery for inventory | Yes | yes | **KEEP** | |
| `internal/orchestrator/inventory.go` | Inventory schema | Yes | yes | **KEEP** | |
| `internal/orchestrator/inventory_prompt.go` | Inventory prompt formatting | Yes | yes | **KEEP** | |
| `internal/orchestrator/inventory_validator.go` | Mission node ↔ component validator | Yes | yes | **KEEP** | |
| `internal/orchestrator/graph_intelligence.go` | Path A: graph-context enrichment | Yes | yes | **KEEP** | |
| `internal/orchestrator/neo4j_graph_querier.go` | Cypher executor | Yes | yes | **KEEP** | |
| `internal/orchestrator/graph_loader.go` | DiscoveryResult metadata prep | Yes | yes | **KEEP** | |
| `internal/orchestrator/graph_querier.go` | GraphClient + query builder | Yes | yes | **KEEP** | |
| `internal/orchestrator/decision.go` | Decision struct | Yes | yes | **KEEP** | |
| `internal/orchestrator/prompts.go` | LLM prompt assembler | Yes | yes | **KEEP** | |
| `internal/orchestrator/adapter.go` | Mission → orchestrator adapter | Yes | yes | **KEEP** | |
| `internal/orchestrator/query_parser.go` | LLM output → Decision | Yes | yes | **KEEP** | |
| `internal/orchestrator/error_conversion.go` | SDK errors → orchestrator codes | Yes | yes | **KEEP** | |
| `internal/orchestrator/escalation.go` | Retry/pause/notify/fail logic | Yes | yes | **KEEP** | |
| `internal/orchestrator/approval.go` | Approval workflow | Yes | yes | **KEEP** | ApprovalManager passed as nil stub |
| `internal/orchestrator/checkpoint.go` | Mission state ser/deser | Yes | yes | **KEEP** | |
| `internal/orchestrator/checkpoint_integration.go` | Checkpoint blob store integration | Yes | yes | **KEEP** | |
| `internal/orchestrator/recall.go` | Memory recall (passed as nil stub at mission_manager.go:783) | **NO** | yes | **DEAD** | 361 LOC; only test imports |
| `internal/orchestrator/reflect.go` | Reflection engine (passed as nil stub at mission_manager.go:783) | **NO** | yes | **DEAD** | 586 LOC; only test imports |
| `internal/orchestrator/restore.go` | Mission restore from checkpoint | Yes | yes | **KEEP** | |
| `internal/orchestrator/policy_source.go` | Mission policy source | Yes | yes | **KEEP** | |
| `internal/orchestrator/policy_checker.go` | Policy checker | Yes | yes | **KEEP** | |
| `internal/orchestrator/data_policy.go` | Ingestion/exfiltration policy | Yes | yes | **KEEP** | |
| `internal/orchestrator/embedding_cache.go` | Embedding cache | Yes | yes | **KEEP** | |
| `internal/orchestrator/result_merger.go` | Concurrent result merger | Yes | yes | **KEEP** | |
| `internal/orchestrator/eval.go` | EvalHarnessFactory wrapper | **NO** | yes | **DEAD** | 227 LOC; `WithEvalOptions` never called |
| `internal/orchestrator/config.go` | Orchestrator config | Yes | yes | **KEEP** | |
| `internal/orchestrator/factory.go` | Orchestrator factory | Yes | yes | **KEEP** | |
| `internal/orchestrator/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/orchestrator/*_test.go` (~43 files) | Unit tests | n/a | self | **TEST-ONLY** | Many tests for the dead recall/reflect — would also be removed |
| `internal/plan/executor.go` | Step executor with guardrail wrapping | Yes | yes | **KEEP** | |
| `internal/plan/plan.go` | Plan struct | Yes | yes | **KEEP** | |
| `internal/plan/step.go` | Step struct | Yes | yes | **KEEP** | |
| `internal/plan/step_executor.go` | Step exec + guardrail.Pipeline calls | Yes | yes | **KEEP** | |
| `internal/plan/generator.go` | LLM plan generator | Yes | yes | **KEEP** | |
| `internal/plan/llm_generator.go` | LLM integration | Yes | yes | **KEEP** | |
| `internal/plan/assessor.go` | Plan quality assessor | Yes | yes | **KEEP** | |
| `internal/plan/approval.go` | Approval state | Yes | yes | **KEEP** | |
| `internal/plan/result.go` | Plan result types | Yes | yes | **KEEP** | |
| `internal/plan/risk.go` | Risk calculation | Yes | yes | **KEEP** | |
| `internal/plan/proto_conversion.go` | Plan ↔ proto | Yes | yes | **KEEP** | |
| `internal/plan/mock_approval.go` | Mock ApprovalManager | n/a (test) | yes | **TEST-ONLY** | |
| `internal/plan/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/plan/*_test.go` (~9 files) | Unit + integration tests | n/a | self | **TEST-ONLY** | |
| `internal/prompt/prompt.go` | Prompt builder | Yes | yes | **KEEP** | |
| `internal/prompt/registry.go` | Template registry | Yes | yes | **KEEP** | |
| `internal/prompt/redis_store.go` | Redis-backed template store | Yes | yes | **KEEP** | |
| `internal/prompt/template.go` | Template struct | Yes | yes | **KEEP** | |
| `internal/prompt/variable.go` | Variable binding | Yes | yes | **KEEP** | |
| `internal/prompt/assembler.go` | Template renderer | Yes | yes | **KEEP** | |
| `internal/prompt/condition.go` | Conditional sections | Yes | yes | **KEEP** | |
| `internal/prompt/component.go` | Component refs | Yes | yes | **KEEP** | |
| `internal/prompt/funcs.go` | Built-in template funcs | Yes | yes | **KEEP** | |
| `internal/prompt/example.go` | Few-shot examples | Yes | yes | **KEEP** | |
| `internal/prompt/position.go` | Line/column tracking | Yes | yes | **KEEP** | |
| `internal/prompt/yaml.go` | YAML config parsing | Yes | yes | **KEEP** | |
| `internal/prompt/config.go` | Prompt config | Yes | yes | **KEEP** | |
| `internal/prompt/result.go` | Render result | Yes | yes | **KEEP** | |
| `internal/prompt/errors.go` | Error types | Yes | yes | **KEEP** | |
| `internal/prompt/relay.go` | gRPC/HTTP relay | Yes | yes | **KEEP** | |
| `internal/prompt/transformer.go` | Transformer plugin system | Yes | yes | **KEEP** | |
| `internal/prompt/transformers/context.go` | Context transformer | Yes | yes | **KEEP** | |
| `internal/prompt/transformers/scope.go` | Scope transformer | Yes | yes | **KEEP** | |
| `internal/prompt/builtin.go` | Hardcoded fallback prompts | Yes | yes | **KEEP** | |
| `internal/prompt/*_test.go` (~25 files) | Unit + integration tests | n/a | self | **TEST-ONLY** | |
| `internal/eval/factory.go` | EvalHarnessFactory | **NO** | yes | **DEAD** | Never instantiated from daemon |
| `internal/eval/harness_adapter.go` | Eval harness adapter | **NO** | yes | **DEAD** | |
| `internal/eval/collector.go` | EvalResultCollector | **NO** | yes | **DEAD** | `GetEvalResults` never called |
| `internal/eval/config.go` | EvalOptions | **NO** | yes | **DEAD** | |
| `internal/eval/summary.go` | EvalSummary | **NO** | yes | **DEAD** | `FinalizeEvalResults` never called |
| `internal/eval/options.go` | EvalOptions helpers | **NO** | yes | **DEAD** | |
| `internal/eval/events.go` | Eval event types | **NO** | yes | **DEAD** | |
| `internal/eval/export_jsonl.go` | JSONL export | **NO** | yes | **DEAD** | |
| `internal/eval/export_external.go` | Langfuse/OTel export | **NO** | yes | **DEAD** | |
| `internal/eval/doc.go` | Package doc | n/a | n/a | **DEAD** | |
| `internal/eval/*_test.go` (~10 files) | Unit tests | n/a | self | **TEST-ONLY (DEAD)** | All test the dead package |
| `internal/guardrail/guardrail.go` | Guardrail interface | Yes | yes | **KEEP** | |
| `internal/guardrail/pipeline.go` | GuardrailPipeline | Yes | yes | **KEEP** | Used by plan/step_executor.go |
| `internal/guardrail/types.go` | Guardrail types | Yes | yes | **KEEP** | |
| `internal/guardrail/errors.go` | Guardrail errors | Yes | yes | **KEEP** | |
| `internal/guardrail/builtin/config.go` | Built-in guardrail factory | Yes | yes | **KEEP** | |
| `internal/guardrail/builtin/content.go` | Content/jailbreak filter | Yes | yes | **KEEP** | |
| `internal/guardrail/builtin/pii.go` | PII detector | Yes | yes | **KEEP** | |
| `internal/guardrail/builtin/rate.go` | Rate guardrail | Yes | yes | **KEEP** | |
| `internal/guardrail/builtin/scope.go` | Scope guardrail | Yes | yes | **KEEP** | |
| `internal/guardrail/builtin/tool.go` | Tool invocation guardrail | Yes | yes | **KEEP** | |
| `internal/guardrail/*_test.go` (~9 files) | Unit tests | n/a | self | **TEST-ONLY** | |

## `internal/mission/`, `internal/checkpoint/`, `internal/missiondraft/`, `internal/finding/` (131 files)

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/mission/authz_state.go` | Run → user/tenant mapping for FGA callbacks | Yes | yes | **KEEP** | |
| `internal/mission/checkpoint_codec.go` | State ser/deser with checksum | Yes | yes | **KEEP** | |
| `internal/mission/checkpoint.go` | Checkpoint data types | Yes | yes | **KEEP** | |
| `internal/mission/checkpoint_manager.go` | Checkpoint capture | Yes | yes | **KEEP** | |
| `internal/mission/checkpoint_store.go` | Redis checkpoint store | Yes | yes | **KEEP** | `NewRedisCheckpointStore` |
| `internal/mission/client.go` | Mission client interface impl | Yes | yes | **KEEP** | |
| `internal/mission/client_run.go` | Status/result types | Yes | yes | **KEEP** | |
| `internal/mission/config.go` | WorkspaceConfig (legacy schema) | Yes | yes | **KEEP** | Legacy retained |
| `internal/mission/constraints.go` | Mission constraints | Yes | yes | **KEEP** | |
| `internal/mission/controller_checkpoint.go` | Checkpoint-aware resume | Yes | yes | **KEEP** | |
| `internal/mission/controller.go` | Mission FSM | Yes | yes | **KEEP** | |
| `internal/mission/data_policy.go` | Mission data policy | Yes | yes | **KEEP** | |
| `internal/mission/definition.go` | Mission definition schema | Yes | yes | **KEEP** | |
| `internal/mission/errors.go` | Error taxonomy | Yes | yes | **KEEP** | |
| `internal/mission/eval_adapter.go` | Mission EventEmitter → eval.MissionEventEmitter | Yes | n/a | **KEEP** | Minimal; satisfies eval (the dead package) — re-evaluate |
| `internal/mission/event_store.go` | EventStore interface | Yes | n/a | **UNCERTAIN** | No implementations in package; superseded by `event_store_conn.go`? |
| `internal/mission/event_store_conn.go` | Redis-backed event store | Yes | yes | **KEEP** | |
| `internal/mission/json_parser.go` | JSON definition parser | Yes | yes | **KEEP** | |
| `internal/mission/loader.go` | Definition loader | Yes | yes | **KEEP** | |
| `internal/mission/migrations.go` | Redis schema migrations | Yes | yes | **KEEP** | |
| `internal/mission/mission.go` | Core domain types | Yes | yes | **KEEP** | |
| `internal/mission/orchestrator_interface.go` | Orchestrator/EventBus/TargetStore interfaces | Yes | n/a | **KEEP** | |
| `internal/mission/parser.go` | YAML definition parser | Yes | yes | **KEEP** | Inline-YAML support removed |
| `internal/mission/resolver_adapter.go` | Mission ↔ component.resolver bridge | Yes | yes | **KEEP** | |
| `internal/mission/run.go` | MissionRun model | Yes | yes | **KEEP** | |
| `internal/mission/run_graphrag.go` | DiscoveryResult field-100 marker | Yes | n/a | **KEEP** | |
| `internal/mission/run_linker.go` | Run lineage manager | Yes | yes | **KEEP** | |
| `internal/mission/run_store.go` | MissionRunStore interface | Yes | n/a | **KEEP** | |
| `internal/mission/run_store_conn.go` | Redis run store | Yes | yes | **KEEP** | |
| `internal/mission/service.go` | MissionService | Yes | yes | **KEEP** | |
| `internal/mission/state.go` | MissionState tracker | Yes | yes | **KEEP** | |
| `internal/mission/store.go` | MissionStore interface | Yes | yes | **KEEP** | |
| `internal/mission/store_conn.go` | Redis mission store | Yes | yes | **KEEP** | |
| `internal/mission/test_helpers.go` | Mock fixtures | n/a | n/a | **TEST-ONLY** | |
| `internal/mission/validator.go` | Definition validator | Yes | yes | **KEEP** | |
| `internal/mission/*_test.go` (~26 files) | Unit/integration tests | n/a | self | **TEST-ONLY** | |
| `internal/checkpoint/approval.go` | Approval metadata | Yes | yes | **KEEP** | |
| `internal/checkpoint/approval_manager.go` | Approval requests/decisions | Yes | yes | **KEEP** | |
| `internal/checkpoint/blob_store.go` | Redis/S3 blob backend factory | Yes | yes | **KEEP** | |
| `internal/checkpoint/branch.go` | Branch metadata | Yes | yes | **KEEP** | |
| `internal/checkpoint/checkpoint.go` | Core types | Yes | yes | **KEEP** | |
| `internal/checkpoint/compression.go` | zstd compression | Yes | yes | **KEEP** | |
| `internal/checkpoint/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/checkpoint/encryption.go` | AES-256-GCM | Yes | yes | **KEEP** | |
| `internal/checkpoint/errors.go` | Errors | Yes | yes | **KEEP** | |
| `internal/checkpoint/events.go` | Lifecycle events | Yes | yes | **KEEP** | |
| `internal/checkpoint/metrics.go` | Prometheus metrics | Yes | yes | **KEEP** | |
| `internal/checkpoint/observability.go` | Logging + tracing | Yes | yes | **KEEP** | |
| `internal/checkpoint/policy.go` | Retention policy | Yes | yes | **KEEP** | |
| `internal/checkpoint/restore.go` | Decompress/decrypt/validate pipeline | Yes | yes | **KEEP** | |
| `internal/checkpoint/sdk_conversion.go` | ToSDK/FromSDK | Yes | n/a | **UNCERTAIN** | No callers found |
| `internal/checkpoint/serializer.go` | marshal → compress → encrypt → store | Yes | yes | **KEEP** | |
| `internal/checkpoint/state.go` | Thread state | Yes | yes | **KEEP** | |
| `internal/checkpoint/store.go` | CheckpointStore interface | Yes | yes | **KEEP** | |
| `internal/checkpoint/threaded_checkpointer.go` | Concurrent capture for parallel missions | Yes | yes | **KEEP** | |
| `internal/checkpoint/thread.go` | Thread metadata | Yes | yes | **KEEP** | |
| `internal/checkpoint/thread_manager.go` | Thread lifecycle | Yes | yes | **KEEP** | |
| `internal/checkpoint/keyprovider/interface.go` | KeyProvider interface | Yes | n/a | **KEEP** | |
| `internal/checkpoint/keyprovider/kubernetes.go` | K8s Secret KeyProvider | Yes | yes | **KEEP** | |
| `internal/checkpoint/*_test.go` (~12 files) | Unit tests | n/a | self | **TEST-ONLY** | |
| `internal/missiondraft/store.go` | 30-day Redis YAML draft store | Yes | yes | **KEEP** | |
| `internal/missiondraft/store_test.go` | Tests | n/a | self | **TEST-ONLY** | |
| `internal/finding/analytics.go` | Severity counts, trends, recurrence | Yes | yes | **KEEP** | |
| `internal/finding/classifier.go` | Classifier interface + factory | Yes | yes | **KEEP** | |
| `internal/finding/compat.go` | Backward-compat shim | Yes | n/a | **UNCERTAIN** | `UnmarshalFinding` no callers found |
| `internal/finding/compliance_update.go` | Compliance status updater | Yes | yes | **KEEP** | |
| `internal/finding/composite_classifier.go` | Heuristic + LLM composite | Yes | yes | **KEEP** | |
| `internal/finding/deduplication.go` | Dedup engine | Yes | yes | **KEEP** | |
| `internal/finding/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/finding/errors.go` | Errors | Yes | yes | **KEEP** | |
| `internal/finding/evidence.go` | Evidence model | Yes | yes | **KEEP** | |
| `internal/finding/heuristic_classifier.go` | Regex classifier | Yes | yes | **KEEP** | |
| `internal/finding/llm_classifier.go` | LLM classifier | Yes | yes | **KEEP** | |
| `internal/finding/mitre.go` | MITRE ATT&CK | Yes | yes | **KEEP** | |
| `internal/finding/store.go` | FindingStore interface | Yes | yes | **KEEP** | |
| `internal/finding/store_conn.go` | Per-tenant store | Yes | yes | **KEEP** | |
| `internal/finding/types.go` | EnhancedFinding | Yes | yes | **KEEP** | |
| `internal/finding/vector_classifier.go` | Embedding similarity classifier | Yes | yes | **KEEP** | |
| `internal/finding/export/csv_exporter.go` | CSV | Yes | yes | **KEEP** | |
| `internal/finding/export/exporter.go` | FindingExporter interface | Yes | yes | **KEEP** | |
| `internal/finding/export/html_exporter.go` | HTML | Yes | yes | **KEEP** | |
| `internal/finding/export/json_exporter.go` | JSON | Yes | yes | **KEEP** | |
| `internal/finding/export/markdown_exporter.go` | Markdown | Yes | yes | **KEEP** | |
| `internal/finding/export/sarif_exporter.go` | SARIF 2.1.0 | Yes | yes | **KEEP** | |
| `internal/finding/*_test.go` and `internal/finding/export/*_test.go` (~14 files) | Tests | n/a | self | **TEST-ONLY** | |

## `internal/llm/`, `internal/memory/`, `internal/providerconfig/`, `internal/ratelimit/`, `internal/budget/` (~118 files)

### `internal/llm/`

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/llm/config.go` | Provider type enum + `SupportedProviderTypes` factory routing table | Yes | yes | **KEEP** | Single source of truth for active providers |
| `internal/llm/convert.go` | langchaingo message schema conversion | Yes | n/a | **KEEP** | Used by providers for marshaling |
| `internal/llm/credential_schema.go` | Provider credential form metadata | Yes | n/a | **KEEP** | Consumed by `GetSupportedProviders` RPC for dashboard form rendering |
| `internal/llm/embedding.go` | Embedding request/response + `EmbeddingProvider` interface | Yes | yes | **KEEP** | |
| `internal/llm/errors.go` | LLM error vocabulary (InvalidInputError, UnsupportedModelError, etc.) | Yes | yes | **KEEP** | |
| `internal/llm/json_extract.go` | Structured-output extraction with JSONSchema validation | Yes | yes | **KEEP** | Tool-use support |
| `internal/llm/modelgate/filter.go` | Request filtering for authz + token budget | Yes | n/a | **KEEP** | Called by slot manager during dispatch |
| `internal/llm/options.go` | Functional options builder | Yes | yes | **KEEP** | |
| `internal/llm/pricing.go` | Token-to-USD cost table per provider (with SelfHosted/Unknown flags) | Yes | yes | **KEEP** | Used by budget enforcer |
| `internal/llm/provider.go` | `LLMProvider` interface | Yes | yes | **KEEP** | |
| `internal/llm/ratelimit.go` | In-process token-per-minute throttle (separate from `internal/ratelimit/` Redis tenant limiter) | Yes | yes | **KEEP** | Per-provider local throttle |
| `internal/llm/registry.go` | `LLMRegistry` + `DefaultLLMRegistry` runtime lookup | Yes | yes | **KEEP** | |
| `internal/llm/slot.go` | Slot resolver (model name → provider + model) | Yes | yes | **KEEP** | |
| `internal/llm/tools.go` | Tool-use metadata structs (ToolName, Parameters, ToolCall) | Yes | yes | **KEEP** | |
| `internal/llm/tracker.go` | UsageTracker for token accounting (mission/agent/slot scopes) | Yes | yes | **KEEP** | |
| `internal/llm/types.go` | Message role enum + Message struct | Yes | yes | **KEEP** | |
| `internal/llm/*_test.go` (15 files) | Unit + integration tests | n/a | self | **TEST-ONLY** | Includes `config_test.go` (factory drift detection), `pricing_coverage_test.go` (forces pricing on every provider) |

### `internal/llm/providers/`

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/llm/providers/anthropic.go` | Anthropic Claude provider | Yes | yes | **KEEP** | |
| `internal/llm/providers/anthropic_direct.go` | Direct Anthropic client wrapper | Yes | yes | **KEEP** | Lower-level impl |
| `internal/llm/providers/bedrock.go` | AWS Bedrock provider | Yes | yes | **KEEP** | |
| `internal/llm/providers/cloudflare.go` | Cloudflare Workers AI provider | Yes | yes | **KEEP** | |
| `internal/llm/providers/cohere.go` | Cohere API provider | Yes | yes | **KEEP** | |
| `internal/llm/providers/convert.go` | Proto ↔ internal message conversion | Yes | n/a | **KEEP** | |
| `internal/llm/providers/credentials.go` | Credential extraction/validation from ProviderConfig | Yes | yes | **KEEP** | |
| `internal/llm/providers/descriptors.go` | ProviderDescriptor registry (metadata for `GetSupportedProviders`) | Yes | yes | **KEEP** | Descriptor completeness enforced by test |
| `internal/llm/providers/factory.go` | `NewProvider` factory switch | Yes | yes | **KEEP** | Coverage test prevents unrouted enum values |
| `internal/llm/providers/google.go` | Google Gemini provider | Yes | n/a | **KEEP** | No dedicated test, but factory-routed and descriptor-tested |
| `internal/llm/providers/huggingface.go` | HuggingFace Inference API provider | Yes | yes | **KEEP** | |
| `internal/llm/providers/llamafile.go` | Llamafile self-hosted provider | Yes | yes | **KEEP** | |
| `internal/llm/providers/mistral.go` | Mistral API provider | Yes | yes | **KEEP** | |
| `internal/llm/providers/mock.go` | Mock provider | Yes | n/a | **KEEP** | Test fixture used outside this package |
| `internal/llm/providers/ollama.go` | Ollama self-hosted provider | Yes | n/a | **KEEP** | |
| `internal/llm/providers/openai.go` | OpenAI provider | Yes | yes | **KEEP** | |
| `internal/llm/providers/ssrf.go` | SSRF protection on provider URLs | Yes | yes | **KEEP** | Validates endpoints against blocklist |
| `internal/llm/providers/*_test.go` (~14 files) | Unit + integration tests | n/a | self | **TEST-ONLY** | |

### `internal/memory/`

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/memory/config.go` | Memory system config (embedder + vector store) | Yes | yes | **KEEP** | Wired in daemon bootstrap |
| `internal/memory/errors.go` | Memory error types | Yes | yes | **KEEP** | |
| `internal/memory/legacy_sqlite.go` | Pre-Redis SQLite memory backend | **NO** | n/a | **DEAD** | Confirmed by first audit pass: zero callers, not wired in bootstrap. Re-audit flagged UNCERTAIN — verify with grep before deleting, but evidence is consistent. |
| `internal/memory/longterm.go` | Longterm tier (vector store + embedder + chunking) | Yes | yes | **KEEP** | |
| `internal/memory/manager.go` | MemoryManager facade (working + mission + longterm) | Yes | yes | **KEEP** | |
| `internal/memory/mission.go` | Mission-tier memory interface | Yes | n/a | **KEEP** | |
| `internal/memory/mission_redis.go` | Redis-backed mission memory | Yes | yes | **KEEP** | |
| `internal/memory/mission_redis_conn.go` | Redis connection helper | Yes | n/a | **KEEP** | |
| `internal/memory/store.go` | `MemoryStore` interface | Yes | n/a | **KEEP** | |
| `internal/memory/tokens.go` | Token counting | Yes | n/a | **KEEP** | |
| `internal/memory/traced_manager.go` | OTel-traced manager wrapper | Yes | yes | **KEEP** | |
| `internal/memory/types.go` | MemoryEntry / MemoryEvent | Yes | yes | **KEEP** | |
| `internal/memory/working.go` | Working (in-process) tier | Yes | yes | **KEEP** | |
| `internal/memory/embedder/embedder.go` | Embedder interface | Yes | n/a | **KEEP** | |
| `internal/memory/embedder/errors.go` | Embedder errors | Yes | n/a | **KEEP** | |
| `internal/memory/embedder/factory.go` | `CreateEmbedder` factory (native only) | Yes | yes | **KEEP** | |
| `internal/memory/embedder/mock.go` | Mock embedder | Yes | n/a | **KEEP** | |
| `internal/memory/embedder/native.go` | Native all-MiniLM-L6-v2 (GoMLX) | Yes | yes | **KEEP** | Only implemented embedder |
| `internal/memory/vector/embedded.go` | In-memory vector store (brute-force search) | Yes | yes | **KEEP** | Fallback backend |
| `internal/memory/vector/errors.go` | Vector store errors | Yes | n/a | **KEEP** | |
| `internal/memory/vector/factory.go` | `NewVectorStore` factory (embedded vs redis) | Yes | yes | **KEEP** | |
| `internal/memory/vector/mock.go` | Mock vector store | Yes | n/a | **KEEP** | |
| `internal/memory/vector/redis.go` | Redis-backed ANN via Redis Search | Yes | yes | **KEEP** | Production backend |
| `internal/memory/vector/store.go` | `VectorStore` interface | Yes | n/a | **KEEP** | |
| `internal/memory/vector/types.go` | Query/result types | Yes | n/a | **KEEP** | |
| `internal/memory/*_test.go` (~14 files including subpackages) | Unit + integration + benchmarks | n/a | self | **TEST-ONLY** | Includes build-tag-gated `embedder/factory_test.go` and `embedder/native_test.go` (tag `embedder_tests`; download large model files) |

### `internal/providerconfig/`

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/providerconfig/store.go` | `ProviderConfigStore` interface + in-memory impl | Yes | yes | **KEEP** | |
| `internal/providerconfig/store_postgres.go` | Postgres-backed encrypted credential store (Spec 25) | Yes | yes | **KEEP** | Production storage; envelope-encrypted |
| `internal/providerconfig/types.go` | ProviderConfigRecord + envelope types | Yes | n/a | **KEEP** | |
| `internal/providerconfig/*_test.go` (3 files) | Unit + Postgres integration tests | n/a | self | **TEST-ONLY** | |

### `internal/ratelimit/`

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/ratelimit/tenant_limiter.go` | Redis sliding-window per-tenant rate limiter | Yes | yes | **KEEP** | Wired in `daemon/grpc.go` + `api/server_provider_exec.go`; ExecuteLLM/StreamLLM=1000/min, TestProvider=10/min |
| `internal/ratelimit/tenant_limiter_test.go` | Tests | n/a | self | **TEST-ONLY** | |

### `internal/budget/`

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/budget/enforcer.go` | Multi-scope (user/team/tenant) cost + token budget enforcer | Yes | yes | **KEEP** | Daemon registers `budgetEnforcer`; `api/server_provider_exec.go` checks before dispatch |
| `internal/budget/rollover.go` | Reset/rollover cycles (monthly/weekly/custom) | Yes | n/a | **KEEP** | Used by enforcer |
| `internal/budget/types.go` | BudgetLimit / BudgetUsage / BudgetCycle | Yes | n/a | **KEEP** | |
| `internal/budget/enforcer_test.go` | Tests | n/a | self | **TEST-ONLY** | |

**Findings for this bucket:**
- All 10 LLM provider backends are factory-registered and tested (Anthropic, Bedrock, Cloudflare, Cohere, Google/Gemini, HuggingFace, Llamafile, Mistral, Ollama, OpenAI). `descriptors_test.go` and `factory_coverage_test.go` enforce that every `SupportedProviderTypes` enum value has both a descriptor and a factory case.
- Spec-25 removed providers (`ernie`, `local`, `maritaca`, `watsonx`) confirmed absent — no source files, no enum entries, no factory cases, no pricing entries.
- One DEAD file: `internal/memory/legacy_sqlite.go` (pre-Redis SQLite backend; not wired in bootstrap; first audit pass found zero callers).
- `google.go` is the only provider without its own `*_test.go`, but is exercised via factory + descriptor coverage tests. Worth adding a dedicated unit test before tagging.

## `internal/graphrag/`, `internal/neo4j/`, `internal/manifest/`, `internal/crypto/`, `internal/api/` (~119 files)

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/graphrag/doc.go` | Package doc | n/a | n/a | **KEEP** | |
| `internal/graphrag/attributes.go` | Node/relationship attribute types | Yes | yes | **KEEP** | |
| `internal/graphrag/types.go` | GraphStore interface | Yes | yes | **KEEP** | |
| `internal/graphrag/errors.go` | Errors | Yes | n/a | **KEEP** | |
| `internal/graphrag/config.go` | Config | Yes | n/a | **KEEP** | |
| `internal/graphrag/store.go` | In-memory GraphStore (MockStore) | Yes | yes | **KEEP** | |
| `internal/graphrag/traced_store.go` | OTel-wrapped GraphStore | Yes | n/a | **KEEP** | |
| `internal/graphrag/provider.go` | Provider interface + factory dispatch | Yes | n/a | **KEEP** | |
| `internal/graphrag/query.go` | Deprecated stub | Yes | n/a | **UNCERTAIN** | Likely orphan |
| `internal/graphrag/merge.go` | Node/rel dedup utilities | Yes | n/a | **KEEP** | |
| `internal/graphrag/processor.go` | Top-level processor wrapper | Yes | yes | **KEEP** | |
| `internal/graphrag/mission_graph_manager.go` | Mission subgraph lifecycle | Yes | yes | **KEEP** | |
| `internal/graphrag/loader/loader.go` | Persists DiscoveryResult (field 100) → Neo4j | Yes | yes | **KEEP** | |
| `internal/graphrag/processor/discovery_processor.go` | Core processor | Yes | yes | **KEEP** | |
| `internal/graphrag/intelligence/service.go` | 5 cross-mission queries; cache + circuit breaker | Yes | yes | **KEEP** | |
| `internal/graphrag/intelligence/grpc.go` | IntelligenceService gRPC adapter | Yes | yes | **KEEP** | |
| `internal/graphrag/intelligence/recurring.go` | GetRecurringVulnerabilities | Yes | n/a | **KEEP** | |
| `internal/graphrag/intelligence/remediation.go` | GetRemediationMetrics | Yes | n/a | **KEEP** | |
| `internal/graphrag/intelligence/risk.go` | GetAssetRiskScore | Yes | yes | **KEEP** | |
| `internal/graphrag/intelligence/patterns.go` | GetAttackPatterns | Yes | n/a | **KEEP** | |
| `internal/graphrag/intelligence/similarity.go` | GetSimilarTargets | Yes | n/a | **KEEP** | |
| `internal/graphrag/intelligence/metrics.go` | MTTR / success-rate calcs | Yes | n/a | **KEEP** | |
| `internal/graphrag/intelligence/cache.go` | TTL query cache | Yes | n/a | **KEEP** | |
| `internal/graphrag/schema/migration.go` | Namespace + constraint creation | Yes | n/a | **KEEP** | |
| `internal/graphrag/schema/mission.go` | Mission schema types | Yes | n/a | **KEEP** | |
| `internal/graphrag/schema/execution.go` | Execution schema types | Yes | yes | **KEEP** | |
| `internal/graphrag/schema/doc.go` | Package doc | n/a | n/a | **KEEP** | |
| `internal/graphrag/queries/mission.go` | Per-target queries (Path A) | Yes | yes | **KEEP** | |
| `internal/graphrag/queries/execution.go` | Execution queries | Yes | yes | **KEEP** | |
| `internal/graphrag/queries/doc.go` | Package doc | n/a | n/a | **KEEP** | |
| `internal/graphrag/graph/client.go` | Neo4j driver init | Yes | n/a | **KEEP** | |
| `internal/graphrag/graph/neo4j.go` | Driver wrapper | Yes | yes | **KEEP** | |
| `internal/graphrag/graph/mock.go` | Mock driver (test helper) | Yes | n/a | **KEEP** | |
| `internal/graphrag/graph/errors.go` | Neo4j errors | Yes | n/a | **KEEP** | |
| `internal/graphrag/graph/doc.go` | Package doc | n/a | n/a | **KEEP** | |
| `internal/graphrag/engine/cypher.go` | Cypher builder + executor | Yes | yes | **KEEP** | |
| `internal/graphrag/engine/doc.go` | Package doc | n/a | n/a | **KEEP** | |
| `internal/graphrag/cypher/predicates.go` | WHERE-clause builders | Yes | yes | **KEEP** | |
| `internal/graphrag/provider/factory.go` | Provider factory (local/cloud/hybrid) | Yes | n/a | **KEEP** | |
| `internal/graphrag/provider/local.go` | LocalProvider | Yes | yes | **KEEP** | |
| `internal/graphrag/provider/cloud.go` | CloudProvider (Neo4j) | Yes | n/a | **KEEP** | |
| `internal/graphrag/provider/hybrid.go` | Hybrid fallback | Yes | n/a | **KEEP** | |
| `internal/graphrag/*_test.go` (~30 files) | Unit/integration tests | n/a | self | **TEST-ONLY** | |
| `internal/neo4j/browser_links.go` | Neo4j Browser debug link generator | Yes | yes | **KEEP** | |
| `internal/neo4j/browser_links_test.go` | Tests | n/a | self | **TEST-ONLY** | |
| `internal/manifest/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/manifest/builder.go` | ManifestBuilder for capability manifests | Yes | yes | **KEEP** | |
| `internal/manifest/types.go` | Manifest types | Yes | n/a | **KEEP** | |
| `internal/manifest/interfaces.go` | Builder/Invalidator/Registry interfaces | Yes | n/a | **KEEP** | |
| `internal/manifest/signer.go` | HMAC signer | Yes | yes | **KEEP** | |
| `internal/manifest/watch.go` | Redis-backed manifest invalidation watcher | Yes | yes | **KEEP** | |
| `internal/manifest/invalidator.go` | ManifestInvalidator | Yes | yes | **KEEP** | |
| `internal/manifest/notifier.go` | Pubsub publisher | Yes | yes | **KEEP** | |
| `internal/manifest/version_store.go` | Version tracker | Yes | yes | **KEEP** | |
| `internal/manifest/staleness.go` | Staleness detector | Yes | yes | **KEEP** | |
| `internal/manifest/fga_observer.go` | Watches FGA changes | Yes | n/a | **KEEP** | |
| `internal/manifest/registry_observer.go` | Watches component registry | Yes | n/a | **KEEP** | |
| `internal/manifest/wellknown.go` | Well-known metadata | Yes | yes | **KEEP** | |
| `internal/manifest/*_test.go` (~10 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/crypto/interface.go` | Encryptor + KeyProvider interfaces | Yes | n/a | **KEEP** | |
| `internal/crypto/encryption.go` | AES-256-GCM | Yes | yes | **KEEP** | |
| `internal/crypto/keyprovider.go` | Generic helper (caching, refresh) | Yes | n/a | **KEEP** | |
| `internal/crypto/providers/factory.go` | Provider factory | Yes | yes | **KEEP** | |
| `internal/crypto/providers/kubernetes.go` | K8s Secret backend | Yes | yes | **KEEP** | |
| `internal/crypto/providers/vault.go` | Vault backend | Yes | yes | **KEEP** | |
| `internal/crypto/providers/aws.go` | AWS Secrets Manager backend | Yes | yes | **KEEP** | |
| `internal/crypto/providers/azure.go` | Azure Key Vault backend | Yes | yes | **KEEP** | |
| `internal/crypto/providers/gcp.go` | GCP Secret Manager backend | Yes | yes | **KEEP** | |
| `internal/crypto/*_test.go` (~9 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/api/discovery/server.go` | DiscoveryService gRPC | Yes | n/a | **KEEP** | |
| `internal/api/discovery/describe.go` | DescribeComponent RPC | Yes | n/a | **KEEP** | |
| `internal/api/discovery/list.go` | ListComponents RPC | Yes | n/a | **KEEP** | |
| `internal/api/discovery/validate.go` | ValidateConfig RPC | Yes | n/a | **KEEP** | |

## `internal/observability/`, `internal/audit/`, `internal/datapool/`, `internal/admin/`, `internal/db/`, `internal/state/`, `internal/database/`, `internal/config/`, `internal/events/` (~163 files)

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/observability/attributes.go` | Span attribute helpers | Yes | yes | **KEEP** | |
| `internal/observability/attributes_authz.go` | Authz span attrs | Yes | yes | **KEEP** | |
| `internal/observability/config.go` | TracingConfig, LangfuseConfig, MetricsConfig | Yes | yes | **KEEP** | |
| `internal/observability/config_demo.go` | Build-tag `ignore` example configs | **NO** | n/a | **DEAD** | Build-tag-gated examples; never imported |
| `internal/observability/context.go` | Span context extraction | Yes | yes | **KEEP** | |
| `internal/observability/correlation.go` | Neo4j ↔ Langfuse correlation IDs | Yes | yes | **KEEP** | |
| `internal/observability/cost.go` | LLM cost tracker | Yes | yes | **KEEP** | |
| `internal/observability/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/observability/errors.go` | Observability errors | Yes | yes | **KEEP** | |
| `internal/observability/event_types.go` | EventType enum | Yes | n/a | **KEEP** | |
| `internal/observability/genai.go` | OTel GenAI semantic convention attrs | Yes | yes | **KEEP** | |
| `internal/observability/health.go` | HealthMonitor + HealthChecker | Yes | yes | **KEEP** | |
| `internal/observability/logging.go` | slog wrapper | Yes | yes | **KEEP** | |
| `internal/observability/metrics.go` | Prometheus/OTLP init | Yes | yes | **KEEP** | |
| `internal/observability/otel_decision_log_adapter.go` | DecisionLogWriter → OTel events | Yes | yes | **KEEP** | |
| `internal/observability/otel_factory.go` | Tracer/meter/logger providers | Yes | n/a | **KEEP** | |
| `internal/observability/otel_metrics.go` | OTelMetricsRecorder | Yes | n/a | **KEEP** | |
| `internal/observability/otel_mission_tracer.go` | Mission DAG span hierarchy | Yes | yes | **KEEP** | |
| `internal/observability/otel_spans.go` | MissionSpan / AgentSpan wrappers | Yes | yes | **KEEP** | |
| `internal/observability/otel_tracing_middleware.go` | LLM/tool call tracing | Yes | yes | **KEEP** | |
| `internal/observability/redaction.go` | PII redaction | Yes | yes | **KEEP** | |
| `internal/observability/span_enrich.go` | EnrichSpan | Yes | yes | **KEEP** | |
| `internal/observability/span_enrich_metric.go` | Unauthenticated-span counter | Yes | n/a | **KEEP** | |
| `internal/observability/trace_types.go` | MessageLog/RequestMetadata/DecisionLog | Yes | n/a | **KEEP** | |
| `internal/observability/tracing.go` | TracingOption builders | Yes | yes | **KEEP** | |
| `internal/observability/*_test.go` (~28 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/audit/logger.go` | Redis-stream audit writer | Yes | yes | **KEEP** | Always-on sink |
| `internal/audit/loki_client.go` | Loki query client | Optional | yes | **UNCERTAIN** | Used in `server_audit.go` if Loki configured |
| `internal/audit/migrations.go` | Postgres audit schema migrations | Yes | n/a | **KEEP** | |
| `internal/audit/model_resolved.go` | Model resolution audit events | Yes | n/a | **KEEP** | |
| `internal/audit/query.go` | Audit event query (Postgres + Loki) | Optional | n/a | **UNCERTAIN** | Same conditional |
| `internal/audit/writer.go` | Postgres audit writer | Optional | yes | **UNCERTAIN** | Wired only if dashboardDB configured |
| `internal/audit/*_test.go` (3 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/datapool/admin/admin_pool.go` | AdminPool for platform-operator | Yes | yes | **KEEP** | |
| `internal/datapool/admin/enumerate.go` | Tenant enumeration | Yes | n/a | **KEEP** | |
| `internal/datapool/admin/metrics.go` | AdminPool metrics | Yes | n/a | **KEEP** | |
| `internal/datapool/conn_credentials.go` | Conn.GetCredential + TenantCredentialProvider | Yes | n/a | **KEEP** | |
| `internal/datapool/conn.go` | Conn interface | Yes | yes | **KEEP** | |
| `internal/datapool/conn_ops_finding.go` | Findings ops on tenant Neo4j | Yes | n/a | **KEEP** | |
| `internal/datapool/conn_ops_memory.go` | Vectordb access for embeddings | Yes | n/a | **KEEP** | |
| `internal/datapool/conn_ops_mission.go` | Mission Redis store | Yes | n/a | **KEEP** | |
| `internal/datapool/conn_release.go` | Connection cleanup | Yes | n/a | **KEEP** | |
| `internal/datapool/envelope/aeswrap.go` | RFC 3394 AES Key Wrap | Yes | yes | **KEEP** | |
| `internal/datapool/envelope/envelope.go` | Envelope encryption | Yes | yes | **KEEP** | |
| `internal/datapool/errors.go` | Provisioning state errors | Yes | n/a | **KEEP** | |
| `internal/datapool/evictor.go` | Connection eviction | Yes | yes | **KEEP** | |
| `internal/datapool/grpc_errors.go` | datapool errors → gRPC codes | Yes | yes | **KEEP** | |
| `internal/datapool/kek.go` | Per-tenant KEK derivation | Yes | yes | **KEEP** | |
| `internal/datapool/metrics/alerts.go` | Datapool alerts | Yes | n/a | **KEEP** | |
| `internal/datapool/metrics/metrics.go` | Datapool metrics | Yes | yes | **KEEP** | |
| `internal/datapool/neo4j_per_tenant.go` | Per-tenant Neo4j conn mgmt | Yes | yes | **KEEP** | |
| `internal/datapool/pgxpool_per_tenant.go` | Per-tenant Postgres pool | Yes | yes | **KEEP** | |
| `internal/datapool/pool.go` | Pool interface | Yes | n/a | **KEEP** | |
| `internal/datapool/pool_impl.go` | Pool implementation | Yes | yes | **KEEP** | |
| `internal/datapool/provisioning_check.go` | Provisioning gate | Yes | yes | **KEEP** | |
| `internal/datapool/redis_per_tenant.go` | Per-tenant Redis | Yes | yes | **KEEP** | |
| `internal/datapool/vectordb/qdrant.go` | Qdrant client | Yes | yes | **KEEP** | |
| `internal/datapool/vectordb/vectordb.go` | VectorDB interface | Yes | n/a | **KEEP** | |
| `internal/datapool/vector_per_tenant.go` | Per-tenant vector connection | Yes | yes | **KEEP** | |
| `internal/datapool/*_test.go` (~15 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/admin/doc.go` | Package marker (real code in `datapool/admin/`) | Yes | n/a | **KEEP** | |
| `internal/db/` (no .go files) | SQL migrations only | n/a | n/a | **DEAD** | Empty Go-wise; superseded |
| `internal/state/client.go` | Unified Redis client wrapper | Yes | yes | **KEEP** | |
| `internal/state/config.go` | Redis config | Yes | yes | **KEEP** | |
| `internal/state/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/state/errors.go` | State errors | Yes | yes | **KEEP** | |
| `internal/state/indexes_definitions.go` | RediSearch index defs | Yes | n/a | **KEEP** | |
| `internal/state/indexes.go` | IndexManager | Yes | yes | **KEEP** | |
| `internal/state/json.go` | JSON helpers | Yes | n/a | **KEEP** | |
| `internal/state/scripts.go` | Lua scripts | Yes | yes | **KEEP** | |
| `internal/state/search.go` | Redis Search query builder | Yes | n/a | **KEEP** | |
| `internal/state/streams.go` | Streams wrapper | Yes | yes | **KEEP** | |
| `internal/state/tenant_names.go` | Tenant name ↔ ID | Yes | n/a | **KEEP** | |
| `internal/state/tenant_store.go` | TenantScopedStore | Yes | yes | **KEEP** | |
| `internal/state/*_test.go` (~9 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/database/credential_dao_postgres.go` | Phase C Postgres credential DAO | Optional | yes | **UNCERTAIN** | Phase D moved to datapool |
| `internal/database/interfaces.go` | DAO interfaces | Yes | n/a | **KEEP** | |
| `internal/database/legacy_sqlite.go` | SQLite wrapper (Phase C) | **NO** | n/a | **DEAD** | |
| `internal/database/metrics.go` | x-tenant decrypt metric | Yes | n/a | **KEEP** | |
| `internal/database/session_dao_redis.go` | Agent session store | Optional | yes | **UNCERTAIN** | Unclear if Phase D mission flow uses |
| `internal/database/target_dao_redis.go` | Target persistence | Yes | yes | **KEEP** | Wired in daemon.go:441 |
| `internal/config/activity_logging.go` | ActivityLoggingConfig | Yes | yes | **KEEP** | |
| `internal/config/aliases.go` | env alias mapping | Yes | yes | **KEEP** | |
| `internal/config/authconfig.go` | AuthConfig + SPIFFE/OAuth/HMAC | Yes | n/a | **KEEP** | |
| `internal/config/callback.go` | CallbackConfig | Yes | yes | **KEEP** | |
| `internal/config/checkpoint.go` | CheckpointConfig | Yes | yes | **KEEP** | |
| `internal/config/config.go` | Root Config | Yes | yes | **KEEP** | |
| `internal/config/defaults.go` | Default factories | Yes | n/a | **KEEP** | |
| `internal/config/helpers.go` | ExpandEnv (`${VAR:-default}`) | Yes | n/a | **KEEP** | |
| `internal/config/loader.go` | YAML parse + env subst + validate | Yes | n/a | **KEEP** | |
| `internal/config/metrics.go` | MetricsConfig | Yes | n/a | **KEEP** | |
| `internal/config/mode.go` | DaemonMode enum | Yes | yes | **KEEP** | |
| `internal/config/sandbox.go` | SandboxConfig (Setec) | Yes | n/a | **KEEP** | |
| `internal/config/validator.go` | Config validator orchestration | Yes | yes | **KEEP** | |
| `internal/config/*_test.go` (~11 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/events/bus.go` | DefaultEventBus | Yes | yes | **KEEP** | |
| `internal/events/doc.go` | Package doc | Yes | n/a | **KEEP** | |
| `internal/events/types.go` | EventType enum | Yes | n/a | **KEEP** | |

## `internal/authz/`, `internal/apikeys/`, `internal/capabilitygrant/`, `internal/impersonation/`, `internal/onboarding/`, `internal/types/`, `internal/schema/`, `internal/contextkeys/`, `internal/util/`, `internal/testing/` (~85 files)

Note: `internal/identity/` and `internal/extauthz/` directories do NOT exist as packages. Identity is now in `core/sdk/auth`; ext_authz client lifecycle lives directly in `internal/daemon/extauthz_subsystem.go`.

| File | Purpose | Reachable | Tests | Verdict | Notes |
|---|---|---|---|---|---|
| `internal/authz/interface.go` | Authorizer interface | Yes | n/a | **KEEP** | |
| `internal/authz/client.go` | OpenFGA HTTP client wrapper | Yes | n/a | **KEEP** | |
| `internal/authz/client_methods.go` | Check/Write/Delete/ListObjects helpers | Yes | n/a | **KEEP** | |
| `internal/authz/config_resolver.go` | FGA config resolution | Yes | yes | **KEEP** | |
| `internal/authz/errors.go` | Authz errors | Yes | n/a | **KEEP** | |
| `internal/authz/envelope_hmac.go` | HMAC envelope signer | Yes | yes | **KEEP** | Used for work envelopes |
| `internal/authz/noop.go` | Noop authorizer | Yes | yes | **KEEP** | |
| `internal/authz/backfill.go` | FGA tuple backfill (feature flag `fga_resource_objects_v2`) | Yes | yes | **KEEP** | |
| `internal/authz/*_test.go` (~7 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/apikeys/hash.go` | gsk_-prefix key hashing | Yes | n/a | **KEEP** | |
| `internal/apikeys/store.go` | Redis API key store | Yes | n/a | **KEEP** | |
| `internal/capabilitygrant/service.go` | Capability grant service interface | Yes | n/a | **KEEP** | |
| `internal/capabilitygrant/mint.go` | High-level mint entry | Yes | yes | **KEEP** | |
| `internal/capabilitygrant/jwt.go` | Agent JWT codec (HS256) | Yes | yes | **KEEP** | |
| `internal/capabilitygrant/fga_bridge.go` | FGA tuple bridge | Yes | yes | **KEEP** | |
| `internal/capabilitygrant/fga_bridge_manifest.go` | Manifest-aware FGA grants | Yes | yes | **KEEP** | |
| `internal/capabilitygrant/store.go` | Redis grant store | Yes | n/a | **KEEP** | |
| `internal/capabilitygrant/migrations.go` | Schema migrations | Yes | n/a | **KEEP** | |
| `internal/capabilitygrant/*_test.go` (~4 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/impersonation/issuer.go` | Tenant impersonation token issuer | Yes | yes | **KEEP** | |
| `internal/impersonation/issuer_test.go` | Tests | n/a | self | **TEST-ONLY** | |
| `internal/onboarding/store.go` | 30-day onboarding state | Yes | yes | **KEEP** | |
| `internal/onboarding/store_test.go` | Tests | n/a | self | **TEST-ONLY** | |
| `internal/types/credential.go` | Credential + CredentialType | Yes | yes | **KEEP** | Different shape from `sdk/types`; not duplicate |
| `internal/types/errors.go` | GibsonError | Yes | yes | **KEEP** | |
| `internal/types/health.go` | HealthStatus enum | Yes | yes | **KEEP** | |
| `internal/types/ids.go` | Typed string IDs (Mission/Target/Agent/Task/Result/Finding) | Yes | yes | **KEEP** | 228+ imports |
| `internal/types/status.go` | TargetStatus/MissionStatus/FindingStatus/CredentialStatus enums | Yes | n/a | **KEEP** | |
| `internal/types/structured.go` | ResponseFormat + StructuredOutputOptions | Yes | yes | **KEEP** | |
| `internal/types/target.go` | Domain Target + TargetType enum | Yes | yes | **KEEP** | Different from `sdk/types/target.go`'s `TargetInfo`; not duplicate |
| `internal/types/target_technique.go` | MITRE technique mapping | Yes | n/a | **KEEP** | |
| `internal/types/*_test.go` (~7 files) | Tests | n/a | self | **TEST-ONLY** | |
| `internal/schema/schema.go` | JSONSchema struct + validators | **NO** | yes | **DEAD** | Duplicates `core/sdk/schema/schema.go`; gibson imports SDK version |
| `internal/schema/validate.go` | Validation logic | **NO** | n/a | **DEAD** | |
| `internal/schema/validation.go` | Constraint checkers | **NO** | yes | **DEAD** | |
| `internal/schema/*_test.go` (~4 files) | Tests for dead package | n/a | self | **TEST-ONLY (DEAD)** | |
| `internal/contextkeys/keys.go` | AgentRunID/TenantID/ActorID/CallerChain/MissionRunID/AuthzDecision | Yes | yes | **KEEP** | Cycle-breaking keys |
| `internal/contextkeys/keys_test.go` | Tests | n/a | self | **TEST-ONLY** | |
| `internal/util/paths.go` | ExpandPath/MustExpandPath | **NO** | yes | **DEAD** | Zero production callers |
| `internal/util/paths_test.go` | Tests for dead helpers | n/a | self | **TEST-ONLY (DEAD)** | |
| `internal/testing/doc.go` | Package doc | n/a | n/a | **TEST-ONLY** | |
| `internal/testing/tenant_helper.go` | Tenant test fixture | n/a (only test imports) | yes | **TEST-ONLY** | |
| `internal/testing/tenant_helper_test.go` | Tests | n/a | self | **TEST-ONLY** | |

---

# Verdict tally

Approximate counts across all 10 buckets (some test files counted by directory):

| Verdict | Files |
|---|---|
| **KEEP** (live in default binary) | ~720 |
| **TEST-ONLY** | ~430 |
| **CODEGEN** | 3 (one .proto + two generated .pb.go files) |
| **CONFIG/DATA** | ~40 |
| **TOOL-ONLY** (gibsoncheck analyzer) | ~12 |
| **DEAD** (high-confidence delete candidates) | ~25 source files (~1k LOC orchestrator/recall+reflect+eval, ~1k LOC eval pkg, schema pkg, legacy_sqlite ×2, util/paths, db/) |
| **UNCERTAIN** (verify before cutting) | ~10 |
| **STUB** | 4 RPC handlers in `server_prod_handlers.go` + `server_user.go` |
| **KEEP-GATED** (build tag) | 2 production files + 7 test files |

High-signal deletion candidates are concentrated in:
- The orchestrator/eval scaffolding (`internal/orchestrator/{recall,reflect,eval}.go` + entire `internal/eval/` package, ~2,200 LOC).
- Three legacy artifacts: `legacy_sqlite.go` in `internal/memory/` and `internal/database/`, the `internal/schema/` duplicate package, `internal/util/paths.go`, and the empty `internal/db/`.
- The committed `gibson` binary at the repo root.

A small follow-up: `internal/llm/providers/google.go` is the only provider without its own unit test (covered transitively by factory + descriptor tests). Worth a dedicated test before tagging.
