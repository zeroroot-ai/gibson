# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Gibson is a Kubernetes-native AI agent framework for autonomous security operations. This is the core daemon/orchestrator — a Go binary providing a gRPC server (:50002), CLI, DAG-based mission orchestration, multi-provider LLM abstraction, and a component registry for agents, tools, and plugins.

## Build & Test

```bash
make bin                    # Build → bin/gibson (CGO_ENABLED=0, ldflags inject Version/GitCommit/BuildTime)
make test                   # Unit tests
make test-race              # Tests with race detection
make test-coverage          # Coverage with 90% threshold (scripts/check-coverage.sh enforces)
make lint                   # golangci-lint
make check                  # fmt + vet + lint + test-race (pre-commit gate)
make proto                  # protoc: api/proto/*.proto → api/gen/proto/ (needs protoc-gen-go, protoc-gen-go-grpc)
make proto-clean            # Remove generated .pb.go files
make tidy                   # go mod tidy
make install                # Build + install to GOPATH/bin

# Single test
go test -v -run TestSpecificName ./internal/path/...
```

**Test file conventions**: `*_test.go` (unit), `*_integration_test.go` (testcontainers for Redis/Neo4j), `*_e2e_test.go` (end-to-end). Uses `testify/assert`. Mocks live near implementations (e.g., `internal/component/build/mock.go`).

## Architecture

### Command Mode System (`cmd/gibson/mode/`)

CLI commands are classified into execution modes in `mode/registry.go`:
- **Standalone** (`version`, `config`, `plugin init`): No daemon connection needed
- **Daemon** (`daemon start/stop/status`): Manages daemon lifecycle
- **Client** (default): Connects to running daemon via gRPC

`root.go` uses the mode to determine initialization strategy — standalone commands skip daemon setup entirely, client commands discover the daemon via Redis registration, daemon commands start the full server.

### Daemon Startup Pipeline (`internal/daemon/`)

`daemon.New()` constructs; `daemon.Start()` performs phased initialization:
1. **State Client** (Redis) — always required
2. **Component Registry/Lifecycle** — etcd-backed, 30-second TTL heartbeat
3. **Mission services** — Store, RunStore, Installer, Service
4. **Infrastructure** — OTel, GraphRAG (Neo4j), LLM registry, findings
5. **Harness Factory** with middleware chain
6. **gRPC Server** — registers DaemonService + ComponentService, optional auth interceptors
7. **Event Bus** + Redis daemon registration for client discovery
8. **Health server** — `/healthz` (liveness) + `/readyz` (readiness) on :8080

### Graceful Shutdown

`SignalHandler` runs 4 phases on SIGTERM: PreShutdown (stop accepting missions) → Checkpoint (save active missions to Redis via `DaemonMissionCheckpointer`) → Wait (drain in-flight ops) → Terminate. This enables pause/resume across pod restarts.

### Multi-Tenancy

Components are scoped to tenants. The **system tenant** (`_system`) hosts platform plugins available to all tenants. `ComponentService` extracts tenant from auth context via `auth.TenantFromContext()`. Registry has four discovery methods: `Discover`, `DiscoverAll`, `DiscoverTenantOnly`, `DiscoverSystemOnly`.

### Component Lifecycle (`internal/component/`)

Components (agents/tools/plugins) register via `RegisterComponent` RPC. The registry uses **30-second TTL** — components must heartbeat to stay alive. Work dispatch uses long-polling via `PollWork`. Results return via `SubmitResult`. A `LoadBalancer` wraps the registry with strategies: RoundRobin, Random, LeastConnection.

### Harness (`internal/harness/`)

The `AgentHarness` interface is the single API agents use for all capabilities. It's built by `HarnessFactory` with dependency injection of three proxy interfaces:
- **LLMCompleter**: Routes completions to the correct provider per mission slot
- **FindingSubmitter**: Persists findings through the pipeline
- **PluginAccessStore**: Manages encrypted per-tenant plugin configuration

Unconnected proxies return `codes.Unimplemented` until wired. The harness wraps with `OTelHarnessMiddleware` for automatic tracing.

### Memory System (`internal/memory/`)

Three-tier, coordinated by `MemoryManager`:
- **Working** — ephemeral, in-process (per-execution)
- **Mission** — Redis-backed (persistent within mission lifetime)
- **LongTerm** — vector store (semantic search over discoveries)

`MemoryFactory` creates managers with pre-initialized Redis + vector store. `TracedMemoryManager` wraps all access with OTel spans.

### LLM Abstraction (`internal/llm/`)

Agents declare **LLM slots** with requirements (context window, features like `tool_use`/`vision`/`json_mode`). The daemon resolves slots to actual providers (Anthropic, OpenAI, Gemini, Ollama) at runtime. Agents never hardcode a specific model.

### Discovery Processing (`internal/graphrag/processor/`)

Tool workers perform entity extraction tool-side (in the SDK serve loop) and populate proto field 100 (`DiscoveryResult`) on their response before returning results. The daemon does **not** run any extraction logic itself. When it receives a tool response with field 100 populated, `DiscoveryProcessor` delegates to `GraphLoader.LoadDiscovery()` to persist the proto entities (hosts, ports, services, endpoints, domains, findings, etc.) into Neo4j with mission scoping and provenance tracking.

### Authentication (`internal/auth/`)

Three auth paths: (1) `gsk_`-prefixed tokens → APIKeyAuthenticator (Redis-backed, for external components/CLI); (2) OIDC JWTs → OIDCValidator (for users via Keycloak); (3) K8s ServiceAccount tokens → K8sValidator (auto-detected, for in-cluster components). Auth modes: `enterprise`, `saas`, `dev`. In enterprise/saas mode, K8s SA auth is auto-detected (no config flag needed). RBAC maps claims to roles/permissions.

### Authorization (`internal/authz/`) — Phase 0 foundation (authz-01)

**Feature flag**: `authz.enabled: false` by default — no existing code path changes until spec authz-02.

The `authz` package implements a stable `Authorizer` interface backed by OpenFGA (Google Zanzibar-based ReBAC). The daemon startup pipeline includes an Authorization Service phase that runs AFTER Redis State Client and BEFORE Component Registry.

Key types:
- `Authorizer` interface — `Check`, `BatchCheck`, `Write`, `Delete`, `ListObjects`, `ListUsers`, `StoreID`, `ModelID`, `Close`
- `noopAuthorizer` — always returns `allowed=true`; injected when `authz.enabled=false` or FGA is unreachable in dev mode
- `fgaAuthorizer` — wraps `github.com/openfga/go-sdk v0.7.5` HTTP client with OTel spans
- `ResolveStoreAndModelIDs` — 3-source fallback: config file → ConfigMap `gibson/gibson-fga-config` → env vars `GIBSON_AUTHZ_FGA_STORE_ID` / `GIBSON_AUTHZ_FGA_MODEL_ID`

Startup behavior:
- `authz.enabled=false` → noopAuthorizer, log INFO
- `authz.enabled=true`, FGA reachable → fgaAuthorizer, log INFO
- `authz.enabled=true`, FGA unreachable, `require_ready=true` → fail daemon startup (production)
- `authz.enabled=true`, FGA unreachable, `require_ready=false` → noopAuthorizer, log WARN (dev mode)

FGA HTTP endpoint is `gibson-fga:8080` (not gRPC port 8081). The `/readyz` probe includes an FGA check with 10s TTL caching when `authz.enabled=true`.

Authorization model (`internal/authz/model.fga`): schema 1.1 with types `user`, `tenant`, `component`, `system_tenant`. Provisioned by the `gibson-fga-init` Kubernetes Job on every helm install/upgrade.

CLI: `gibson authz check <user> <relation> <object>`, `gibson authz write <user> <relation> <object>`, `gibson authz model-info`.

Makefile: `make check-authz` (unit), `make check-authz INTEGRATION=1` (requires Docker for testcontainers).

### Encryption (`internal/crypto/`)

AES-256-GCM for plugin config encryption. `KeyProvider` interface with backends: Kubernetes Secret, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager. Factory pattern selects provider from config.

### Context Keys (`internal/contextkeys/`)

Shared context keys avoid circular imports: `AgentRunID`, `ToolExecutionID`, `MissionRunID`, `AgentName`, `MissionID`. Set during mission execution, consumed by harness, GraphRAG, and observability packages.

## Proto / Generated Code

Gibson owns one proto file: the daemon gRPC API surface.

**Proto source:** `internal/daemon/api/gibson/daemon/v1/daemon.proto` (package `gibson.daemon.v1`)
**Generated Go:** `internal/daemon/api/daemon.pb.go` + `daemon_grpc.pb.go`

**Buf configuration** — this repo has its own `buf.yaml` and `buf.gen.yaml` at the repo root:
```bash
buf lint                   # Lint daemon proto (STANDARD ruleset, zero exceptions)
buf generate               # Regenerate daemon Go code
```

**SDK proto imports** — Gibson imports generated Go types from the SDK. Package mapping:

| SDK Package | Import Path | Alias | Types |
|-------------|------------|-------|-------|
| `gibson.agent.v1` | `github.com/zero-day-ai/sdk/api/gen/gibson/agent/v1` | `agentpb` | AgentService client, GetDescriptorResponse, ExecuteRequest/Response |
| `gibson.tool.v1` | `github.com/zero-day-ai/sdk/api/gen/gibson/tool/v1` | `toolpb` | ToolService client, ExecuteRequest/Response |
| `gibson.plugin.v1` | `github.com/zero-day-ai/sdk/api/gen/gibson/plugin/v1` | `pluginpb` | PluginService client, InitializeRequest/Response |
| `gibson.harness.v1` | `github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1` | `harnesspb` | HarnessCallbackService, LLM/memory/validation types |
| `gibson.types.v1` | `github.com/zero-day-ai/sdk/api/gen/gibson/types/v1` | `typespb` | Task, Result, Finding, enums |
| `gibson.common.v1` | `github.com/zero-day-ai/sdk/api/gen/gibson/common/v1` | `commonpb` | TypedValue, TypedMap, ErrorCode, HealthStatus |
| `gibson.component.v1` | `github.com/zero-day-ai/sdk/api/gen/gibson/component/v1` | `componentpb` | ComponentService types |
| `gibson.graphrag.v1` | `github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1` | `graphragpb` | GraphQuery, GraphNode, DiscoveryResult |
| `gibson.workflow.v1` | `github.com/zero-day-ai/sdk/api/gen/gibson/workflow/v1` | `workflowpb` | WorkflowDefinition |
| `taxonomy.v1` | `github.com/zero-day-ai/sdk/api/gen/taxonomy/v1` | `taxonomypb` | CoreNodeType, CoreRelationType |
| `intelligence.v1` | `github.com/zero-day-ai/sdk/api/gen/intelligence/v1` | `intelligencepb` | IntelligenceService types |
| toolspb | `github.com/zero-day-ai/sdk/api/gen/toolspb` | `toolspb` | Nmap/Httpx/Nuclei protobuf types for extraction |

**NEVER import tool, plugin, or agent Go modules in Gibson's go.mod.** Gibson depends ONLY on the SDK (plus third-party libs). Tool protobuf types for extraction come from the SDK's `toolspb` package, not from individual tool repos.

**NEVER hand-write proto message types or gRPC service stubs.** Always generate from `.proto` files using `buf generate`.

**When adding new RPCs to daemon.proto:** regenerate Go code here, then regenerate TypeScript in the dashboard repo.

## Critical Rules

- **NEVER use local file includes for anything** — all includes, imports, references, and dependencies must point to GitHub (e.g., `github.com/zero-day-ai/...`). No local `replace` directives, no local file paths in imports, no local file:// references. GitHub only.

## Key Conventions

- **Go 1.25**, `CGO_ENABLED=0` for all builds
- **No local `replace` in go.mod** — causes proto descriptor mismatches and daemon panics. Use `go work` for local SDK development.
- **No tool/plugin/agent dependencies in go.mod** — Gibson only depends on the SDK. Tool proto types come from SDK's `toolspb`.
- **Proto field 100** in tool responses is always reserved for `gibson.graphrag.v1.DiscoveryResult`
- **`component.yaml`** defines tool/plugin/agent metadata for registry discovery
- **Environment variable substitution** in config: `${VAR:-default}` syntax
- Structured logging with `log/slog`; context propagation for tracing
- Proto source: `internal/daemon/api/gibson/daemon/v1/daemon.proto` → generated: `internal/daemon/api/`

## Configuration

Primary: `configs/gibson.yaml` or `~/.gibson/config.yaml`. Key sections: core (home/data/cache dirs), security (encryption, key provider), auth (OIDC issuers, K8s, local users), components (gRPC/callback addresses), inference (LLM slots/limits), observability (log level, OTLP exporters).

## Infrastructure

- **Redis** — state, queues, mission memory, daemon registration, plugin config storage
- **Neo4j 5.x** — GraphRAG knowledge graph
- **etcd** — component registry, service discovery (30s TTL heartbeat)
- **PostgreSQL/ClickHouse** — Langfuse persistence/analytics

Redis key patterns: `plugin-access:tenant:name`, `plugin-config:tenant:name`, `plugin-schema:name`, `mission:run:*`.
