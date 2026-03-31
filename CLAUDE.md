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

### Entity Extraction (`internal/extraction/`)

Tool responses are converted to GraphRAG entities via `EntityExtractor` implementations registered in `ExtractorRegistry`. Each tool (nmap, nuclei, httpx) has its own extractor producing `graphragpb.DiscoveryResult` (nodes + relationships) stored in Neo4j.

### Authentication (`internal/auth/`)

Token routing chain: `gsk_`-prefixed → APIKeyAuthenticator (Redis-backed); all others → OIDC → K8s ServiceAccount → Local (first match). Auth modes: `enterprise`, `saas`, `development`. `trust_localhost` bypasses auth for 127.0.0.1 in dev. RBAC maps claims to roles/permissions.

### Encryption (`internal/crypto/`)

AES-256-GCM for plugin config encryption. `KeyProvider` interface with backends: Kubernetes Secret, HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager. Factory pattern selects provider from config.

### Context Keys (`internal/contextkeys/`)

Shared context keys avoid circular imports: `AgentRunID`, `ToolExecutionID`, `MissionRunID`, `AgentName`, `MissionID`. Set during mission execution, consumed by harness, GraphRAG, and observability packages.

## Critical Rules

- **NEVER use local file includes for anything** — all includes, imports, references, and dependencies must point to GitHub (e.g., `github.com/zero-day-ai/...`). No local `replace` directives, no local file paths in imports, no local file:// references. GitHub only.

## Key Conventions

- **Go 1.25**, `CGO_ENABLED=0` for all builds
- **No local `replace` in go.mod** — causes proto descriptor mismatches and daemon panics. Use `go work` for local SDK development.
- **Proto field 100** in tool responses is always reserved for `gibson.graphrag.DiscoveryResult`
- **`component.yaml`** defines tool/plugin/agent metadata for registry discovery
- **Environment variable substitution** in config: `${VAR:-default}` syntax
- Structured logging with `log/slog`; context propagation for tracing
- Proto source: `api/proto/*.proto` → generated: `api/gen/proto/` (source-relative paths)

## Configuration

Primary: `configs/gibson.yaml` or `~/.gibson/config.yaml`. Key sections: core (home/data/cache dirs), security (encryption, key provider), auth (OIDC issuers, K8s, local users), components (gRPC/callback addresses), inference (LLM slots/limits), observability (log level, OTLP exporters).

## Infrastructure

- **Redis** — state, queues, mission memory, daemon registration, plugin config storage
- **Neo4j 5.x** — GraphRAG knowledge graph
- **etcd** — component registry, service discovery (30s TTL heartbeat)
- **PostgreSQL/ClickHouse** — Langfuse persistence/analytics

Redis key patterns: `plugin-access:tenant:name`, `plugin-config:tenant:name`, `plugin-schema:name`, `mission:run:*`.
