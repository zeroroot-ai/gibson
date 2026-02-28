# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Development Commands

```bash
# Build the binary (CGO required for SQLite FTS5)
make bin                    # Quick local build -> bin/gibson

# Testing
make test                   # Run all tests with -v
make test-race              # Run tests with race detection
make test-coverage          # Run tests with 90% coverage threshold
go test -v ./internal/llm/... # Run specific package tests

# Code quality
make lint                   # Run golangci-lint (staticcheck, govet, errcheck, ineffassign, unused)
make fmt                    # Format code
make check                  # Run fmt, vet, lint, test-race

# Proto generation (if adding gRPC APIs)
make proto                  # Generate Go code from proto files
```

**Important:** CGO is required (`CGO_ENABLED=1`) with `CGO_CFLAGS=-DSQLITE_ENABLE_FTS5` for SQLite FTS5 support. The Makefile handles this automatically.

## Architecture Overview

Gibson is an autonomous security testing orchestration framework. The architecture follows a daemon-based model where the CLI communicates with a background gRPC server that orchestrates agents, tools, and missions.

### Core Components

**Daemon (`internal/daemon/`)** - Background gRPC server providing orchestration services. Handles mission execution, agent registration, and tool dispatching. Supports both local and remote connections via `GIBSON_DAEMON_ADDRESS`.

**Orchestrator (`internal/orchestrator/`)** - Executes mission workflows as DAGs (directed acyclic graphs). Manages node execution, branching, parallel execution, and checkpointing.

**Harness (`internal/harness/`)** - Runtime environment provided to agents. Provides LLM access, tool invocation, sub-agent delegation, finding submission, and three-tier memory (working/mission/long-term).

**LLM (`internal/llm/`)** - Multi-provider LLM abstraction supporting Anthropic, OpenAI, Google, and Ollama. Handles provider detection from environment variables, token tracking, and pricing.

**Memory (`internal/memory/`)** - Three-tier memory system:
- Working: Ephemeral, task-scoped (in-memory)
- Mission: Persistent, mission-scoped (SQLite with FTS5)
- Long-term: Vector storage for semantic search

**GraphRAG (`internal/graphrag/`)** - Neo4j-powered knowledge graph for storing discovered assets, relationships, and findings with vector embeddings.

**Registry (`internal/registry/`)** - etcd-based service discovery for agents and tools.

**Tool (`internal/tool/`)** - Redis queue-based distributed tool execution.

### CLI Structure

`cmd/gibson/` contains Cobra commands organized by domain:
- `daemon.go` - Daemon lifecycle (start/stop/status)
- `mission.go` - Mission execution and management
- `attack.go` - Quick single-agent attacks
- `agent.go`, `tool.go`, `plugin.go` - Component management
- `target.go`, `finding.go`, `credential.go` - Data management

### External Dependencies

The framework depends on the [Gibson SDK](https://github.com/zero-day-ai/sdk) (`github.com/zero-day-ai/sdk`) which provides interfaces for building agents, tools, and plugins.

### Key Design Patterns

- **Proto-based APIs**: All tool I/O uses Protocol Buffers for type safety
- **Event-driven**: Comprehensive event system with OpenTelemetry trace correlation
- **Mission YAML**: Workflows defined as DAGs with nodes (agent, tool, condition, parallel, join)
- **Three-tier memory**: Working (ephemeral) -> Mission (persistent) -> Long-term (vector)

### Orchestrator Decision Actions

The LLM orchestrator can take these actions during mission execution:

| Action | Description | Use Case |
|--------|-------------|----------|
| `execute_agent` | Run the specified workflow node | Node ready, dependencies satisfied |
| `skip_agent` | Skip a workflow node | Node no longer needed based on findings |
| `modify_params` | Change node parameters | Discoveries suggest different config |
| `retry` | Retry a failed node | Transient failure, can retry |
| `spawn_agent` | Dynamically add a new node | Unexpected attack surface discovered |
| `complete` | Mark workflow complete | Mission objective achieved |
| `request_approval` | Pause for human approval | Before exploits, credential testing |
| `abort` | Emergency stop mission | Scope violation, safety concern |
| `escalate` | Escalate to human/specialist | Zero-day, unclear authorization |
| `rollback` | Revert to checkpoint | Strategy failed, need alternative |
| `reflect` | Self-evaluate strategy | Multiple failures, mid-mission review |
| `recall` | Query memory for context | Leverage prior findings |

See `internal/orchestrator/prompts.go` for the full system prompt and decision schema.

## Testing Patterns

Tests use `testify` for assertions and `testcontainers-go` for integration tests requiring Redis, Neo4j, or etcd. Integration tests are tagged and may require running infrastructure.

```bash
# Run a single test
go test -v -run TestSpecificFunction ./internal/memory/...
```

## Connecting to Remote Daemons (Kubernetes)

The Gibson CLI can connect to daemons running in Kubernetes clusters using environment variables.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `GIBSON_DAEMON_ADDRESS` | Remote daemon address (e.g., `gibson.example.com:50002`) |
| `GIBSON_FORCE_INLINE_YAML` | Set to `true` when using port-forward (forces inline YAML transmission) |

### Method 1: Direct Connection (Ingress/LoadBalancer)

If the Gibson daemon is exposed via Ingress or LoadBalancer:

```bash
export GIBSON_DAEMON_ADDRESS="gibson.internal.example.com:50002"

# Verify connectivity
gibson daemon status

# Run missions - local files are automatically transmitted inline
gibson mission run ./missions/recon.yaml --target my-app
```

### Method 2: Port Forwarding

When using `kubectl port-forward`, the address appears as localhost but the daemon is remote. Use `GIBSON_FORCE_INLINE_YAML` to force inline YAML transmission:

```bash
# Start port-forward to the Gibson service
kubectl port-forward svc/gibson 50002:50002 -n gibson &

# Configure CLI - MUST set GIBSON_FORCE_INLINE_YAML for port-forward
export GIBSON_DAEMON_ADDRESS="localhost:50002"
export GIBSON_FORCE_INLINE_YAML="true"

# Now run missions - local YAML files are sent inline to remote daemon
gibson daemon status
gibson mission run ./missions/security-scan.yaml --target my-app
```

### How Remote Detection Works

The CLI determines local vs remote based on `GIBSON_DAEMON_ADDRESS`:

**Local (file path sent to daemon):**
- Empty/unset
- `localhost`, `localhost:*`
- `127.0.0.1`, `127.0.0.1:*`
- `unix://` paths

**Remote (YAML content transmitted inline):**
- Any other hostname or IP
- OR when `GIBSON_FORCE_INLINE_YAML=true`

Implementation: `internal/daemon/client/client.go:559` (`isRemoteDaemon()`)

### Kubernetes Deployment Notes

The daemon must be configured to listen on all interfaces for remote connections:

```yaml
# config.yaml on daemon
daemon:
  grpc_address: 0.0.0.0:50002  # Not localhost:50002
```

### Troubleshooting

**Connection refused:**
```bash
# Check daemon is listening
kubectl exec -n gibson deploy/gibson -- netstat -tlnp | grep 50002

# Check service exists
kubectl get svc -n gibson

# Test connectivity
kubectl port-forward svc/gibson 50002:50002 -n gibson
nc -zv localhost 50002
```

**"workflow file not found" error:**
- You're connecting to a remote daemon but didn't set `GIBSON_FORCE_INLINE_YAML=true`
- The remote daemon is trying to read a local file path that doesn't exist on its filesystem

**Mission file too large:**
- Inline YAML transmission has a 10MB limit
- Split large missions or deploy YAML directly to the daemon filesystem
