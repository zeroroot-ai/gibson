# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Gibson is a Kubernetes-native AI agent framework for developing, deploying, and observing autonomous agents. It provides orchestration, observability, state management, tool execution, and knowledge persistence for AI agents performing security testing, API discovery, compliance auditing, and other autonomous tasks.

## Build Commands

```bash
# Build the binary
make bin                    # Quick local build, outputs to bin/gibson

# Run tests
make test                   # Run all tests
make test-race              # Run tests with race detection
go test ./internal/finding/...  # Run tests for a specific package

# Code quality
make lint                   # Run golangci-lint
make fmt                    # Format code
make vet                    # Run go vet
make check                  # Run all checks (fmt, vet, lint, test-race)

# Coverage
make test-coverage          # Run with 90% coverage threshold
make coverage-html          # Generate HTML coverage report
```

## Architecture

### Core Packages (`internal/`)

- **orchestrator**: LLM-driven mission orchestration using DAG execution, makes decisions about agent scheduling
- **harness**: `AgentHarness` interface provided to agents - coordinates LLM access, tool execution, memory, and findings
- **llm**: Multi-provider LLM abstraction (Anthropic, OpenAI, Ollama) with slot-based model selection
- **memory**: Three-tier memory system - working (ephemeral), mission (Redis), long-term (vector)
- **graphrag**: Neo4j-backed knowledge graph for semantic entity storage and retrieval
- **registry**: etcd-based service discovery for agents and tools
- **finding**: Security finding types, classification, and export (SARIF, CSV, HTML, Markdown)
- **observability**: OpenTelemetry tracing with GenAI conventions, Prometheus metrics
- **daemon**: gRPC daemon server with health probes (`/healthz`, `/readyz`)
- **mission**: Mission definition, parsing, and lifecycle management
- **guardrail**: Input validation and safety checks (PII, scope, rate limiting)
- **prompt**: Prompt assembly with components, variables, and transformers
- **state**: Redis-backed state management with checkpointing

### CLI Structure (`cmd/gibson/`)

- **root.go**: Command registration and mode-based initialization (daemon, client, standalone)
- **mode/**: Command mode classification determining initialization strategy
- **daemon.go**: Daemon start/stop commands
- Mission, agent, tool, finding commands for respective operations

### Agent Execution Flow

1. Mission YAML parsed and validated
2. Orchestrator builds execution DAG
3. For each node, orchestrator calls LLM to decide next action
4. Agent executes via `AgentHarness.Execute(ctx, task, harness)`
5. Agent uses harness for:
   - LLM: `harness.Complete(ctx, "primary", messages)`
   - Tools: `harness.CallToolProto(ctx, "nmap", req, resp)`
   - Findings: `harness.SubmitFinding(ctx, finding)`
   - Memory: `harness.Memory().Mission().Set(ctx, key, value)`
6. Results flow to GraphRAG knowledge graph

### Key Interfaces

```go
// Agent execution interface
type AgentHarness interface {
    Complete(ctx, slot, messages, opts...) (*CompletionResponse, error)
    CompleteWithTools(ctx, slot, messages, tools, opts...) (*CompletionResponse, error)
    CallToolProto(ctx, name string, req, resp proto.Message) error
    SubmitFinding(ctx, finding) error
    Memory() MemoryManager
    // ... more methods
}
```

## Configuration

- Primary config: `configs/gibson.yaml` (example) or `~/.gibson/config.yaml`
- Environment variables: `GIBSON_HOME`, `REDIS_URL`, `NEO4J_URI`, `ANTHROPIC_API_KEY`, etc.
- LLM providers configured via env: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OLLAMA_HOST`

## Testing Patterns

- Unit tests alongside source files (`*_test.go`)
- Integration tests use testcontainers for Redis/Neo4j
- E2E tests in `tests/e2e/` and `cmd/gibson/*_e2e_test.go`
- Use `github.com/stretchr/testify` for assertions
- Mock interfaces defined near implementations (e.g., `internal/component/build/mock.go`)

## Dependencies

- Uses `github.com/zero-day-ai/sdk` (local replace directive pointing to `../sdk`)
- Redis via `github.com/redis/go-redis/v9`
- Neo4j via `github.com/neo4j/neo4j-go-driver/v5`
- etcd via `go.etcd.io/etcd/client/v3`
- OpenTelemetry for observability
- Cobra/Viper for CLI

## Code Conventions

- CGO disabled (`CGO_ENABLED=0`)
- Go 1.24+ required
- Structured logging with `log/slog`
- Context propagation for tracing and cancellation
- Protocol Buffers for tool communication
