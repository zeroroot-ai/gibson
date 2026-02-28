# Gibson

**Autonomous Security Testing Framework**

Gibson is an extensible framework for building and orchestrating autonomous security testing agents. It provides the infrastructure to rapidly develop agents that can test anything - APIs, networks, web applications, cloud infrastructure, smart contracts, LLMs, IoT devices, or any system you can write an agent for.

## What Gibson Does

Gibson is **not** a security scanner. It's a **framework** that lets you:

- **Build agents** that autonomously perform security testing tasks
- **Orchestrate workflows** that coordinate multiple agents in complex testing scenarios
- **Store knowledge** in a graph database for reasoning about attack paths and relationships
- **Execute tools** in a distributed, queue-based architecture
- **Track findings** with full provenance back to the agent and mission that discovered them

Think of it as Kubernetes for security testing - you bring the agents, Gibson handles orchestration, scheduling, observability, and state management.

## Architecture

```
                         ┌─────────────────────────────────────────────────────────────┐
                         │                      Gibson CLI                             │
                         │  mission | attack | agent | tool | target | finding | ...  │
                         └────────────┬────────────────────────────────────────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────────────────────────────────────────┐
                         │                  Daemon (gRPC Server)                       │
                         │     Orchestration · Registry · Callbacks · Persistence      │
                         └────┬──────────────┬──────────────┬──────────────┬───────────┘
                              │              │              │              │
                              ▼              ▼              ▼              ▼
                         ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐
                         │  etcd   │  │  Redis   │  │ Database │  │  GraphRAG    │
                         │Registry │  │  Queue   │  │ (SQLite) │  │  (Neo4j)     │
                         └─────────┘  └──────────┘  └──────────┘  └──────────────┘
                                           │
                                           ▼
                         ┌─────────────────────────────────────────────────────────────┐
                         │                    Your Agents & Tools                       │
                         │   network-scanner | web-fuzzer | cloud-auditor | ...        │
                         └─────────────────────────────────────────────────────────────┘
```

## Core Concepts

### Component Hierarchy

Gibson has three types of executable components with distinct roles and invocation patterns:

| Aspect | Tool | Plugin | Agent |
|--------|------|--------|-------|
| **Purpose** | Atomic security operations | External service integrations | Autonomous LLM-driven testing |
| **State** | Stateless | Stateful (connections, caches) | Stateful (memory, context) |
| **I/O Format** | Protocol Buffers | JSON maps | Harness interface |
| **Invoked By** | Agents only | Agents only | **Orchestrator directly** |
| **LLM Access** | No | No | Yes (multi-slot) |
| **Memory Access** | No | No | Yes (3-tier) |
| **Sub-delegation** | No | No | Yes (to other agents) |
| **Graph Population** | Automatic (Field 100) | Manual | Agent decides |
| **Examples** | nmap, httpx, nuclei | shodan, scope-ingestion | network-recon, web-fuzzer |

**Key Architectural Point:** The mission orchestrator's Observe → Think → Act loop **only manages agents**. Tools and plugins are resources that agents invoke through their harness - they are not directly orchestrated.

```
MISSION ORCHESTRATOR (LLM decides which agent to run)
    │
    └─→ Executes AGENT (e.g., network-recon)
            │
            AGENT has Harness providing:
            ├─→ CallToolProto("nmap", request)     ← Agent decides when
            ├─→ QueryPlugin("shodan", "search")    ← Agent decides when
            ├─→ DelegateToAgent("subdomain-enum")  ← Agent decides when
            ├─→ Complete("primary", messages)      ← LLM reasoning
            └─→ Memory().Mission().Set(...)        ← State persistence
```

This design means:
- **Agents are autonomous** - they decide which tools/plugins to use based on LLM reasoning
- **Tools are simple** - stateless operations that don't need orchestrator decisions
- **Plugins are resources** - stateful services that agents query as needed
- **Orchestrator focuses on strategy** - which agent runs when, not low-level tool calls

### Agents

Autonomous units that perform security testing. An agent can be anything:
- A network scanner that maps infrastructure
- A web crawler that discovers endpoints
- A fuzzer that tests input validation
- A credential tester that checks authentication
- An LLM red-teamer that probes AI systems
- A smart contract auditor that analyzes bytecode

Agents are built with the [Gibson SDK](https://github.com/zero-day-ai/sdk) and can use any tools, call any APIs, and implement any testing logic.

### Tools

Stateless capabilities that agents invoke. Tools execute via a Redis queue-based distributed architecture for horizontal scaling:

- Protocol Buffers for type-safe I/O
- Automatic GraphRAG population with discovered assets
- Health monitoring and capability reporting
- Categories mapped to MITRE ATT&CK techniques

### Missions

YAML-defined workflows that orchestrate agents in a DAG (directed acyclic graph):

- Sequential, parallel, and conditional execution
- Checkpointing and resumption
- Constraints (time, cost, finding limits)
- Auto-installation of dependencies

### GraphRAG

Neo4j-powered hybrid knowledge graph that stores:

- Discovered assets (hosts, ports, services, endpoints)
- Relationships between entities
- Attack patterns and MITRE ATT&CK technique mappings
- Findings with full context and evidence
- Vector embeddings for semantic search

### Harness

The runtime environment provided to agents:

- **LLM Access** - Anthropic Claude, OpenAI GPT, Google Gemini, Ollama (local)
- **Tool Invocation** - Proto-based tool execution via Redis queues
- **Sub-agent Delegation** - Spawn and coordinate child agents
- **Finding Submission** - Store vulnerabilities with evidence
- **Three-tier Memory** - Working (ephemeral), Mission (persistent), Long-term (vector)

### Plugins

Stateful service integrations with methods and lifecycle management:

- Initialize with configuration
- Expose query methods
- Report health status
- Integrate external APIs

## Quick Start

### Prerequisites

- Go 1.24+
- Redis 6.0+
- Neo4j 5.0+ (optional, for GraphRAG)

### Installation

```bash
git clone https://github.com/zero-day-ai/gibson.git
cd gibson
make build
./bin/gibson init
```

### Run Your First Mission

```bash
# Start the daemon
gibson daemon start

# Add a target
gibson target add my-app --type http_api

# Run a mission
gibson mission run recon.yaml --target my-app

# View findings
gibson finding list
```

## Remote Mission Execution

Gibson supports running missions on remote daemons, enabling CI/CD integration and distributed deployments. When connecting to a remote daemon, the CLI automatically transmits local mission files inline without requiring filesystem access on the remote host.

### How It Works

The CLI automatically detects whether you're connecting to a local or remote daemon based on the `GIBSON_DAEMON_ADDRESS` environment variable:

- **Local Mode** (default): Mission file path is sent to the daemon, which reads the file from its local filesystem
- **Remote Mode**: Mission file content is read locally and transmitted inline via gRPC (up to 10MB)

### Usage

Set the `GIBSON_DAEMON_ADDRESS` environment variable to point to a remote daemon:

```bash
# Connect to remote daemon
export GIBSON_DAEMON_ADDRESS="remote-host.example.com:50002"

# Run a local mission file on the remote daemon
gibson mission run ./missions/recon.yaml --target my-app

# The CLI automatically reads the local file and sends it to the remote daemon
```

### Local vs Remote Detection

The daemon is considered **remote** when `GIBSON_DAEMON_ADDRESS` is set to any value that is NOT:
- Empty (unset)
- `localhost`
- `127.0.0.1`
- `::1`
- `localhost:*` (any port)
- `127.0.0.1:*` (any port)
- `::1:*` (any port)

All other addresses (hostnames, IPs, FQDNs) trigger remote mode with inline YAML transmission.

### CI/CD Pipeline Integration

#### GitLab CI Example

```yaml
# .gitlab-ci.yml
stages:
  - security-test

gibson-scan:
  stage: security-test
  image: ghcr.io/zero-day-ai/gibson:latest
  variables:
    GIBSON_DAEMON_ADDRESS: "gibson.internal.example.com:50002"
    # Optional: Set LLM provider keys
    ANTHROPIC_API_KEY: $ANTHROPIC_API_KEY
  script:
    # Verify daemon connectivity
    - gibson daemon status

    # Add target (or use pre-configured target)
    - gibson target add ${CI_PROJECT_NAME} --type http_api --url ${CI_ENVIRONMENT_URL}

    # Run security mission
    - gibson mission run ./gibson/security-scan.yaml --target ${CI_PROJECT_NAME}

    # Export findings
    - gibson finding export --format json > findings.json

    # Fail pipeline if critical findings exist
    - |
      CRITICAL_COUNT=$(jq '[.[] | select(.severity == "critical")] | length' findings.json)
      if [ "$CRITICAL_COUNT" -gt 0 ]; then
        echo "Found $CRITICAL_COUNT critical findings!"
        exit 1
      fi
  artifacts:
    reports:
      # Export findings as test report
      junit: findings.json
    paths:
      - findings.json
    expire_in: 30 days
  only:
    - main
    - merge_requests
```

#### GitHub Actions Example

```yaml
# .github/workflows/security-scan.yml
name: Gibson Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    # Run daily security scans
    - cron: '0 2 * * *'

jobs:
  security-test:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Run Gibson security scan
        env:
          GIBSON_DAEMON_ADDRESS: gibson.internal.example.com:50002
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          # Install Gibson CLI (if not in container)
          # curl -L https://github.com/zero-day-ai/gibson/releases/latest/download/gibson-linux-amd64 -o gibson
          # chmod +x gibson

          # Or use pre-built container
          docker run --rm \
            -v $(pwd)/missions:/missions \
            -e GIBSON_DAEMON_ADDRESS="${GIBSON_DAEMON_ADDRESS}" \
            -e ANTHROPIC_API_KEY="${ANTHROPIC_API_KEY}" \
            ghcr.io/zero-day-ai/gibson:latest \
            mission run /missions/security-scan.yaml

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-findings
          path: findings.json

      - name: Check for critical findings
        run: |
          CRITICAL_COUNT=$(jq '[.[] | select(.severity == "critical")] | length' findings.json || echo 0)
          if [ "$CRITICAL_COUNT" -gt 0 ]; then
            echo "::error::Found $CRITICAL_COUNT critical security findings"
            exit 1
          fi
```

#### Jenkins Pipeline Example

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        GIBSON_DAEMON_ADDRESS = 'gibson.internal.example.com:50002'
        ANTHROPIC_API_KEY = credentials('anthropic-api-key')
    }

    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Run Gibson mission
                    sh '''
                        gibson mission run ./missions/api-security.yaml \
                          --target ${JOB_NAME} \
                          --var "base_url=${BUILD_URL}"
                    '''

                    // Export and analyze findings
                    sh 'gibson finding export --format json > findings.json'

                    def findings = readJSON file: 'findings.json'
                    def criticalCount = findings.count { it.severity == 'critical' }

                    if (criticalCount > 0) {
                        error("Found ${criticalCount} critical security findings!")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'findings.json', fingerprint: true
            publishHTML([
                reportDir: '.',
                reportFiles: 'findings.json',
                reportName: 'Security Findings'
            ])
        }
    }
}
```

### Troubleshooting

#### Connection Refused

```bash
Error: failed to connect to remote daemon at remote-host:50002
```

**Solutions:**
1. Verify the daemon is running: `ssh user@remote-host 'gibson daemon status'`
2. Check network connectivity: `telnet remote-host 50002` or `nc -zv remote-host 50002`
3. Verify firewall rules allow traffic on port 50002
4. Ensure the daemon gRPC address is configured correctly in `~/.gibson/config.yaml`:
   ```yaml
   daemon:
     grpc_address: 0.0.0.0:50002  # Listen on all interfaces for remote connections
   ```

#### Mission File Size Limit

```bash
Error: mission file exceeds 10MB limit
```

**Solutions:**
1. Reduce mission file size by splitting into smaller missions
2. Remove unnecessary comments or documentation from YAML
3. Extract large data structures into separate configuration files
4. For very large missions, deploy the mission file directly on the remote daemon filesystem

#### File Not Found

```bash
Error: failed to read mission file: no such file or directory
```

**Solutions:**
1. Verify the file path is correct: `ls -l ./missions/my-mission.yaml`
2. Use absolute paths if running from different working directories
3. Check file permissions: `chmod 644 missions/my-mission.yaml`

#### Invalid YAML

```bash
Error: mission YAML parse error: yaml: line 45: could not find expected ':'
```

**Solutions:**
1. Validate YAML syntax: `gibson mission validate ./missions/my-mission.yaml`
2. Use a YAML linter: `yamllint missions/my-mission.yaml`
3. Check for tabs vs spaces (YAML requires spaces)
4. Ensure proper indentation (2 spaces recommended)

#### Daemon Version Mismatch

If connecting to an older daemon that doesn't support inline YAML transmission:

```bash
Warning: Remote daemon may not support inline YAML transmission
Error: workflow file not found on daemon filesystem
```

**Solutions:**
1. Update the remote daemon to the latest version
2. Manually copy the mission file to the remote daemon: `scp mission.yaml user@remote:/tmp/`
3. Use the file path on the remote filesystem: `gibson mission run /tmp/mission.yaml`

### Security Considerations

1. **TLS Encryption**: Enable TLS for remote connections to protect mission content in transit:
   ```yaml
   # config.yaml
   daemon:
     grpc_address: 0.0.0.0:50002
     tls:
       enabled: true
       cert_file: /path/to/cert.pem
       key_file: /path/to/key.pem
   ```

2. **Authentication**: Use network-level authentication (VPN, private networks, mTLS) for remote daemon access

3. **Size Limits**: The 10MB limit prevents excessive memory usage and potential DoS attacks

4. **Input Validation**: Mission YAML is validated before execution to prevent injection attacks

## CLI Reference

### Daemon

```bash
gibson daemon start    # Start background services
gibson daemon stop     # Stop daemon
gibson daemon status   # Check status
```

### Targets

```bash
gibson target add <name> --type <type>   # Add target (http_api, kubernetes, network, etc.)
gibson target list                        # List targets
gibson target test <name>                 # Test connectivity
gibson target delete <name>               # Remove target
```

### Missions

```bash
gibson mission run <file|url|name>       # Execute a mission
gibson mission list                       # List missions
gibson mission show <id>                  # Show progress
gibson mission pause <id>                 # Pause execution
gibson mission resume <id>                # Resume from checkpoint
gibson mission cancel <id>                # Cancel mission
gibson mission validate <file>            # Validate YAML
```

### Quick Attack

```bash
gibson attack --target <name> --agent <agent>   # Single-agent attack
gibson attack --list-agents                      # List available agents
```

### Agents & Tools

```bash
gibson agent list                    # List installed agents
gibson agent install <url>           # Install from URL/git
gibson agent start <name>            # Start agent service
gibson agent stop <name>             # Stop agent service

gibson tool list                     # List installed tools
gibson tool install <url>            # Install tool
```

### Knowledge Store

```bash
gibson knowledge ingest --from-dir ./data    # Ingest documents
gibson knowledge search "query"               # Semantic search
```

### Findings

```bash
gibson finding list                  # List findings
gibson finding show <id>             # Show details
gibson finding export --format json  # Export findings
```

### Credentials

```bash
gibson credential add <name>         # Store encrypted credential
gibson credential list               # List credentials
```

## Configuration

Configuration lives at `~/.gibson/config.yaml`:

```yaml
core:
  home_dir: ~/.gibson
  parallel_limit: 10
  timeout: 5m

database:
  path: ~/.gibson/gibson.db

daemon:
  grpc_address: localhost:50002

redis:
  url: redis://localhost:6379

registry:
  type: embedded
  listen_address: localhost:2379

graphrag:
  enabled: true
  neo4j:
    uri: bolt://localhost:7687
    username: neo4j
    password: password

# LLM providers (set via environment variables)
# ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY, OLLAMA_URL

# Observability
langfuse:
  enabled: false
  host: "https://cloud.langfuse.com"
  public_key: ""
  secret_key: ""

tracing:
  enabled: false
  endpoint: localhost:4317

callback:
  enabled: true
  listen_address: 0.0.0.0:50001
```

## Mission YAML

Missions define workflows as directed acyclic graphs:

```yaml
name: "Infrastructure Assessment"
description: "Map and test network infrastructure"
version: "1.0.0"

nodes:
  # Discovery phase
  network-scan:
    type: agent
    agent: network-mapper
    parameters:
      ports: "1-65535"
      timeout: 10m

  # Branch based on findings
  check-services:
    type: condition
    expression: "findings.open_ports > 0"
    on_true: service-enum
    on_false: report

  # Enumerate services
  service-enum:
    type: agent
    agent: service-fingerprinter

  # Parallel vulnerability testing
  vuln-testing:
    type: parallel
    nodes: [web-scanner, ssh-auditor, db-tester]

  web-scanner:
    type: agent
    agent: web-vulnerability-scanner

  ssh-auditor:
    type: agent
    agent: ssh-config-auditor

  db-tester:
    type: agent
    agent: database-security-tester

  # Aggregate results
  aggregate:
    type: join
    sources: [vuln-testing]

  report:
    type: agent
    agent: report-generator

edges:
  - from: network-scan
    to: check-services
  - from: service-enum
    to: vuln-testing
  - from: aggregate
    to: report

entry_points: [network-scan]
exit_points: [report]

constraints:
  max_duration: 2h
  max_findings: 5000

dependencies:
  agents:
    - github.com/your-org/agents/network-mapper
    - github.com/your-org/agents/web-vulnerability-scanner
```

### Node Types

| Type | Purpose |
|------|---------|
| `agent` | Execute an agent |
| `tool` | Execute a tool directly |
| `condition` | Branch based on expression |
| `parallel` | Run multiple nodes concurrently |
| `join` | Wait for parallel nodes to complete |
| `plugin` | Invoke plugin capability |

## Gibson SDK

The [Gibson SDK](https://github.com/zero-day-ai/sdk) provides everything needed to build agents, tools, and plugins.

### SDK Package Structure

```
sdk/
├── agent/       # Agent interfaces and types
├── tool/        # Tool interfaces and worker utilities
├── plugin/      # Plugin interfaces
├── llm/         # LLM abstractions and message types
├── memory/      # Three-tier memory APIs
├── finding/     # Finding submission types
├── mission/     # Mission context types
├── serve/       # gRPC serving utilities
├── graphrag/    # GraphRAG integration
│   ├── domain/      # Generated domain types (Host, Port, Finding, etc.)
│   ├── validation/  # CEL-based validators
│   └── id/          # Node ID generation
├── taxonomy/    # YAML-driven taxonomy (single source of truth)
└── examples/    # Reference implementations
```

### Building an Agent

```go
package main

import (
    "context"
    "github.com/zero-day-ai/sdk/agent"
    "github.com/zero-day-ai/sdk/llm"
    "github.com/zero-day-ai/sdk/serve"
)

type MyAgent struct{}

func (a *MyAgent) Name() string        { return "my-agent" }
func (a *MyAgent) Version() string     { return "1.0.0" }
func (a *MyAgent) Description() string { return "My security agent" }

func (a *MyAgent) Capabilities() []string {
    return []string{"scanning", "enumeration"}
}

func (a *MyAgent) LLMSlots() []agent.SlotDefinition {
    return []agent.SlotDefinition{
        agent.NewSlotDefinition("primary", "Main reasoning LLM", true).
            WithConstraints(agent.SlotConstraints{
                MinContextWindow: 8000,
                RequiredFeatures: []string{agent.FeatureToolUse},
            }),
    }
}

func (a *MyAgent) Execute(ctx context.Context, task agent.Task, h agent.Harness) (agent.Result, error) {
    result := agent.NewResult(task.ID)
    result.Start()

    // Use LLM
    messages := []llm.Message{
        llm.NewSystemMessage("You are a security analyst"),
        llm.NewUserMessage(task.Goal),
    }
    resp, err := h.Complete(ctx, "primary", messages)
    if err != nil {
        result.Fail(err)
        return result, err
    }

    // Execute tools
    toolOutput, err := h.ExecuteTool(ctx, "nmap", &pb.NmapRequest{
        Target: task.Context["target"].(string),
    })

    // Submit findings
    h.SubmitFinding(ctx, agent.Finding{
        Title:      "Vulnerability Found",
        Severity:   agent.SeverityHigh,
        Confidence: 0.9,
    })

    result.Complete(map[string]any{"analysis": resp.Content})
    return result, nil
}

func main() {
    serve.Agent(&MyAgent{}, serve.WithPort(50051))
}
```

### Building a Tool

Tools are stateless wrappers around security utilities with Protocol Buffer I/O:

```go
package main

import (
    "context"
    pb "github.com/myorg/mytool/proto"
    "github.com/zero-day-ai/sdk/serve"
    "github.com/zero-day-ai/sdk/types"
    "google.golang.org/protobuf/proto"
)

type MyTool struct{}

func (t *MyTool) Name() string              { return "mytool" }
func (t *MyTool) Version() string           { return "1.0.0" }
func (t *MyTool) Description() string       { return "My security tool" }
func (t *MyTool) Tags() []string            { return []string{"scanning"} }
func (t *MyTool) InputMessageType() string  { return "gibson.tools.MyToolRequest" }
func (t *MyTool) OutputMessageType() string { return "gibson.tools.MyToolResponse" }

func (t *MyTool) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
    req := input.(*pb.MyToolRequest)

    // Execute tool logic
    results := performScan(req.Target)

    return &pb.MyToolResponse{
        Success: true,
        Data:    results,
    }, nil
}

func (t *MyTool) Health(ctx context.Context) types.HealthStatus {
    return types.HealthStatus{Status: types.HealthStatusHealthy}
}

func main() {
    serve.Tool(&MyTool{}, serve.WithPort(50052))
}
```

### Queue-Based Tool Workers

Tools can run as distributed workers processing jobs from Redis queues:

```go
package main

import (
    "github.com/myorg/mytool"
    "github.com/zero-day-ai/sdk/tool/worker"
    "time"
)

func main() {
    tool := &mytool.MyTool{}

    opts := worker.Options{
        RedisURL:        "redis://localhost:6379",
        Concurrency:     4,
        ShutdownTimeout: 30 * time.Second,
    }

    worker.Run(tool, opts)
}
```

### Three-Tier Memory System

```go
// Working Memory - ephemeral, task-scoped (in-memory key-value)
harness.Memory().Working().Set(ctx, "key", value)
harness.Memory().Working().Get(ctx, "key")

// Mission Memory - persistent, mission-scoped (SQLite with FTS5 search)
harness.Memory().Mission().Set(ctx, "key", value)
harness.Memory().Mission().Search(ctx, "query", opts)

// Long-Term Memory - vector storage, cross-mission (semantic embeddings)
harness.Memory().LongTerm().Store(ctx, "text data", metadata)
harness.Memory().LongTerm().Search(ctx, "semantic query", threshold, limit)
```

### GraphRAG Domain Types

Type-safe domain types for storing security data in the knowledge graph:

```go
import "github.com/zero-day-ai/sdk/graphrag/domain"

// Create entities with automatic UUID assignment
host := domain.NewHost().
    SetIp("192.168.1.1").
    SetHostname("server.local").
    SetOs("Linux")

// Child entities wire parent relationships automatically
port := domain.NewPort(443, "tcp").BelongsTo(host)
service := domain.NewService("https").BelongsTo(port)

// Findings with evidence
finding := domain.NewFinding("SQL Injection", "critical").
    SetDescription("SQL injection in login form").
    SetConfidence(0.95)
```

## LLM Providers

Gibson automatically detects LLM providers from environment variables:

| Variable | Provider |
|----------|----------|
| `ANTHROPIC_API_KEY` | Claude models |
| `OPENAI_API_KEY` | GPT models |
| `GOOGLE_API_KEY` | Gemini models |
| `OLLAMA_URL` | Local Ollama (also tries localhost:11434) |

## Orchestrator Decision Actions

The mission orchestrator uses an LLM-powered Observe → Think → Act loop to make intelligent decisions about workflow execution. The following actions are available:

| Action | Description | When to Use |
|--------|-------------|-------------|
| `execute_agent` | Run the specified workflow node | Node is ready, dependencies satisfied |
| `skip_agent` | Skip execution of a workflow node | Node no longer needed based on findings |
| `modify_params` | Change parameters for a target node | Discoveries suggest different configuration |
| `retry` | Retry a failed node | Transient failure that can be overcome |
| `spawn_agent` | Dynamically add a new node | Unexpected attack surface discovered |
| `complete` | Mark workflow as complete | Mission objective achieved |
| `request_approval` | Pause for human approval | Before exploits, credential testing, data extraction |
| `abort` | Emergency stop the mission | Scope violation, safety concern detected |
| `escalate` | Escalate to human or specialist | Zero-day discovery, unclear authorization |
| `rollback` | Revert to previous checkpoint | Strategy triggered defenses, need alternative |
| `reflect` | Self-evaluate current strategy | Multiple failures, mid-mission assessment |
| `recall` | Query memory for context | Leverage prior findings for similar targets |

### Safety Actions

The orchestrator includes built-in safety mechanisms:

- **request_approval**: Blocks execution until human approves sensitive operations (exploits, injection tests)
- **abort**: Immediately terminates mission on scope violations or unintended access
- **escalate**: Routes critical findings (potential zero-days) to security team

### Memory Actions

The orchestrator can leverage the three-tier memory system:

- **reflect**: Triggers a separate LLM evaluation of strategy effectiveness
- **recall**: Queries mission memory (SQLite FTS5) or long-term memory (Qdrant vectors) for relevant context

See `internal/orchestrator/prompts.go` for the full system prompt and decision schema.

## Event System

Comprehensive event types for observability with OpenTelemetry trace correlation:

- **Mission Events** - started, progress, node, completed, failed
- **Agent Events** - registered, started, completed, failed, delegated
- **LLM Events** - request started/completed/failed, streaming
- **Tool Events** - call started/completed/failed, progress
- **Finding Events** - discovered, submitted
- **Memory Events** - get, set, search

## Project Structure

```
gibson/
├── cmd/gibson/           # CLI commands
├── configs/              # Example configuration
├── internal/
│   ├── agent/            # Agent interfaces
│   ├── config/           # Configuration loading
│   ├── daemon/           # Daemon and gRPC server
│   ├── events/           # Event bus and types
│   ├── finding/          # Finding management
│   ├── graphrag/         # Neo4j integration
│   ├── harness/          # Agent runtime environment
│   ├── llm/              # LLM provider abstraction
│   ├── memory/           # Three-tier memory implementation
│   ├── mission/          # Mission execution
│   ├── observability/    # OpenTelemetry, Langfuse
│   ├── orchestrator/     # Workflow orchestration
│   ├── plugin/           # Plugin registry and lifecycle
│   ├── registry/         # Service discovery (etcd)
│   ├── component/        # External component management
│   └── tool/             # Tool execution (Redis)
└── tests/
```

## Building

```bash
make build          # Build binary
make test           # Run tests
make test-coverage  # Coverage report
make lint           # Lint code
make proto          # Generate protobuf
```

## Use Cases

Gibson is designed for building:

- **Network Security Testing** - Autonomous infrastructure scanning and vulnerability discovery
- **Web Application Testing** - Crawling, fuzzing, injection testing
- **Cloud Security Auditing** - AWS/Azure/GCP configuration review
- **API Security Testing** - Authentication, authorization, input validation
- **Container Security** - Kubernetes, Docker security assessment
- **Smart Contract Auditing** - Blockchain and DeFi security
- **LLM Red-Teaming** - Prompt injection, jailbreak testing
- **IoT Security** - Device and protocol testing
- **Compliance Scanning** - Automated compliance checking
- **Custom Security Workflows** - Whatever you can build an agent for

## Related Repositories

| Repository | Description |
|------------|-------------|
| [sdk](https://github.com/zero-day-ai/sdk) | Go SDK for building agents, tools, and plugins |
| [tools](https://github.com/zero-day-ai/tools) | Security tool wrappers (nmap, httpx, nuclei, etc.) |

## Why Gibson?

| Problem | Gibson's Solution |
|---------|-------------------|
| Security tools don't integrate | Unified orchestration layer with proto-based APIs |
| Manual testing doesn't scale | Autonomous agent execution with LLM reasoning |
| Findings lack context | GraphRAG knowledge relationships and semantic search |
| Complex workflows are fragile | DAG-based missions with checkpointing and resumption |
| Building security tools is slow | SDK with batteries included and code generation |
| No visibility into testing | OpenTelemetry tracing and Langfuse observability |

## License

Apache 2.0

## Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.
