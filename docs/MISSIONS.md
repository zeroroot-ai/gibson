# Gibson Missions

Missions are YAML-defined workflows that orchestrate autonomous agents through directed acyclic graphs (DAGs). The Gibson orchestrator uses an LLM-powered **Observe → Think → Act** loop to dynamically execute, adapt, and reason through mission workflows.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Mission Execution                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Mission YAML ──► Parser ──► DAG Builder ──► Orchestrator               │
│                                                    │                     │
│                              ┌─────────────────────┼─────────────────┐   │
│                              │     Control Loop    ▼                 │   │
│                              │  ┌─────────────────────────────────┐  │   │
│                              │  │          1. OBSERVE             │  │   │
│                              │  │   Query graph state, memory,    │  │   │
│                              │  │   completed nodes, findings     │  │   │
│                              │  └───────────────┬─────────────────┘  │   │
│                              │                  ▼                    │   │
│                              │  ┌─────────────────────────────────┐  │   │
│                              │  │           2. THINK              │  │   │
│                              │  │   LLM reasoning: what next?     │  │   │
│                              │  │   Returns Decision with action  │  │   │
│                              │  └───────────────┬─────────────────┘  │   │
│                              │                  ▼                    │   │
│                              │  ┌─────────────────────────────────┐  │   │
│                              │  │            3. ACT               │  │   │
│                              │  │   Execute decision: run agent,  │  │   │
│                              │  │   skip, retry, spawn, complete  │  │   │
│                              │  └───────────────┬─────────────────┘  │   │
│                              │                  │                    │   │
│                              │        ◄─────────┘ (loop until done) │   │
│                              └───────────────────────────────────────┘   │
│                                                                          │
│   State Backend: Redis Stack (RediSearch + RedisJSON + Streams)          │
│   Graph Backend: Neo4j (entity/relationship storage)                     │
│   Registry: etcd (agent/tool discovery)                                  │
└─────────────────────────────────────────────────────────────────────────┘
```

## Quickstart

### Prerequisites

Gibson requires Redis Stack as its primary state backend:

```bash
# Start Redis Stack (includes RediSearch and RedisJSON)
docker run -d --name redis-stack \
  -p 6379:6379 \
  -p 8001:8001 \
  redis/redis-stack:latest

# Start Neo4j for GraphRAG (optional but recommended)
docker run -d --name neo4j \
  -p 7474:7474 -p 7687:7687 \
  -e NEO4J_AUTH=neo4j/password \
  neo4j:5-community

# Start etcd for service discovery
docker run -d --name etcd \
  -p 2379:2379 \
  quay.io/coreos/etcd:v3.5.18 \
  etcd --advertise-client-urls http://0.0.0.0:2379 \
       --listen-client-urls http://0.0.0.0:2379
```

### Create Your First Mission

```yaml
# recon-mission.yaml
name: "Basic Reconnaissance"
description: "Network discovery and service enumeration"
version: "1.0.0"

nodes:
  - id: network-scan
    type: agent
    agent: network-recon
    timeout: 10m
    task:
      target: "{{target}}"
      scan_type: passive

  - id: service-enum
    type: agent
    agent: service-fingerprinter
    depends_on: [network-scan]
    timeout: 15m
    task:
      target: "{{target}}"
      depth: full

  - id: vuln-scan
    type: agent
    agent: vulnerability-scanner
    depends_on: [service-enum]
    timeout: 30m
    task:
      severity_threshold: medium

constraints:
  max_duration: 1h
  checkpoint_interval: 5m
```

### Run the Mission

```bash
# Start the Gibson daemon
gibson daemon start

# Run the mission
gibson mission run recon-mission.yaml --target 192.168.1.0/24

# Monitor progress
gibson mission show <mission-id>

# View findings
gibson finding list --mission <mission-id>
```

### Docker Compose Development Setup

```yaml
# docker-compose.yaml
version: '3.8'

services:
  redis:
    image: redis/redis-stack:latest
    ports:
      - "6379:6379"
      - "8001:8001"
    volumes:
      - redis-data:/data

  neo4j:
    image: neo4j:5-community
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      NEO4J_AUTH: neo4j/password
    volumes:
      - neo4j-data:/data

  etcd:
    image: quay.io/coreos/etcd:v3.5.18
    ports:
      - "2379:2379"
    command:
      - etcd
      - --advertise-client-urls=http://0.0.0.0:2379
      - --listen-client-urls=http://0.0.0.0:2379

volumes:
  redis-data:
  neo4j-data:
```

```bash
# Start all services
docker-compose up -d

# Build and run Gibson
make build
./bin/gibson daemon start
```

## Mission YAML Schema

### Top-Level Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Mission name |
| `description` | string | No | Mission description |
| `version` | string | No | Semantic version |
| `target` | any | No | Free-form target (string, object, or complex structure) |
| `nodes` | list | Yes | Workflow nodes |
| `edges` | list | No | Explicit edges (optional, use `depends_on` instead) |
| `entry_points` | list | No | Starting node IDs |
| `exit_points` | list | No | Terminal node IDs |
| `metadata` | map | No | Custom key-value metadata |
| `dependencies` | object | No | Required agents/tools/plugins |
| `constraints` | object | No | Execution constraints |

### Node Definition

```yaml
nodes:
  - id: unique-node-id          # Required: unique identifier
    type: agent                  # Required: node type
    name: "Human-readable name"  # Optional: display name
    description: "What this node does"

    # Agent-specific fields (type: agent)
    agent: agent-name            # Agent to execute
    task:                        # Task configuration
      target: "{{target}}"
      custom_param: value

    # Tool-specific fields (type: tool)
    tool: tool-name              # Tool to execute
    tool_input:                  # Tool parameters
      param1: value1

    # Plugin-specific fields (type: plugin)
    plugin: plugin-name          # Plugin to call
    plugin_method: method-name   # Method to invoke
    plugin_params:               # Method parameters
      param1: value1

    # Common fields
    depends_on: [other-node-id]  # Dependencies (creates edges)
    timeout: 10m                 # Node execution timeout
    retry_policy:                # Retry configuration
      max_retries: 3
      backoff_strategy: exponential
      initial_delay: 1s
      max_delay: 30s
      multiplier: 2.0
    data_policy:                 # Data sharing configuration
      output_scope: mission      # Where output is stored
      input_scope: mission       # Where to read data from
      reuse: skip                # Reuse behavior
    metadata:                    # Custom node metadata
      priority: high
```

### Node Types

| Type | Description | Required Fields |
|------|-------------|-----------------|
| `agent` | Runs an autonomous agent | `agent`, optionally `task` |
| `tool` | Executes a stateless tool | `tool`, optionally `tool_input` |
| `plugin` | Calls a plugin method | `plugin`, `plugin_method` |
| `condition` | Conditional branching | `condition` expression |
| `parallel` | Parallel execution group | `sub_nodes` list |
| `join` | Join point for parallel branches | `depends_on` |

### Retry Policy

```yaml
retry_policy:
  max_retries: 3                 # Maximum retry attempts
  backoff_strategy: exponential  # constant, linear, or exponential
  initial_delay: 1s              # Delay before first retry
  max_delay: 1m                  # Maximum delay (exponential only)
  multiplier: 2.0                # Delay multiplier (exponential only)
```

**Backoff Strategies:**
- `constant`: Same delay for all retries
- `linear`: `delay * (attempt + 1)`
- `exponential`: `min(initial_delay * multiplier^attempt, max_delay)`

### Data Policy

Controls how node data is shared across the mission:

```yaml
data_policy:
  output_scope: mission          # Where to store output
  input_scope: mission           # Where to read input from
  reuse: skip                    # Reuse behavior
```

| Scope | Description |
|-------|-------------|
| `mission` | Shared within the mission definition |
| `mission_run` | Isolated to this specific run |
| `global` | Shared across all missions |

| Reuse | Description |
|-------|-------------|
| `skip` | Skip execution if output already exists |
| `always` | Always use cached output if available |
| `never` | Never reuse, always execute fresh |

### Constraints

```yaml
constraints:
  max_duration: 2h               # Maximum mission duration
  checkpoint_interval: 5m        # How often to checkpoint state
  max_findings: 1000             # Stop after N findings
  severity_threshold: high       # Minimum severity to trigger action
  severity_action: pause         # Action on threshold: pause or fail
  require_evidence: true         # Findings must include evidence
  max_tokens: 100000             # LLM token budget
  max_cost: 10.00                # LLM cost budget (USD)
```

### Targets

Targets are **free-form** - there's no enforced schema. The target is templated and passed through to agents, so you can target anything: networks, APIs, smart contracts, cloud accounts, etc.

```yaml
# Simple string target
target: "192.168.1.0/24"

# Network target with metadata
target:
  connection: "192.168.1.0/24"
  type: network
  scope: internal

# API target
target:
  base_url: "https://api.example.com"
  auth_token: "${API_TOKEN}"
  openapi_spec: "./spec.yaml"

# Smart contract target
target:
  chain: ethereum
  contract_address: "0x1234abcd..."
  rpc_url: "https://mainnet.infura.io/v3/${INFURA_KEY}"

# Cloud infrastructure target
target:
  provider: aws
  account_id: "123456789012"
  regions: [us-east-1, us-west-2]
```

Reference targets in nodes via templating:

```yaml
nodes:
  - id: scan
    type: agent
    agent: network-recon
    task:
      target: "{{target}}"              # Pass entire target object
      network: "{{target.connection}}"  # Or specific fields
```

Each agent defines what target fields it expects. Gibson doesn't validate target structure - it templates and passes through to agents.

### Dependencies

Auto-install required components before mission execution:

```yaml
dependencies:
  agents:
    - network-recon
    - service-fingerprinter
  tools:
    - nmap
    - httpx
  plugins:
    - slack-notifier
```

## Orchestrator Decision Actions

The LLM orchestrator can take 12 different actions based on mission state:

### Execution Actions

| Action | Description | Required Fields |
|--------|-------------|-----------------|
| `execute_agent` | Run a workflow node | `target_node_id` |
| `skip_agent` | Skip a node's execution | `target_node_id` |
| `modify_params` | Modify node parameters before execution | `target_node_id`, `modifications` |
| `retry` | Retry a failed node | `target_node_id` |
| `spawn_agent` | Dynamically create and add a new node | `spawn_config` |

### Terminal Actions

| Action | Description | Required Fields |
|--------|-------------|-----------------|
| `complete` | Mission completed successfully | `stop_reason` |
| `abort` | Emergency stop due to safety violation | `abort_reason`, `abort_severity` |

### Control Actions

| Action | Description | Required Fields |
|--------|-------------|-----------------|
| `request_approval` | Pause for human approval | `target_node_id`, `approval_context` |
| `escalate` | Escalate to humans or specialists | `escalation_level`, `escalation_urgency`, `escalation_context` |
| `rollback` | Revert to a previous checkpoint | `checkpoint_id` or `rollback_to_node` |

### Reflection Actions

| Action | Description | Required Fields |
|--------|-------------|-----------------|
| `reflect` | Self-evaluate current strategy | `reflection_scope` |
| `recall` | Query memory for relevant context | `recall_query`, `recall_memory_tier` |

### Decision Structure

```go
type Decision struct {
    Reasoning       string                  // Chain-of-thought explanation
    Action          DecisionAction          // Action to take
    TargetNodeID    string                  // Target node (if applicable)
    Modifications   map[string]interface{}  // Parameter modifications
    SpawnConfig     *SpawnNodeConfig        // For spawn_agent action
    Confidence      float64                 // 0.0-1.0 confidence level
    StopReason      string                  // Why workflow is complete
    // ... additional fields for specific actions
}
```

## State Management

### Redis-Backed State

All mission state is stored in Redis Stack:

- **Mission Store**: Mission definitions and metadata (RedisJSON)
- **Mission Run Store**: Execution state per run (RedisJSON)
- **Checkpoint Store**: Pause/resume checkpoints (RedisJSON with TTL)
- **Memory Store**: Agent memory with full-text search (RediSearch)
- **Event Streams**: Durable event processing (Redis Streams)

### Memory Continuity Modes

Control how agent memory is shared across mission runs:

| Mode | Description |
|------|-------------|
| `isolated` | Each run has completely isolated memory (default) |
| `inherit` | Read-only access to previous run's memory |
| `shared` | Shared memory pool across all runs |

### Checkpointing

Missions automatically checkpoint state for crash recovery:

```yaml
constraints:
  checkpoint_interval: 5m  # Checkpoint every 5 minutes
```

**Checkpoint Contents:**
- Current node being executed
- All completed node outputs
- In-progress node state (retry count, start time)
- Working and mission memory snapshots
- Finding IDs discovered so far
- Execution metrics
- DAG traversal position

**Operations:**
```bash
# Pause a running mission (creates checkpoint)
gibson mission pause <mission-id>

# Resume from checkpoint
gibson mission resume <mission-id>
```

## GraphRAG Integration

Missions automatically populate a Neo4j knowledge graph:

```
┌─────────────────────────────────────────────────────────────────┐
│                      Knowledge Graph                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   (Host)──[:HAS_PORT]──►(Port)──[:RUNS_SERVICE]──►(Service)     │
│     │                                                  │         │
│     └──[:RESOLVED_TO]──►(Domain)                      │         │
│                                                        │         │
│   (Vulnerability)◄──[:AFFECTS]───────────────────────┘         │
│         │                                                        │
│         └──[:DISCOVERED_BY]──►(Agent)                           │
│                                    │                             │
│                                    └──[:PART_OF]──►(Mission)    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

All tools return `DiscoveryResult` (field 100) containing:
- **Entities**: Hosts, ports, services, domains, vulnerabilities
- **Relationships**: Connections between entities
- **Properties**: Metadata for filtering and analysis

## Observability

### OpenTelemetry Tracing

Every operation is traced:

```yaml
tracing:
  enabled: true
  endpoint: otel-collector:4317
```

**Trace Spans:**
- Mission lifecycle (start, checkpoint, complete)
- Agent task execution
- LLM request/response with token counts
- Tool invocations
- Memory operations

### Prometheus Metrics

```yaml
metrics:
  enabled: true
  port: 9090
```

**Key Metrics:**
- `gibson_missions_total{status}` - Mission execution counts
- `gibson_agent_executions_total{agent,status}` - Agent task counts
- `gibson_tool_calls_total{tool,status}` - Tool invocation counts
- `gibson_llm_tokens_total{provider,model}` - LLM token usage
- `gibson_orchestrator_decisions_total{action}` - Decision counts

## CLI Reference

```bash
# Mission operations
gibson mission run <file> [--target <target>]   # Execute mission
gibson mission list                              # List all missions
gibson mission show <id>                         # Show mission progress
gibson mission pause <id>                        # Checkpoint and pause
gibson mission resume <id>                       # Resume from checkpoint
gibson mission cancel <id>                       # Cancel execution
gibson mission delete <id>                       # Delete mission record

# Finding operations
gibson finding list [--mission <id>]             # List findings
gibson finding show <id>                         # Show finding details
gibson finding export --format json              # Export findings

# Mission templates
gibson mission validate <file>                   # Validate YAML syntax
gibson mission graph <file>                      # Visualize DAG
```

## Configuration Reference

### Core Settings

```yaml
core:
  home_dir: ~/.gibson              # Installation directory
  data_dir: ~/.gibson/data         # Data storage
  cache_dir: ~/.gibson/cache       # Cache directory
  parallel_limit: 10               # Max parallel operations
  timeout: 5m                      # Global timeout
  debug: false                     # Debug mode
```

### Daemon Settings

```yaml
daemon:
  grpc_address: "0.0.0.0:50002"    # gRPC API address

health:
  port: 8080                       # Health endpoint port

shutdown:
  timeout: 30s                     # Total shutdown timeout
  drain_timeout: 10s               # Request drain timeout
  checkpoint_timeout: 5s           # Per-mission checkpoint timeout
  agent_timeout: 15s               # Agent disconnect timeout
```

### Redis Configuration

```yaml
redis:
  # Standalone mode
  url: "redis://localhost:6379"
  password: "${REDIS_PASSWORD}"
  database: 0

  # Connection pool
  pool_size: 10
  connect_timeout: 5s
  read_timeout: 3s
  write_timeout: 3s
  max_retries: 3

  # Cluster mode
  cluster_mode: false
  cluster_addrs:
    - "node1:6379"
    - "node2:6379"
    - "node3:6379"

  # Sentinel mode
  sentinel_master: ""
  sentinel_addrs:
    - "sentinel1:26379"
    - "sentinel2:26379"

  # TLS
  tls_enabled: false
  tls_cert_file: ""
  tls_key_file: ""
  tls_ca_file: ""
```

### Service Registry (etcd)

```yaml
registry:
  type: embedded                   # embedded or etcd
  data_dir: ~/.gibson/etcd-data
  listen_address: "0.0.0.0:2379"
  namespace: gibson
  ttl: 30s
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    ca_file: ""
```

### GraphRAG (Neo4j)

```yaml
graphrag:
  enabled: true
  neo4j:
    uri: "bolt://localhost:7687"
    username: neo4j
    password: "${NEO4J_PASSWORD}"
    max_connections: 10
    connection_timeout: 30s
```

### LLM Providers

```yaml
llm:
  default_provider: ""             # anthropic, openai, ollama
  # Set via environment variables:
  # ANTHROPIC_API_KEY
  # OPENAI_API_KEY
  # OLLAMA_HOST (default: http://localhost:11434)
```

### Observability

```yaml
tracing:
  enabled: false
  endpoint: "${OTEL_EXPORTER_OTLP_ENDPOINT}"

metrics:
  enabled: false
  port: 9090

logging:
  level: info                      # debug, info, warn, error, fatal
  format: json                     # json or text
```

### Security

```yaml
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
```

### Embedder

```yaml
embedder:
  provider: native                 # native or openai
  model: all-minilm-l6-v2
  # For OpenAI:
  # provider: openai
  # model: text-embedding-3-small
  # api_key: ${OPENAI_API_KEY}
```

### Agent Registration

```yaml
registration:
  enabled: false
  port: 50100
  auth_token: ""
  heartbeat_timeout: 30s

callback:
  enabled: true
  listen_address: "0.0.0.0:50001"
  advertise_address: ""
```

## Examples

### Security Reconnaissance Mission

```yaml
name: "Security Reconnaissance"
description: "Comprehensive security assessment workflow"
version: "1.0.0"

dependencies:
  agents:
    - network-recon
    - tech-stack-fingerprint
    - vulnerability-scanner
  tools:
    - nmap
    - httpx
    - nuclei

nodes:
  - id: passive-recon
    type: agent
    agent: network-recon
    timeout: 15m
    task:
      target: "{{target}}"
      scan_type: passive
    data_policy:
      output_scope: mission
      reuse: skip

  - id: active-scan
    type: agent
    agent: network-recon
    depends_on: [passive-recon]
    timeout: 30m
    task:
      target: "{{target}}"
      scan_type: active

  - id: fingerprint
    type: agent
    agent: tech-stack-fingerprint
    depends_on: [active-scan]
    timeout: 20m
    retry_policy:
      max_retries: 2
      backoff_strategy: exponential
      initial_delay: 5s

  - id: vuln-scan
    type: agent
    agent: vulnerability-scanner
    depends_on: [fingerprint]
    timeout: 1h
    task:
      severity_threshold: medium

constraints:
  max_duration: 3h
  checkpoint_interval: 10m
  max_findings: 500
```

### Parallel Scanning Mission

```yaml
name: "Parallel Security Scan"
version: "1.0.0"

nodes:
  - id: discovery
    type: agent
    agent: network-recon
    timeout: 10m

  - id: web-scan
    type: agent
    agent: web-scanner
    depends_on: [discovery]
    timeout: 30m

  - id: ssh-audit
    type: agent
    agent: ssh-auditor
    depends_on: [discovery]
    timeout: 15m

  - id: dns-enum
    type: agent
    agent: dns-enumerator
    depends_on: [discovery]
    timeout: 10m

  - id: aggregate
    type: join
    depends_on: [web-scan, ssh-audit, dns-enum]

  - id: report
    type: agent
    agent: report-generator
    depends_on: [aggregate]
    timeout: 5m

constraints:
  max_duration: 2h
```

### Conditional Workflow

```yaml
name: "Conditional Assessment"
version: "1.0.0"

nodes:
  - id: initial-scan
    type: agent
    agent: network-recon

  - id: check-web
    type: condition
    depends_on: [initial-scan]
    condition: "nodes.initial-scan.output.has_web_services == true"

  - id: web-deep-scan
    type: agent
    agent: web-vulnerability-scanner
    depends_on: [check-web]
    timeout: 1h

  - id: api-testing
    type: agent
    agent: api-fuzzer
    depends_on: [check-web]
    timeout: 45m
```
