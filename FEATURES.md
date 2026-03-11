# Gibson Features

Gibson is a Kubernetes-native AI agent framework for building, deploying, and operating autonomous agents at scale. This document provides a comprehensive overview of all features available in the Gibson ecosystem.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Gibson Core (Daemon)](#gibson-core-daemon)
  - [Daemon & Server](#daemon--server)
  - [Orchestration](#orchestration)
  - [Mission Management](#mission-management)
  - [State Management](#state-management)
  - [Registry & Service Discovery](#registry--service-discovery)
  - [GraphRAG Knowledge Graph](#graphrag-knowledge-graph)
  - [Finding & Reporting](#finding--reporting)
  - [Attack Framework](#attack-framework)
  - [Observability](#observability)
  - [Guardrails & Safety](#guardrails--safety)
  - [CLI Commands](#cli-commands)
  - [Remote Connectivity](#remote-connectivity)
  - [CI/CD Integration](#cicd-integration)
- [Gibson SDK](#gibson-sdk)
  - [Core Framework](#core-framework)
  - [Agent Development](#agent-development)
  - [Tool Development](#tool-development)
  - [Plugin Development](#plugin-development)
  - [LLM Abstraction](#llm-abstraction)
  - [Three-Tier Memory](#three-tier-memory)
  - [GraphRAG Client](#graphrag-client)
  - [Agent Harness](#agent-harness)
  - [Finding Management](#finding-management)
  - [Tool Worker System](#tool-worker-system)
  - [Serving & Deployment](#serving--deployment)
  - [Utilities](#utilities)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Kubernetes Cluster                              │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                           Gibson Daemon                                 │  │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │  │
│  │   │Orchestrator │  │  Registry   │  │   Harness   │  │Health Probes│   │  │
│  │   │ (LLM-driven)│  │   (etcd)    │  │  Factory    │  │/healthz/readyz  │  │
│  │   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │  │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │  │
│  │   │   Mission   │  │    State    │  │  GraphRAG   │  │Observability│   │  │
│  │   │   Manager   │  │   (Redis)   │  │  (Neo4j)    │  │   (OTel)    │   │  │
│  │   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                      │                                        │
│       ┌──────────────────────────────┼──────────────────────────────┐        │
│       ▼                              ▼                              ▼        │
│  ┌─────────────┐              ┌─────────────┐              ┌─────────────┐   │
│  │   Agents    │              │    Tools    │              │   Plugins   │   │
│  │  (SDK-built)│              │  (Workers)  │              │ (Services)  │   │
│  └─────────────┘              └─────────────┘              └─────────────┘   │
│                                                                               │
│  ┌────────────────────────────────────────────────────────────────────────┐  │
│  │                         Infrastructure                                  │  │
│  │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │  │
│  │   │    etcd     │  │ Redis Stack │  │   Neo4j     │  │   SigNoz    │   │  │
│  │   │  Registry   │  │State & Queue│  │  GraphRAG   │  │Observability│   │  │
│  │   └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │  │
│  └────────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Gibson Core (Daemon)

The Gibson daemon is the central orchestration engine that coordinates agents, manages missions, and provides infrastructure services.

### Daemon & Server

The daemon provides the runtime environment for mission execution and agent coordination.

#### gRPC API Server

- **Port**: 50002 (configurable)
- **Protocol**: gRPC with Protocol Buffer definitions
- **Authentication**: mTLS support for secure communication
- **Features**:
  - Mission lifecycle management (create, run, pause, resume, cancel)
  - Agent and tool invocation
  - Finding submission and retrieval
  - Real-time event streaming
  - Log tailing and aggregation

#### Health Probes

Kubernetes-native health endpoints for liveness and readiness checks:

| Endpoint | Purpose | Checks |
|----------|---------|--------|
| `/healthz` | Liveness probe | Daemon process is alive and responsive |
| `/readyz` | Readiness probe | All dependencies healthy (Redis, Neo4j, etcd) |

```yaml
# Kubernetes probe configuration
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 15

readinessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

#### Graceful Shutdown

Multi-phase shutdown process for zero data loss:

1. **Stop Accepting Work** - Health probes return unhealthy
2. **Checkpoint Active Missions** - Persist state to Redis
3. **Drain Agent Queues** - Wait for in-flight operations
4. **Close Connections** - Clean up gRPC, Redis, etcd, Neo4j connections

```yaml
# Kubernetes termination configuration
terminationGracePeriodSeconds: 60
```

#### Process Management

- **PID File**: Written to `~/.gibson/daemon.pid` for process tracking
- **Info File**: `~/.gibson/daemon.json` contains gRPC address for client discovery
- **Signal Handling**: SIGTERM triggers graceful shutdown, SIGINT for immediate stop

---

### Orchestration

The orchestrator is the brain of Gibson, using LLMs to make decisions about mission execution.

#### Observe-Think-Act Control Loop

```
┌─────────────────────────────────────────────────────────────┐
│                    Orchestrator Loop                         │
│                                                              │
│   ┌──────────┐     ┌──────────┐     ┌──────────┐            │
│   │ OBSERVE  │────▶│  THINK   │────▶│   ACT    │            │
│   │          │     │  (LLM)   │     │          │            │
│   │ - State  │     │ - Reason │     │ - Execute│            │
│   │ - Events │     │ - Plan   │     │ - Invoke │            │
│   │ - Results│     │ - Decide │     │ - Update │            │
│   └──────────┘     └──────────┘     └──────────┘            │
│        ▲                                   │                 │
│        └───────────────────────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

#### Decision Event Logging

Every orchestrator decision is logged for transparency and debugging:

```json
{
  "event": "orchestrator_decision",
  "timestamp": "2024-01-15T10:30:00Z",
  "mission_id": "m-abc123",
  "decision": "invoke_agent",
  "reasoning": "Target reconnaissance complete, proceeding to vulnerability scan",
  "agent": "vuln-scanner",
  "confidence": 0.92
}
```

#### Orchestration Controls

| Control | Description | Default |
|---------|-------------|---------|
| `max_iterations` | Maximum orchestrator loops | 100 |
| `token_budget` | Maximum tokens per mission | Unlimited |
| `concurrency_limit` | Parallel agent executions | 5 |
| `timeout` | Mission timeout duration | 30m |
| `decision_timeout` | Per-decision LLM timeout | 30s |

#### Orchestrator Status Codes

| Status | Description |
|--------|-------------|
| `completed` | Mission finished successfully |
| `failed` | Mission failed with error |
| `max_iterations` | Iteration limit reached |
| `timeout` | Mission timeout exceeded |
| `cancelled` | User-initiated cancellation |
| `budget_exceeded` | Token budget exhausted |
| `concurrency_limit` | Too many parallel executions |

---

### Mission Management

Missions are the primary unit of work in Gibson, defining what agents should accomplish.

#### Mission Lifecycle

```
┌─────────┐     ┌─────────┐     ┌───────────┐
│ PENDING │────▶│ RUNNING │────▶│ COMPLETED │
└─────────┘     └────┬────┘     └───────────┘
                     │
                     ├─────────▶ FAILED
                     │
                     ├─────────▶ CANCELLED
                     │
                     └─────────▶ PAUSED ──────▶ RUNNING (resume)
```

#### Mission Definition (YAML)

```yaml
name: "API Security Assessment"
version: "1.0.0"
description: "Comprehensive API security testing"

# Target specification
target:
  type: http_api
  url: https://api.example.com
  auth:
    type: bearer
    token_env: API_TOKEN

# Workflow nodes (DAG)
nodes:
  reconnaissance:
    type: agent
    agent: api-discovery
    goal: "Discover all API endpoints and their schemas"

  vulnerability-scan:
    type: agent
    agent: vuln-scanner
    depends_on: [reconnaissance]
    goal: "Scan discovered endpoints for vulnerabilities"

  exploit-verification:
    type: agent
    agent: exploit-verifier
    depends_on: [vulnerability-scan]
    goal: "Verify exploitability of discovered vulnerabilities"

# Mission constraints
constraints:
  max_duration: 2h
  max_tokens: 100000
  max_cost: 10.00
  max_findings: 50

# Memory configuration
memory:
  continuity: inherit  # isolated | inherit | shared
```

#### Mission Constraints

| Constraint | Description | Example |
|------------|-------------|---------|
| `max_duration` | Maximum mission runtime | `2h`, `30m` |
| `max_tokens` | Token budget across all LLM calls | `100000` |
| `max_cost` | Cost limit in USD | `10.00` |
| `max_findings` | Stop after N findings | `50` |
| `checkpoint_interval` | Auto-checkpoint frequency | `5m` |

#### Checkpointing & Resume

Missions can be paused and resumed from checkpoints:

```bash
# Pause a running mission
gibson mission pause m-abc123

# Resume from checkpoint
gibson mission resume m-abc123

# List checkpoints
gibson mission checkpoints m-abc123
```

Checkpoint data includes:
- Current workflow node
- Agent execution state
- Memory contents
- Finding count
- Token usage

#### Mission Hierarchy

Missions can spawn sub-missions for complex workflows:

```yaml
nodes:
  parallel-scans:
    type: mission
    mission:
      name: "Parallel Endpoint Scan"
      # Sub-mission inherits parent context
      nodes:
        - scan-auth-endpoints
        - scan-data-endpoints
        - scan-admin-endpoints
```

---

### State Management

Gibson uses Redis for distributed state management, enabling horizontal scaling and fault tolerance.

#### State Storage

| Store | Purpose | TTL |
|-------|---------|-----|
| `missions:{id}` | Mission metadata and status | None |
| `missions:{id}:state` | Current execution state | None |
| `missions:{id}:checkpoints` | Checkpoint history | 7 days |
| `agents:{name}:state` | Agent execution state | 1 hour |
| `tools:{name}:queue` | Tool work queue | None |

#### Checkpoint Recovery

```go
// Automatic checkpoint on pause
daemon.PauseMission(ctx, missionID)
// State persisted to Redis: missions:{id}:checkpoints:{timestamp}

// Resume from latest checkpoint
daemon.ResumeMission(ctx, missionID)
// State restored, execution continues from checkpoint
```

#### Distributed Coordination

- **Leader Election**: etcd-based leader election for singleton operations
- **Distributed Locks**: Redis-based locks for concurrent access control
- **Event Bus**: Redis pub/sub for real-time event distribution

---

### Registry & Service Discovery

Gibson uses etcd for service discovery, enabling dynamic agent and tool registration.

#### Embedded vs External etcd

| Mode | Use Case | Configuration |
|------|----------|---------------|
| Embedded | Development, single-node | `registry.type: embedded` |
| External | Production, HA | `registry.type: etcd` with endpoints |

```yaml
# Embedded etcd (development)
registry:
  type: embedded
  data_dir: ~/.gibson/etcd-data
  listen_address: 0.0.0.0:2379

# External etcd (production)
registry:
  type: etcd
  endpoints:
    - etcd-0.etcd:2379
    - etcd-1.etcd:2379
    - etcd-2.etcd:2379
```

#### Service Registration

Agents and tools automatically register on startup:

```
/gibson/agents/{name}/{instance-id}
  ├── address: "10.0.0.5:50051"
  ├── version: "1.2.0"
  ├── capabilities: ["prompt_injection", "jailbreak"]
  ├── health: "healthy"
  └── last_heartbeat: "2024-01-15T10:30:00Z"

/gibson/tools/{name}/{instance-id}
  ├── address: "10.0.0.6:50052"
  ├── version: "1.0.0"
  ├── input_type: "nmap.ScanRequest"
  └── output_type: "nmap.ScanResponse"
```

#### Health Monitoring

- **Heartbeat Interval**: 10 seconds (configurable)
- **Heartbeat Timeout**: 30 seconds before marking unhealthy
- **Auto-Deregistration**: 60 seconds of no heartbeat

#### Circuit Breaker

Built-in circuit breaker for unreliable services:

| State | Behavior |
|-------|----------|
| Closed | Normal operation, requests pass through |
| Open | Requests fail fast, no backend calls |
| Half-Open | Limited requests to test recovery |

```yaml
registry:
  circuit_breaker:
    failure_threshold: 5
    recovery_timeout: 30s
    half_open_requests: 3
```

#### gRPC Connection Pooling

- **Pool Size**: Configurable per-service connection pool
- **Idle Timeout**: Connections closed after inactivity
- **Health Checks**: Periodic connection health verification

---

### GraphRAG Knowledge Graph

Gibson uses Neo4j for persistent knowledge storage, enabling cross-mission intelligence and semantic search.

#### Knowledge Graph Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    Knowledge Graph                           │
│                                                              │
│   Domain ──[HAS_SUBDOMAIN]──▶ Subdomain                     │
│      │                            │                          │
│      └──[RESOLVES_TO]─────────────┼──▶ Host                 │
│                                   │       │                  │
│                                   │       └──[HAS_PORT]──▶ Port
│                                   │                    │     │
│                                   │                    │     │
│   Finding ◀──[AFFECTS]────────────┘                    │     │
│      │                                                 │     │
│      └──[USES_TECHNIQUE]──▶ Technique                  │     │
│                                   │                    │     │
│                                   └──[PART_OF]──▶ Tactic    │
│                                                              │
│   Endpoint ◀──[RUNS_SERVICE]───────────────────────────┘    │
│      │                                                       │
│      └──[VULNERABLE_TO]──▶ Vulnerability                    │
└─────────────────────────────────────────────────────────────┘
```

#### Node Types

| Type | Description | Key Properties |
|------|-------------|----------------|
| `Domain` | DNS domain | name, registrar, created_at |
| `Subdomain` | DNS subdomain | name, cname, discovered_at |
| `Host` | IP address or hostname | ip, hostname, os, geo |
| `Port` | Network port | number, protocol, state |
| `Service` | Running service | name, version, banner |
| `Endpoint` | API endpoint | path, method, params |
| `Finding` | Security finding | severity, category, status |
| `Technique` | Attack technique | mitre_id, name, tactic |
| `Vulnerability` | CVE/weakness | cve_id, cvss, description |

#### Relationship Types

| Relationship | From | To | Description |
|--------------|------|-----|-------------|
| `HAS_SUBDOMAIN` | Domain | Subdomain | Domain contains subdomain |
| `RESOLVES_TO` | Subdomain | Host | DNS resolution |
| `HAS_PORT` | Host | Port | Open port on host |
| `RUNS_SERVICE` | Port | Service | Service on port |
| `HAS_ENDPOINT` | Service | Endpoint | API endpoint |
| `AFFECTS` | Finding | Any | Finding affects entity |
| `USES_TECHNIQUE` | Finding | Technique | Attack technique used |
| `VULNERABLE_TO` | Endpoint | Vulnerability | Endpoint vulnerability |
| `LEADS_TO` | Finding | Finding | Finding chain |

#### Entity Deduplication

Automatic UUID-based deduplication prevents duplicate entities:

```go
// Same entity discovered by multiple agents
agent1.StoreNode(ctx, &Node{Type: "host", Properties: {"ip": "10.0.0.5"}})
agent2.StoreNode(ctx, &Node{Type: "host", Properties: {"ip": "10.0.0.5"}})
// Result: Single node with merged properties
```

#### Hybrid Queries

Combine semantic similarity with graph structure:

```go
results, _ := graphrag.Query(ctx, QueryOptions{
    Text:              "SQL injection vulnerabilities in authentication endpoints",
    NodeTypes:         []string{"finding", "endpoint"},
    SimilarityWeight:  0.6,  // 60% semantic similarity
    StructuralWeight:  0.4,  // 40% graph connectivity
    MaxHops:           3,
    Limit:             10,
})
```

#### Mission Scoping

Knowledge graphs are scoped to missions with optional sharing:

| Mode | Behavior |
|------|----------|
| `isolated` | Mission has its own knowledge graph |
| `inherit` | Read access to parent mission's graph |
| `shared` | Full read/write access to shared graph |

#### Taxonomy Validation

YAML-driven taxonomy ensures consistent node and relationship types:

```yaml
# taxonomy.yaml
node_types:
  - name: host
    required_properties: [ip]
    optional_properties: [hostname, os, geo]

  - name: finding
    required_properties: [title, severity, category]
    optional_properties: [description, remediation]

relationship_types:
  - name: AFFECTS
    from_types: [finding]
    to_types: [host, endpoint, service]
```

---

### Finding & Reporting

Gibson provides comprehensive security finding management with industry-standard export formats.

#### Finding Categories

| Category | Description | Example |
|----------|-------------|---------|
| `jailbreak` | LLM jailbreak/bypass | System prompt extraction |
| `prompt_injection` | Prompt injection attack | Indirect prompt injection |
| `data_extraction` | Unauthorized data access | PII extraction |
| `privilege_escalation` | Elevated access | Admin role bypass |
| `dos` | Denial of service | Resource exhaustion |
| `model_manipulation` | Model behavior change | Fine-tuning attack |
| `information_disclosure` | Information leak | Error message disclosure |

#### Finding Structure

```json
{
  "id": "f-abc123",
  "title": "SQL Injection in Login Endpoint",
  "description": "The /api/auth/login endpoint is vulnerable to SQL injection...",
  "category": "data_extraction",
  "severity": "critical",
  "status": "open",
  "risk_score": 9.5,

  "target": {
    "type": "endpoint",
    "url": "https://api.example.com/auth/login"
  },

  "evidence": {
    "request": "POST /api/auth/login HTTP/1.1\n...",
    "response": "HTTP/1.1 500 Internal Server Error\n...",
    "payload": "' OR '1'='1",
    "screenshot": "base64://..."
  },

  "mitre": {
    "technique_id": "T1190",
    "technique_name": "Exploit Public-Facing Application",
    "tactic": "Initial Access"
  },

  "remediation": "Use parameterized queries or prepared statements...",

  "reproduction_steps": [
    "Navigate to login page",
    "Enter payload in username field",
    "Submit form",
    "Observe SQL error in response"
  ],

  "metadata": {
    "mission_id": "m-xyz789",
    "agent": "sql-scanner",
    "discovered_at": "2024-01-15T10:30:00Z",
    "confidence": 0.95
  }
}
```

#### Finding Status Lifecycle

```
┌──────┐     ┌───────────┐     ┌──────────┐
│ OPEN │────▶│ CONFIRMED │────▶│ RESOLVED │
└──────┘     └───────────┘     └──────────┘
    │
    └────────▶ FALSE_POSITIVE
```

#### Risk Scoring

CVSS-like risk scoring (0.0 - 10.0):

| Severity | Score Range | Color |
|----------|-------------|-------|
| Critical | 9.0 - 10.0 | Red |
| High | 7.0 - 8.9 | Orange |
| Medium | 4.0 - 6.9 | Yellow |
| Low | 0.1 - 3.9 | Blue |
| Info | 0.0 | Gray |

#### Export Formats

| Format | Use Case | Command |
|--------|----------|---------|
| SARIF | GitHub/GitLab security dashboards | `gibson finding export --format sarif` |
| JSON | Programmatic processing | `gibson finding export --format json` |
| CSV | Spreadsheet analysis | `gibson finding export --format csv` |
| HTML | Web viewing | `gibson finding export --format html` |
| Markdown | Documentation | `gibson finding export --format markdown` |

#### SARIF Export Example

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Gibson",
        "version": "1.0.0",
        "informationUri": "https://github.com/zero-day-ai/gibson"
      }
    },
    "results": [{
      "ruleId": "sql-injection",
      "level": "error",
      "message": {
        "text": "SQL Injection in Login Endpoint"
      },
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "https://api.example.com/auth/login"
          }
        }
      }]
    }]
  }]
}
```

#### Finding Aggregation

Query findings across missions:

```bash
# All critical findings from last 7 days
gibson finding list --severity critical --since 7d

# Findings by category
gibson finding list --category prompt_injection

# Export for specific mission
gibson finding export --mission m-abc123 --format sarif
```

---

### Attack Framework

Gibson provides an ephemeral attack execution framework for quick security testing without full mission setup.

#### Attack Execution

```bash
# Quick attack against a target
gibson attack \
  --target my-api \
  --agent api-fuzzer \
  --max-findings 10 \
  --timeout 5m
```

#### Attack Options

| Option | Description | Default |
|--------|-------------|---------|
| `--target` | Stored target name | Required |
| `--agent` | Agent to execute | Required |
| `--max-findings` | Stop after N findings | Unlimited |
| `--max-turns` | Maximum agent turns | 20 |
| `--timeout` | Attack timeout | 10m |
| `--persist` | Always save findings | false |
| `--dry-run` | Validate without executing | false |

#### Payload Management

Pre-built attack payloads with parameterization:

```yaml
# payload definition
name: "Basic SQL Injection"
category: data_extraction
technique_id: T1190

template: |
  ' OR '{{condition}}'='{{condition}}

parameters:
  condition:
    type: string
    default: "1"

success_indicators:
  - type: regex
    pattern: "(SQL|syntax|query|mysql|postgresql)"
  - type: http_status
    codes: [500, 502, 503]
```

#### Payload Categories

| Category | Description |
|----------|-------------|
| `jailbreak` | LLM jailbreak attempts |
| `prompt_injection` | Prompt injection payloads |
| `data_extraction` | Data exfiltration tests |
| `dos` | Resource exhaustion |
| `model_manipulation` | Model behavior modification |
| `privilege_escalation` | Access control bypass |
| `rag_poisoning` | RAG system attacks |
| `encoding_bypass` | Encoding-based evasion |

#### Payload Chaining

Execute payloads in sequence:

```yaml
chain:
  - payload: reconnaissance
    extract:
      - name: endpoints
        from: response
        pattern: "/api/[a-z]+"

  - payload: injection_test
    for_each: endpoints
    template: "{{endpoint}}?id=' OR 1=1--"
```

#### Attack Results

```json
{
  "status": "findings",
  "duration": "3m 45s",
  "turns": 12,
  "tokens_used": 15000,
  "findings": 3,
  "findings_by_severity": {
    "critical": 1,
    "high": 1,
    "medium": 1
  }
}
```

---

### Observability

Gibson provides comprehensive observability through OpenTelemetry integration.

#### OpenTelemetry Tracing

Full distributed tracing with W3C trace context propagation:

```
Trace: mission-execution
├── Span: orchestrator.decide
│   ├── Span: llm.complete (Anthropic)
│   │   └── Attributes: model, tokens, cost
│   └── Span: decision.log
├── Span: agent.invoke (api-scanner)
│   ├── Span: llm.complete
│   ├── Span: tool.call (httpx)
│   └── Span: finding.submit
└── Span: mission.checkpoint
```

#### GenAI Semantic Conventions

Token usage and cost tracking per OpenTelemetry GenAI spec:

| Attribute | Description |
|-----------|-------------|
| `gen_ai.system` | LLM provider (anthropic, openai) |
| `gen_ai.request.model` | Model name |
| `gen_ai.usage.prompt_tokens` | Input tokens |
| `gen_ai.usage.completion_tokens` | Output tokens |
| `gen_ai.usage.cost` | Estimated cost in USD |

#### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `gibson_missions_total` | Counter | Total missions by status |
| `gibson_agent_executions_total` | Counter | Agent executions by agent/status |
| `gibson_tool_calls_total` | Counter | Tool invocations by tool/status |
| `gibson_llm_tokens_total` | Counter | Token usage by provider/model |
| `gibson_llm_cost_total` | Counter | LLM cost by provider |
| `gibson_findings_total` | Counter | Findings by severity/category |
| `gibson_mission_duration_seconds` | Histogram | Mission duration distribution |
| `gibson_agent_turn_duration_seconds` | Histogram | Agent turn duration |

#### Structured Logging

JSON logging with trace correlation:

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "INFO",
  "message": "Agent execution completed",
  "trace_id": "abc123def456",
  "span_id": "789xyz",
  "component": "orchestrator",
  "mission_id": "m-abc123",
  "agent": "api-scanner",
  "duration_ms": 45000,
  "findings": 3
}
```

#### Sensitive Data Redaction

Automatic redaction of sensitive data in logs and traces:

```yaml
observability:
  redaction:
    patterns:
      - "(?i)(api[_-]?key|password|secret|token|bearer)[=:\\s]+\\S+"
      - "(?i)authorization:\\s*bearer\\s+\\S+"
    replacement: "[REDACTED]"
```

#### Configuration

```yaml
observability:
  tracing:
    enabled: true
    provider: otlp
    endpoint: http://otel-collector:4317
    service_name: gibson
    sample_rate: 1.0

  metrics:
    enabled: true
    provider: prometheus
    port: 9090

  logging:
    level: info
    format: json

  content_logging:
    enabled: true
    max_prompt_length: 10000
    max_completion_length: 10000
```

---

### Guardrails & Safety

Gibson includes built-in safety mechanisms to prevent misuse and ensure responsible operation.

#### Guardrail Types

| Type | Purpose | Example |
|------|---------|---------|
| `scope` | Target scope enforcement | Only test authorized domains |
| `content` | Output content filtering | Block harmful content generation |
| `rate` | Rate limiting | Max 100 requests/minute |
| `tool` | Tool usage restrictions | Disable destructive tools |
| `pii` | PII detection | Redact personal information |

#### Scope Validation

```yaml
guardrails:
  scope:
    allowed_domains:
      - "*.example.com"
      - "api.test.local"
    blocked_domains:
      - "*.google.com"
      - "*.microsoft.com"
    allowed_ip_ranges:
      - "10.0.0.0/8"
      - "192.168.0.0/16"
```

#### Rate Limiting

```yaml
guardrails:
  rate:
    global:
      requests_per_minute: 1000
    per_agent:
      requests_per_minute: 100
    per_tool:
      httpx:
        requests_per_minute: 60
      nmap:
        requests_per_minute: 10
```

#### PII Detection

Automatic detection and handling of personally identifiable information:

| PII Type | Action |
|----------|--------|
| Email addresses | Redact in logs, warn in findings |
| Phone numbers | Redact |
| SSN/Tax IDs | Block, alert |
| Credit cards | Block, alert |
| API keys | Redact |

#### Tool Restrictions

```yaml
guardrails:
  tools:
    blocked:
      - "rm"
      - "kubectl delete"
    require_confirmation:
      - "kubectl apply"
      - "terraform apply"
```

---

### CLI Commands

Gibson provides a comprehensive CLI for all operations.

#### Daemon Management

```bash
# Start daemon in foreground
gibson daemon start

# Start daemon in background
gibson daemon start --background

# Stop daemon gracefully
gibson daemon stop

# Check daemon status
gibson daemon status

# Restart daemon
gibson daemon restart
```

#### Mission Operations

```bash
# Run a mission from YAML
gibson mission run ./mission.yaml

# Run with target override
gibson mission run ./mission.yaml --target my-api

# List all missions
gibson mission list

# Show mission details
gibson mission show m-abc123

# Pause a running mission
gibson mission pause m-abc123

# Resume a paused mission
gibson mission resume m-abc123

# Cancel a mission
gibson mission cancel m-abc123

# Validate mission YAML
gibson mission validate ./mission.yaml

# Show execution plan (DAG visualization)
gibson mission plan ./mission.yaml
```

#### Agent Management

```bash
# List registered agents
gibson agent list

# Show agent details
gibson agent show api-scanner

# Install agent from URL
gibson agent install https://github.com/zero-day-ai/agent-api-scanner

# View agent logs
gibson agent logs api-scanner

# Stream agent logs
gibson agent logs api-scanner --follow

# Remove agent
gibson agent remove api-scanner
```

#### Tool Management

```bash
# List registered tools
gibson tool list

# Show tool details
gibson tool show httpx

# Install tool
gibson tool install https://github.com/zero-day-ai/tool-httpx

# View tool logs
gibson tool logs httpx
```

#### Finding Management

```bash
# List findings
gibson finding list

# Filter by severity
gibson finding list --severity critical,high

# Filter by category
gibson finding list --category prompt_injection

# Filter by mission
gibson finding list --mission m-abc123

# Show finding details
gibson finding show f-xyz789

# Export findings
gibson finding export --format sarif > findings.sarif
gibson finding export --format csv > findings.csv
gibson finding export --format html > findings.html
```

#### Attack Operations

```bash
# Run quick attack
gibson attack --target my-api --agent api-fuzzer

# List available attacks
gibson attack list

# Dry run (validate only)
gibson attack --target my-api --agent api-fuzzer --dry-run
```

#### Target Management

```bash
# Add a target
gibson target add my-api \
  --type http_api \
  --url https://api.example.com \
  --auth bearer:$API_TOKEN

# List targets
gibson target list

# Show target details
gibson target show my-api

# Remove target
gibson target remove my-api
```

#### Configuration

```bash
# Show current configuration
gibson config show

# Edit configuration
gibson config edit

# Validate configuration
gibson config validate

# Show specific section
gibson config show --section llm
```

#### Knowledge Graph

```bash
# Query knowledge graph
gibson knowledge query "SQL injection vulnerabilities"

# Export knowledge graph
gibson knowledge export --format cypher > graph.cypher
gibson knowledge export --format json > graph.json
```

#### Logs

```bash
# Stream daemon logs
gibson logs stream

# Show log history
gibson logs show --since 1h

# Filter by component
gibson logs show --component orchestrator
```

#### Status & Information

```bash
# Show version
gibson version

# Show overall status
gibson status
```

---

### Remote Connectivity

Gibson CLI can connect to remote daemons for distributed operation.

#### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GIBSON_DAEMON_ADDRESS` | Remote daemon gRPC address | `gibson.example.com:50002` |
| `GIBSON_FORCE_INLINE_YAML` | Force inline YAML mode | `true` |
| `GIBSON_TLS_CERT` | Client TLS certificate | `/path/to/cert.pem` |
| `GIBSON_TLS_KEY` | Client TLS key | `/path/to/key.pem` |

#### Connection Modes

**Local Daemon (default)**
```bash
# CLI reads daemon.json from ~/.gibson/
gibson mission list
```

**Remote Daemon**
```bash
# Connect to remote Gibson deployment
export GIBSON_DAEMON_ADDRESS="gibson.example.com:50002"
gibson status
gibson mission run ./mission.yaml
```

**Kubernetes Port-Forward**
```bash
# Forward the daemon port locally
kubectl port-forward svc/gibson 50002:50002 -n gibson &

# Connect via localhost
export GIBSON_DAEMON_ADDRESS="localhost:50002"
export GIBSON_FORCE_INLINE_YAML="true"
gibson mission run ./mission.yaml
```

#### Address Detection

| Address Pattern | Mode | Behavior |
|-----------------|------|----------|
| Empty | Local | Read `~/.gibson/daemon.json` |
| `localhost:*` | Local | Direct connection, file paths |
| `127.0.0.1:*` | Local | Direct connection, file paths |
| `unix:///path` | Local | Unix socket connection |
| Everything else | Remote | Inline YAML, no file access |

---

### CI/CD Integration

Gibson integrates with CI/CD pipelines for automated security testing.

#### Pattern 1: Remote Daemon (Recommended)

Connect to a long-running Gibson deployment:

```yaml
# .gitlab-ci.yml
variables:
  GIBSON_DAEMON_ADDRESS: "gibson.internal.example.com:50002"

security-scan:
  stage: test
  image: ghcr.io/zero-day-ai/gibson:latest
  script:
    - gibson status
    - gibson attack --target $CI_PROJECT_NAME --agent api-scanner
    - gibson finding export --format sarif > gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

```yaml
# GitHub Actions
name: Security Scan
on: [push]

env:
  GIBSON_DAEMON_ADDRESS: gibson.internal.example.com:50002

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Gibson Scan
        run: |
          gibson attack --target ${{ github.repository }} --agent api-scanner
          gibson finding export --format sarif > results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

#### Pattern 2: Inline Execution (Stateless)

Run Gibson daemon and agents in the CI job:

```yaml
# GitHub Actions - Inline
name: Security Scan (Inline)
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379

    steps:
      - uses: actions/checkout@v4

      - name: Setup Gibson
        run: |
          curl -L https://github.com/zero-day-ai/gibson/releases/latest/download/gibson-linux-amd64 -o gibson
          chmod +x gibson

      - name: Start Daemon
        run: |
          cat > config.yaml << EOF
          redis:
            url: redis://localhost:6379
          registry:
            type: embedded
          EOF

          ./gibson daemon start --config config.yaml &
          sleep 5
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}

      - name: Run Mission
        run: |
          ./gibson mission run ./missions/security-scan.yaml
```

#### Pattern 3: Hybrid

Custom agents with remote daemon:

```yaml
# Build and test custom agent against remote daemon
name: Custom Agent Test
on: [push]

env:
  GIBSON_DAEMON_ADDRESS: gibson.internal.example.com:50002

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Agent
        run: |
          cd agents/my-agent
          go build -o agent .

      - name: Register Agent
        run: |
          ./agents/my-agent/agent serve \
            --callback-address gibson.internal.example.com:50001 \
            --port 50051 &
          sleep 5
          gibson agent list

      - name: Test Agent
        run: |
          gibson mission run ./missions/test-my-agent.yaml
```

#### Best Practices

1. **Use secrets management** for API keys
2. **Export findings as SARIF** for security dashboard integration
3. **Set timeouts** on missions to prevent runaway jobs
4. **Use `--persist` flag** to save findings even on partial completion
5. **Tag missions** with CI metadata:
   ```bash
   gibson mission run ./mission.yaml \
     --metadata "ci.job=$CI_JOB_ID" \
     --metadata "ci.commit=$CI_COMMIT_SHA" \
     --metadata "ci.branch=$CI_COMMIT_BRANCH"
   ```

---

## Gibson SDK

The Gibson SDK is a Go library for building agents, tools, and plugins that integrate with the Gibson platform.

### Core Framework

#### Installation

```bash
go get github.com/zero-day-ai/sdk@latest
```

#### Package Structure

```
github.com/zero-day-ai/sdk/
├── agent/          # Agent interface and utilities
├── tool/           # Tool interface and workers
├── plugin/         # Plugin interface
├── llm/            # LLM abstraction layer
├── memory/         # Three-tier memory system
├── graphrag/       # Knowledge graph client
├── finding/        # Finding management
├── serve/          # gRPC serving utilities
├── schema/         # JSON Schema helpers
├── input/          # Type-safe input extraction
└── types/          # Common types and errors
```

#### Framework Interface

```go
import "github.com/zero-day-ai/sdk"

// Create framework instance
fw, err := sdk.NewFramework(ctx, sdk.Config{
    ConfigPath: "~/.gibson/config.yaml",
})

// Access framework services
missions := fw.Missions()
registry := fw.Registry()
findings := fw.Findings()

// Lifecycle management
fw.Start(ctx)
defer fw.Shutdown(ctx)
```

---

### Agent Development

Agents are autonomous LLM-driven components that execute tasks.

#### Agent Interface

```go
type Agent interface {
    // Metadata
    Name() string
    Version() string
    Description() string

    // LLM requirements
    LLMSlots() []SlotDefinition

    // Lifecycle
    Initialize(ctx context.Context, config map[string]any) error
    Shutdown(ctx context.Context) error

    // Execution
    Execute(ctx context.Context, task Task, harness Harness) (Result, error)

    // Health
    Health(ctx context.Context) HealthStatus
}
```

#### Building an Agent

```go
package main

import (
    "context"
    "github.com/zero-day-ai/sdk/agent"
    "github.com/zero-day-ai/sdk/llm"
    "github.com/zero-day-ai/sdk/serve"
)

type APIScanner struct {
    config map[string]any
}

func (a *APIScanner) Name() string        { return "api-scanner" }
func (a *APIScanner) Version() string     { return "1.0.0" }
func (a *APIScanner) Description() string { return "Scans APIs for vulnerabilities" }

func (a *APIScanner) LLMSlots() []agent.SlotDefinition {
    return []agent.SlotDefinition{
        agent.NewSlotDefinition("primary", "Main reasoning LLM", true).
            WithConstraints(agent.SlotConstraints{
                MinContextWindow: 8000,
                RequiredFeatures: []string{agent.FeatureToolUse},
            }),
        agent.NewSlotDefinition("fast", "Quick classification", false).
            WithPreferredModels([]string{"claude-3-haiku"}),
    }
}

func (a *APIScanner) Execute(ctx context.Context, task agent.Task, h agent.Harness) (agent.Result, error) {
    // Use LLM for reasoning
    resp, err := h.Complete(ctx, "primary", []llm.Message{
        llm.NewSystemMessage("You are an API security expert..."),
        llm.NewUserMessage(task.Goal),
    })
    if err != nil {
        return agent.NewFailedResult(err), nil
    }

    // Execute tools
    scanResult, err := h.CallToolProto(ctx, "httpx", &httpx.ScanRequest{
        Url: task.Target.URL,
    })
    if err != nil {
        return agent.NewFailedResult(err), nil
    }

    // Submit findings
    if vuln := analyzeResponse(scanResult); vuln != nil {
        h.SubmitFinding(ctx, vuln)
    }

    // Store in memory for other agents
    h.Memory().Mission().Set(ctx, "scan_results", scanResult)

    return agent.NewSuccessResult(map[string]any{
        "endpoints_scanned": len(scanResult.Endpoints),
        "vulnerabilities":   len(scanResult.Vulnerabilities),
    }), nil
}

func main() {
    serve.Agent(&APIScanner{}, serve.WithPort(50051))
}
```

#### Task Structure

```go
type Task struct {
    ID          string                 // Unique task identifier
    Goal        string                 // What the agent should accomplish
    Target      Target                 // Target to operate on
    Context     map[string]any         // Additional context from orchestrator
    Constraints TaskConstraints        // Execution constraints
    Metadata    map[string]string      // User-defined metadata
}

type TaskConstraints struct {
    MaxTurns     int           // Maximum reasoning iterations
    MaxTokens    int           // Token budget
    Timeout      time.Duration // Execution timeout
    AllowedTools []string      // Restricted tool list (empty = all)
}
```

#### Result Types

```go
// Success with output data
result := agent.NewSuccessResult(map[string]any{
    "endpoints": 42,
    "findings":  3,
})

// Partial success (some tasks completed)
result := agent.NewPartialResult(
    map[string]any{"partial": "data"},
    errors.New("some endpoints failed"),
)

// Failure with structured error
result := agent.NewFailedResult(
    agent.NewResultError("SCAN_FAILED", "Network timeout").
        WithRetryable(true).
        WithComponent("httpx"),
)

// Timeout or cancellation
result := agent.NewTimeoutResult()
result := agent.NewCancelledResult()
```

#### Capabilities Declaration

```go
func (a *APIScanner) Capabilities() []agent.Capability {
    return []agent.Capability{
        agent.CapabilityPromptInjection,
        agent.CapabilityDataExtraction,
        agent.CapabilityJailbreak,
    }
}

func (a *APIScanner) TechniqueTypes() []string {
    return []string{
        "T1190",  // Exploit Public-Facing Application
        "T1059",  // Command and Scripting Interpreter
    }
}
```

#### Target Schemas

```go
// Built-in target schemas
schema := agent.GetBuiltinSchema("http_api")
schema := agent.GetBuiltinSchema("llm_chat")
schema := agent.GetBuiltinSchema("llm_api")
schema := agent.GetBuiltinSchema("kubernetes")
schema := agent.GetBuiltinSchema("smart_contract")

// Validate target against schema
if err := agent.ValidateTarget(target, schema); err != nil {
    return agent.NewFailedResult(err), nil
}
```

---

### Tool Development

Tools are stateless operations that agents invoke to interact with external systems.

#### Tool Interface

```go
type Tool interface {
    // Metadata
    Name() string
    Version() string
    Description() string
    Tags() []string

    // Proto types for type-safe I/O
    InputMessageType() proto.Message
    OutputMessageType() proto.Message

    // Execution
    Execute(ctx context.Context, input proto.Message) (proto.Message, error)

    // Health
    Health(ctx context.Context) HealthStatus
}
```

#### Building a Tool

```go
package main

import (
    "context"
    "github.com/zero-day-ai/sdk/tool"
    "github.com/zero-day-ai/sdk/serve"
    pb "github.com/zero-day-ai/tools/httpx/proto"
)

type HTTPXTool struct{}

func (t *HTTPXTool) Name() string        { return "httpx" }
func (t *HTTPXTool) Version() string     { return "1.0.0" }
func (t *HTTPXTool) Description() string { return "HTTP probing and analysis" }
func (t *HTTPXTool) Tags() []string      { return []string{"http", "recon", "web"} }

func (t *HTTPXTool) InputMessageType() proto.Message  { return &pb.ProbeRequest{} }
func (t *HTTPXTool) OutputMessageType() proto.Message { return &pb.ProbeResponse{} }

func (t *HTTPXTool) Execute(ctx context.Context, input proto.Message) (proto.Message, error) {
    req := input.(*pb.ProbeRequest)

    // Execute httpx probe
    result, err := runHTTPXProbe(ctx, req)
    if err != nil {
        return nil, err
    }

    return &pb.ProbeResponse{
        StatusCode:  result.StatusCode,
        ContentType: result.ContentType,
        Headers:     result.Headers,
        Body:        result.Body,
    }, nil
}

func main() {
    serve.Tool(&HTTPXTool{}, serve.WithPort(50052))
}
```

#### Tool Worker System

For horizontal scaling, tools can run as Redis queue workers:

```go
// Worker mode - consumes jobs from Redis queue
func main() {
    tool := &HTTPXTool{}

    worker := tool.NewWorker(tool.WorkerConfig{
        RedisURL:    "redis://localhost:6379",
        Concurrency: 10,
        QueueName:   "httpx",
    })

    // Blocks until shutdown signal
    worker.Run(context.Background())
}
```

Worker features:
- **Job Distribution**: LPUSH/BRPOP based work queue
- **Concurrency Control**: Configurable worker count
- **Heartbeats**: Worker health tracking
- **Graceful Shutdown**: Signal handling, queue draining
- **Result Delivery**: Redis pub/sub for streaming results

---

### Plugin Development

Plugins are stateful service integrations with multiple named methods.

#### Plugin Interface

```go
type Plugin interface {
    // Metadata
    Name() string
    Version() string
    Description() string
    Methods() []MethodDescriptor

    // Lifecycle
    Initialize(ctx context.Context, config map[string]any) error
    Shutdown(ctx context.Context) error

    // Invocation
    Invoke(ctx context.Context, method string, input map[string]any) (map[string]any, error)

    // Health
    Health(ctx context.Context) HealthStatus
}

type MethodDescriptor struct {
    Name        string
    Description string
    InputSchema  *schema.Schema
    OutputSchema *schema.Schema
}
```

#### Building a Plugin

```go
package main

import (
    "context"
    "github.com/zero-day-ai/sdk/plugin"
    "github.com/zero-day-ai/sdk/schema"
    "github.com/zero-day-ai/sdk/serve"
)

type GitLabPlugin struct {
    client *gitlab.Client
}

func (p *GitLabPlugin) Name() string        { return "gitlab" }
func (p *GitLabPlugin) Version() string     { return "1.0.0" }
func (p *GitLabPlugin) Description() string { return "GitLab integration" }

func (p *GitLabPlugin) Methods() []plugin.MethodDescriptor {
    return []plugin.MethodDescriptor{
        {
            Name:        "list_projects",
            Description: "List accessible GitLab projects",
            InputSchema: schema.Object().
                Property("group", schema.String().Description("Filter by group")).
                Property("limit", schema.Integer().Default(100)),
            OutputSchema: schema.Object().
                Property("projects", schema.Array().Items(schema.Object())),
        },
        {
            Name:        "get_vulnerabilities",
            Description: "Get vulnerabilities for a project",
            InputSchema: schema.Object().
                Property("project_id", schema.Integer().Required()).
                Property("severity", schema.Enum("critical", "high", "medium", "low")),
        },
    }
}

func (p *GitLabPlugin) Initialize(ctx context.Context, config map[string]any) error {
    token := config["token"].(string)
    p.client = gitlab.NewClient(token)
    return nil
}

func (p *GitLabPlugin) Invoke(ctx context.Context, method string, input map[string]any) (map[string]any, error) {
    switch method {
    case "list_projects":
        return p.listProjects(ctx, input)
    case "get_vulnerabilities":
        return p.getVulnerabilities(ctx, input)
    default:
        return nil, fmt.Errorf("unknown method: %s", method)
    }
}

func main() {
    serve.Plugin(&GitLabPlugin{}, serve.WithPort(50053))
}
```

---

### LLM Abstraction

The SDK provides a unified interface for multiple LLM providers.

#### Supported Providers

| Provider | Models | Features |
|----------|--------|----------|
| Anthropic | Claude 3.5, Claude 3 | Tool use, vision, streaming |
| OpenAI | GPT-4, GPT-3.5 | Tool use, vision, streaming, JSON mode |
| Google | Gemini Pro, Gemini Ultra | Tool use, vision, streaming |
| Ollama | Llama, Mistral, etc. | Local execution, streaming |

#### Message Types

```go
// Create messages
msg := llm.NewSystemMessage("You are a security expert...")
msg := llm.NewUserMessage("Analyze this API endpoint")
msg := llm.NewAssistantMessage("I'll analyze the endpoint...")
msg := llm.NewToolResultMessage(toolCallID, result)

// With images (vision models)
msg := llm.NewUserMessage("What's in this screenshot?").
    WithImage(imageBytes, "image/png")
```

#### Completion API

```go
// Basic completion
resp, err := h.Complete(ctx, "primary", messages)
fmt.Println(resp.Content)
fmt.Println(resp.TokenUsage.Input, resp.TokenUsage.Output)

// With tools
resp, err := h.CompleteWithTools(ctx, "primary", messages, tools)
if resp.ToolCalls != nil {
    for _, call := range resp.ToolCalls {
        result := executeTool(call.Name, call.Arguments)
        messages = append(messages, llm.NewToolResultMessage(call.ID, result))
    }
}

// Streaming
stream, err := h.Stream(ctx, "primary", messages)
for chunk := range stream.Chunks() {
    fmt.Print(chunk.Content)
}

// Structured output
type Analysis struct {
    Severity string   `json:"severity"`
    Issues   []string `json:"issues"`
}
var result Analysis
err := h.CompleteStructured(ctx, "primary", messages, &result)
```

#### Slot System

Slots abstract LLM requirements, allowing the daemon to allocate appropriate models:

```go
func (a *MyAgent) LLMSlots() []agent.SlotDefinition {
    return []agent.SlotDefinition{
        // Primary reasoning slot - requires tool use
        agent.NewSlotDefinition("primary", "Main reasoning", true).
            WithConstraints(agent.SlotConstraints{
                MinContextWindow: 100000,
                RequiredFeatures: []string{
                    agent.FeatureToolUse,
                    agent.FeatureVision,
                },
            }).
            WithPreferredModels([]string{
                "claude-3-5-sonnet",
                "gpt-4-turbo",
            }),

        // Fast classification slot
        agent.NewSlotDefinition("fast", "Quick tasks", false).
            WithConstraints(agent.SlotConstraints{
                MinContextWindow: 4000,
            }).
            WithPreferredModels([]string{
                "claude-3-haiku",
                "gpt-3.5-turbo",
            }),
    }
}
```

#### Token Tracking

```go
// Get token usage
usage := h.TokenUsage()
fmt.Printf("Total: %d input, %d output\n", usage.Input, usage.Output)
fmt.Printf("By slot: %+v\n", usage.BySlot)

// Check budget
if usage.Total() > task.Constraints.MaxTokens {
    return agent.NewBudgetExceededResult(), nil
}
```

---

### Three-Tier Memory

The SDK provides a three-tier memory system for different temporal scales.

#### Memory Tiers

| Tier | Persistence | Scope | Use Case |
|------|-------------|-------|----------|
| Working | Ephemeral | Single execution | Scratch space, intermediate results |
| Mission | Redis | Mission lifetime | Cross-agent sharing, checkpointing |
| Long-Term | Neo4j | Permanent | Knowledge base, historical data |

#### Working Memory

```go
working := h.Memory().Working()

// Set/Get values
working.Set(ctx, "key", value)
value, exists := working.Get(ctx, "key")

// Delete
working.Delete(ctx, "key")

// List keys
keys := working.Keys(ctx)
```

#### Mission Memory

```go
mission := h.Memory().Mission()

// Set with metadata
mission.Set(ctx, "analysis_results", results,
    memory.WithTags("security", "api"),
    memory.WithExpiry(24*time.Hour),
)

// Get with history
value, metadata := mission.GetWithMetadata(ctx, "analysis_results")
fmt.Println(metadata.CreatedAt, metadata.Tags)

// Search
results := mission.Search(ctx, "SQL injection", memory.SearchOptions{
    Tags:  []string{"security"},
    Limit: 10,
})

// History (with continuity enabled)
history := mission.History(ctx, "key", 10)  // Last 10 values
```

#### Long-Term Memory

```go
longterm := h.Memory().LongTerm()

// Store with embedding
longterm.Store(ctx, "finding-123", finding, memory.EmbedContent(finding.Description))

// Semantic search
results := longterm.Search(ctx, "authentication bypass vulnerabilities",
    memory.TopK(10),
    memory.MinSimilarity(0.7),
)

// Get by ID
value := longterm.Get(ctx, "finding-123")
```

#### Memory Continuity

Configure how memory persists across mission runs:

```yaml
# Mission YAML
memory:
  continuity: inherit  # isolated | inherit | shared
```

| Mode | Behavior |
|------|----------|
| `isolated` | Fresh memory for each run |
| `inherit` | Read-only access to previous run's memory |
| `shared` | Full read/write access to shared memory pool |

---

### GraphRAG Client

The SDK provides a client for interacting with the Neo4j knowledge graph.

#### Storing Nodes

```go
// Store a single node
node := graphrag.NewNode("host").
    SetProperty("ip", "10.0.0.5").
    SetProperty("hostname", "api-server").
    SetProperty("os", "Linux")

err := h.GraphRAG().StoreNode(ctx, node)

// Batch store
nodes := []*graphrag.Node{node1, node2, node3}
err := h.GraphRAG().StoreNodes(ctx, nodes)
```

#### Creating Relationships

```go
// Create relationship
err := h.GraphRAG().CreateRelationship(ctx,
    hostNodeID,
    "HAS_PORT",
    portNodeID,
    map[string]any{"discovered_at": time.Now()},
)

// Batch relationships
rels := []graphrag.Relationship{
    {From: id1, Type: "AFFECTS", To: id2},
    {From: id2, Type: "USES_TECHNIQUE", To: id3},
}
err := h.GraphRAG().CreateRelationships(ctx, rels)
```

#### Querying

```go
// Hybrid query (semantic + structural)
results, err := h.GraphRAG().Query(ctx, graphrag.QueryOptions{
    Text:             "SQL injection in authentication",
    NodeTypes:        []string{"finding", "endpoint"},
    SimilarityWeight: 0.6,
    StructuralWeight: 0.4,
    MaxHops:          3,
    Limit:            10,
})

// Traverse relationships
related, err := h.GraphRAG().Traverse(ctx, nodeID, graphrag.TraverseOptions{
    RelationshipTypes: []string{"AFFECTS", "LEADS_TO"},
    Direction:         graphrag.Outgoing,
    MaxDepth:          2,
})
```

#### Query Builder

```go
query := graphrag.NewQuery().
    Text("authentication vulnerabilities").
    NodeTypes("finding", "endpoint").
    WithFilter("severity", "critical").
    SimilarityWeight(0.7).
    StructuralWeight(0.3).
    Limit(20)

results, err := h.GraphRAG().ExecuteQuery(ctx, query)
```

---

### Agent Harness

The harness provides the runtime environment for agent execution.

#### Harness Interface

```go
type Harness interface {
    // LLM operations
    Complete(ctx, slot string, messages []llm.Message, opts ...llm.Option) (*llm.Response, error)
    CompleteWithTools(ctx, slot string, messages []llm.Message, tools []llm.Tool, opts ...llm.Option) (*llm.Response, error)
    Stream(ctx, slot string, messages []llm.Message, opts ...llm.Option) (*llm.StreamResponse, error)
    CompleteStructured(ctx, slot string, messages []llm.Message, result any, opts ...llm.Option) error

    // Tool invocation
    CallToolProto(ctx context.Context, name string, req, resp proto.Message) error
    CallToolJSON(ctx context.Context, name string, input map[string]any) (map[string]any, error)
    QueueToolCalls(ctx context.Context, calls []ToolCall) ([]QueuedToolResult, error)

    // Plugin access
    QueryPlugin(ctx context.Context, name, method string, input map[string]any) (map[string]any, error)
    ListPlugins(ctx context.Context) ([]PluginInfo, error)

    // Agent delegation
    DelegateToAgent(ctx context.Context, agent string, task Task) (Result, error)

    // Findings
    SubmitFinding(ctx context.Context, finding *finding.Finding) error
    GetFindings(ctx context.Context, opts ...finding.QueryOption) ([]*finding.Finding, error)

    // Memory
    Memory() MemoryManager

    // GraphRAG
    GraphRAG() GraphRAGClient

    // Mission management
    CreateMission(ctx context.Context, config MissionConfig) (string, error)
    RunMission(ctx context.Context, missionID string) error
    GetMissionStatus(ctx context.Context, missionID string) (MissionStatus, error)

    // Context
    Target() Target
    Mission() MissionInfo
    Task() Task

    // Observability
    Tracer() trace.Tracer
    Logger() *slog.Logger
    TokenUsage() TokenUsage

    // Planning
    PlanContext() PlanContext
}
```

#### Tool Streaming

Monitor tool execution progress:

```go
result, err := h.CallToolProtoWithStream(ctx, "nmap", req, resp,
    tool.OnProgress(func(pct float64, msg string) {
        log.Printf("Progress: %.1f%% - %s", pct*100, msg)
    }),
    tool.OnPartialResult(func(partial proto.Message) {
        // Handle intermediate results
    }),
    tool.OnWarning(func(msg string) {
        log.Printf("Warning: %s", msg)
    }),
)
```

#### Parallel Tool Execution

```go
// Queue multiple tool calls
calls := []harness.ToolCall{
    {Name: "httpx", Input: &httpx.Request{Url: "https://api1.example.com"}},
    {Name: "httpx", Input: &httpx.Request{Url: "https://api2.example.com"}},
    {Name: "httpx", Input: &httpx.Request{Url: "https://api3.example.com"}},
}

results, err := h.QueueToolCalls(ctx, calls)
for _, result := range results {
    if result.Error != nil {
        log.Printf("Tool %s failed: %v", result.Name, result.Error)
        continue
    }
    // Process result.Output
}
```

---

### Finding Management

Create and submit security findings.

#### Creating Findings

```go
f := finding.New("SQL Injection in Login").
    Category(finding.CategoryDataExtraction).
    Severity(finding.SeverityCritical).
    Description("The login endpoint is vulnerable to SQL injection...").
    Target(target).
    Evidence(finding.Evidence{
        Request:  httpRequest,
        Response: httpResponse,
        Payload:  "' OR '1'='1",
    }).
    MITRE("T1190", "Exploit Public-Facing Application").
    Remediation("Use parameterized queries...").
    ReproductionSteps(
        "Navigate to /login",
        "Enter payload in username field",
        "Submit form",
    ).
    Confidence(0.95)

err := h.SubmitFinding(ctx, f)
```

#### Finding Categories

```go
finding.CategoryJailbreak
finding.CategoryPromptInjection
finding.CategoryDataExtraction
finding.CategoryPrivilegeEscalation
finding.CategoryDoS
finding.CategoryModelManipulation
finding.CategoryInformationDisclosure
```

#### Severity Levels

```go
finding.SeverityCritical  // 9.0 - 10.0
finding.SeverityHigh      // 7.0 - 8.9
finding.SeverityMedium    // 4.0 - 6.9
finding.SeverityLow       // 0.1 - 3.9
finding.SeverityInfo      // 0.0
```

#### Querying Findings

```go
findings, err := h.GetFindings(ctx,
    finding.WithSeverity(finding.SeverityCritical, finding.SeverityHigh),
    finding.WithCategory(finding.CategoryPromptInjection),
    finding.WithStatus(finding.StatusOpen),
    finding.Since(time.Now().Add(-24*time.Hour)),
    finding.Limit(100),
)
```

---

### Tool Worker System

For horizontally scalable tool execution.

#### Worker Configuration

```go
worker := tool.NewWorker(tool.WorkerConfig{
    RedisURL:     "redis://localhost:6379",
    QueueName:    "httpx",
    Concurrency:  10,
    PollInterval: 100 * time.Millisecond,
    JobTimeout:   5 * time.Minute,
})
```

#### Work Item Format

```go
type WorkItem struct {
    JobID     string // Unique job identifier
    Index     int    // Index in batch
    ToolName  string // Tool to execute
    InputType string // Proto message type
    Input     []byte // Serialized proto input
}
```

#### Result Delivery

Results are delivered via Redis pub/sub:

```go
type WorkResult struct {
    JobID      string
    Index      int
    OutputType string
    Output     []byte // Serialized proto output
    Error      string // Error message if failed
    Duration   time.Duration
}
```

---

### Serving & Deployment

Utilities for running agents, tools, and plugins as gRPC servers.

#### Server Configuration

```go
serve.Agent(&MyAgent{},
    serve.WithPort(50051),
    serve.WithHealthPort(8080),
    serve.WithGracefulShutdown(30*time.Second),
    serve.WithTLS("cert.pem", "key.pem"),
)

serve.Tool(&MyTool{},
    serve.WithPort(50052),
    serve.WithWorkerMode(serve.WorkerConfig{
        RedisURL:    "redis://localhost:6379",
        Concurrency: 10,
    }),
)

serve.Plugin(&MyPlugin{},
    serve.WithPort(50053),
)
```

#### Health Probes

All servers automatically expose health endpoints:

| Endpoint | Protocol | Purpose |
|----------|----------|---------|
| `/healthz` | HTTP | Liveness probe |
| `/readyz` | HTTP | Readiness probe |
| `grpc.health.v1.Health` | gRPC | gRPC health check |

#### Signal Handling

Automatic handling of shutdown signals:

- **SIGTERM**: Graceful shutdown with configurable timeout
- **SIGINT**: Immediate shutdown (Ctrl+C)

---

### Utilities

#### JSON Schema Builder

```go
schema := schema.Object().
    Property("url", schema.String().
        Format("uri").
        Required().
        Description("Target URL")).
    Property("method", schema.Enum("GET", "POST", "PUT", "DELETE").
        Default("GET")).
    Property("headers", schema.Object().
        AdditionalProperties(schema.String())).
    Property("timeout", schema.Integer().
        Minimum(1).
        Maximum(300).
        Default(30))
```

#### Type-Safe Input Extraction

```go
import "github.com/zero-day-ai/sdk/input"

// Extract with automatic type coercion
url := input.String(data, "url")
timeout := input.Int(data, "timeout")
enabled := input.Bool(data, "enabled")
duration := input.Duration(data, "interval")  // Parses "5m", "30s", etc.

// With defaults
port := input.IntOr(data, "port", 8080)
```

#### Enum Normalization

```go
import "github.com/zero-day-ai/sdk/enum"

// Register enum mappings
enum.Register("httpx", "method", map[string]int32{
    "get":    1,
    "post":   2,
    "put":    3,
    "delete": 4,
})

// Normalize user input
methodEnum := enum.Normalize("httpx", "method", "GET")  // Returns 1
```

#### Error Handling

```go
import "github.com/zero-day-ai/sdk/types"

// Sentinel errors
if errors.Is(err, types.ErrAgentNotFound) { ... }
if errors.Is(err, types.ErrToolNotFound) { ... }
if errors.Is(err, types.ErrSlotNotSatisfied) { ... }

// Structured errors
sdkErr := types.NewSDKError("agent.execute", types.KindExecution, err).
    WithContext("agent", "api-scanner").
    WithContext("task_id", taskID)
```

---

## Summary

Gibson provides a complete platform for building, deploying, and operating autonomous AI agents:

**Gibson Core**:
- Kubernetes-native daemon with health probes and graceful shutdown
- LLM-driven orchestration with the Observe-Think-Act control loop
- Mission management with checkpointing and resume
- Redis-backed state management for horizontal scaling
- etcd-based service discovery for dynamic agent/tool registration
- Neo4j GraphRAG for persistent knowledge storage
- Comprehensive finding management with SARIF export
- OpenTelemetry observability with GenAI conventions
- Built-in guardrails for safe operation
- Full-featured CLI for all operations
- CI/CD integration patterns

**Gibson SDK**:
- Agent, Tool, and Plugin interfaces with builder patterns
- Multi-provider LLM abstraction with slot-based allocation
- Three-tier memory system (working, mission, long-term)
- GraphRAG client for knowledge graph operations
- Structured finding creation and submission
- Redis-based tool worker system for horizontal scaling
- gRPC serving utilities with health probes
- Type-safe utilities for input handling and schema validation

Together, these components enable teams to build sophisticated autonomous agents that can reason, execute tools, persist knowledge, and operate reliably in production environments.
