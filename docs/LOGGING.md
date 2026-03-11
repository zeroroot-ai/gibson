# Gibson Observability

Gibson provides comprehensive observability through OpenTelemetry as the unified system:

| System | Purpose | Backend |
|--------|---------|---------|
| **Structured Logging** | Human/machine-readable logs | stdout/stderr (JSON/text) |
| **Distributed Tracing** | Request flow across services | OpenTelemetry (OTLP) |
| **Metrics** | Quantitative measurements | Prometheus |
| **GenAI Spans** | LLM decision & token tracking | OpenTelemetry GenAI Conventions |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Gibson Observability                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Agent Execution ──► Harness Middleware ──┬──► Structured Logs         │
│         │                                  │                             │
│         │                                  ├──► OpenTelemetry Spans      │
│         │                                  │    (includes GenAI spans)   │
│         │                                  │                             │
│         └──────────────────────────────────┴──► Prometheus Metrics       │
│                                                                          │
│   ┌─────────────┐  ┌─────────────────────────────┐  ┌─────────────┐     │
│   │   stdout    │  │       OTLP Collector        │  │ Prometheus  │     │
│   │   stderr    │  │  Traces + GenAI Conventions │  │   Server    │     │
│   └─────────────┘  └─────────────────────────────┘  └─────────────┘     │
│         │                      │                           │             │
│         ▼                      ▼                           ▼             │
│   Log Aggregator         Jaeger/Tempo                  Grafana          │
│   (Loki, ELK)                                                            │
└─────────────────────────────────────────────────────────────────────────┘
```

## Structured Logging

### Log Levels

| Level | Use Case |
|-------|----------|
| `debug` | Detailed diagnostic information |
| `info` | Normal operational events |
| `warn` | Unexpected but recoverable situations |
| `error` | Failures requiring attention |

### Log Format

**JSON (default, production):**
```json
{
  "time": "2024-03-09T10:30:00.000Z",
  "level": "INFO",
  "msg": "agent execution started",
  "component": "harness",
  "trace_id": "abc123...",
  "span_id": "def456...",
  "mission_id": "mission-123",
  "mission_name": "security-scan",
  "agent_name": "network-recon",
  "node_id": "scan-1"
}
```

**Text (development):**
```
2024-03-09T10:30:00.000Z INFO agent execution started component=harness mission_id=mission-123 agent_name=network-recon
```

### Automatic Enrichment

All logs automatically include:
- **trace_id** / **span_id** - OpenTelemetry correlation
- **mission_id** / **mission_name** - Mission context
- **agent_name** - Current agent
- **node_id** - Workflow node
- **component** - Gibson component name

### Sensitive Data Redaction

These fields are automatically redacted:
- `password`, `secret`, `token`, `apikey`, `api_key`
- `credential`, `authorization`, `bearer`
- `privatekey`, `private_key`, `secretkey`
- `prompt`, `prompts` (LLM inputs)

**Example:**
```json
{
  "api_key": "[REDACTED]",
  "token": "sk-a***xyz9"
}
```

### Configuration

```yaml
logging:
  level: info                    # debug, info, warn, error
  format: json                   # json or text
```

**Environment Variables:**
```bash
export GIBSON_LOG_LEVEL=debug    # Override log level
```

### Logger API

```go
// In agent code
h.Logger().Debug(ctx, "processing hosts", "count", len(hosts))
h.Logger().Info(ctx, "scan complete", "duration_ms", elapsed)
h.Logger().Warn(ctx, "rate limited", "retry_after", retryAfter)
h.Logger().Error(ctx, "scan failed", "error", err)

// Structured events
h.Logger().Event(ctx, "finding_discovered", "new vulnerability", finding)
```

---

## OpenTelemetry Tracing

### Providers

| Provider | Use Case | Configuration |
|----------|----------|---------------|
| `otlp` | Production (Jaeger, Tempo, etc.) | gRPC endpoint |
| `noop` | Testing/disabled | None |

### Configuration

```yaml
tracing:
  enabled: true
  provider: otlp                 # otlp or noop
  endpoint: "localhost:4317"     # OTLP collector endpoint
  service_name: gibson-daemon
  sample_rate: 1.0               # 0.0-1.0

  # TLS (optional)
  tls_cert_file: ""
  tls_key_file: ""
  insecure_mode: false
```

### Span Names

**Mission Lifecycle:**
- `gibson.mission.execute` - Full mission execution
- `gibson.mission.checkpoint` - Checkpoint operation

**Agent Operations:**
- `gibson.agent.execute` - Agent task execution
- `gibson.agent.delegate` - Sub-agent delegation

**LLM Operations:**
- `gibson.llm.complete` - Completion request
- `gibson.llm.complete_with_tools` - Completion with tool use
- `gibson.llm.stream` - Streaming completion

**Tool Operations:**
- `gibson.tool.call` - Tool invocation
- `gibson.tool.result` - Tool result processing

**Memory Operations:**
- `gibson.memory.working.get/set` - Working memory
- `gibson.memory.mission.store/retrieve/search` - Mission memory
- `gibson.memory.longterm.search` - Vector search

**Other:**
- `gibson.finding.submit` - Finding submission
- `gibson.plugin.query` - Plugin query
- `gibson.graph.store` - Graph storage

### Span Attributes

**Gibson-Specific:**
| Attribute | Description |
|-----------|-------------|
| `gibson.mission.id` | Mission identifier |
| `gibson.mission.name` | Mission name |
| `gibson.agent.name` | Agent name |
| `gibson.agent.version` | Agent version |
| `gibson.workflow.name` | Workflow name |
| `gibson.turn.number` | Orchestration turn |
| `gibson.tool.name` | Tool name |
| `gibson.plugin.name` | Plugin name |
| `gibson.plugin.method` | Plugin method |
| `gibson.finding.id` | Finding ID |
| `gibson.finding.severity` | Finding severity |
| `gibson.finding.category` | Finding category |
| `gibson.llm.cost` | LLM cost in USD |
| `gibson.delegation.target_agent` | Delegation target |
| `gibson.delegation.task_id` | Delegation task ID |

**OpenTelemetry GenAI Conventions:**
| Attribute | Description |
|-----------|-------------|
| `gen_ai.system` | LLM provider (anthropic, openai) |
| `gen_ai.request.model` | Model name |
| `gen_ai.usage.input_tokens` | Input token count |
| `gen_ai.usage.output_tokens` | Output token count |

### Example Trace

```
Trace: mission-abc123 (5m 23s)
├── Span: gibson.mission.execute
│   ├── gibson.mission.id: "abc123"
│   ├── gibson.mission.name: "security-scan"
│   │
│   ├── Span: gibson.agent.execute (network-recon)
│   │   ├── gibson.agent.name: "network-recon"
│   │   │
│   │   ├── Span: gibson.llm.complete (2.3s)
│   │   │   ├── gen_ai.system: "anthropic"
│   │   │   ├── gen_ai.request.model: "claude-sonnet-4-20250514"
│   │   │   ├── gen_ai.usage.input_tokens: 1234
│   │   │   └── gen_ai.usage.output_tokens: 567
│   │   │
│   │   ├── Span: gibson.tool.call (nmap) (45s)
│   │   │   └── gibson.tool.name: "nmap"
│   │   │
│   │   └── Span: gibson.finding.submit
│   │       ├── gibson.finding.id: "finding-789"
│   │       └── gibson.finding.severity: "high"
│   │
│   └── Span: gibson.mission.checkpoint
```

---

## Prometheus Metrics

### Configuration

```yaml
metrics:
  enabled: true
  provider: prometheus           # prometheus or otlp
  port: 9090                     # Scrape port
```

### Available Metrics

**LLM Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gibson_llm_completions_total` | Counter | slot, provider, model, status | Total completions |
| `gibson_llm_tokens_input_total` | Counter | slot, provider, model | Input tokens consumed |
| `gibson_llm_tokens_output_total` | Counter | slot, provider, model | Output tokens generated |
| `gibson_llm_latency_ms` | Histogram | slot, provider, model | Request latency |
| `gibson_llm_cost_usd` | Histogram | slot, provider, model | Request cost |

**Tool Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gibson_tool_calls_total` | Counter | tool, status | Total tool calls |
| `gibson_tool_duration_ms` | Histogram | tool | Execution duration |

**Finding Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gibson_findings_submitted_total` | Counter | severity, category | Findings submitted |

**Agent Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gibson_agent_delegations_total` | Counter | source_agent, target_agent, status | Agent delegations |

**Mission Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gibson_missions_active` | Gauge | - | Currently active missions |
| `gibson_missions_total` | Counter | status | Total missions executed |
| `gibson_mission_duration_seconds` | Histogram | mission_id | Mission duration |
| `gibson_mission_nodes_total` | Counter | mission_id, status | Nodes completed/failed |
| `gibson_mission_iterations_total` | Counter | mission_id | Orchestration iterations |

**Health Metrics:**

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `gibson_health_status` | Gauge | component, state | Component health (1=healthy, 0=unhealthy) |

### Grafana Dashboard Queries

```promql
# LLM cost per hour
sum(rate(gibson_llm_cost_usd[1h])) by (provider, model)

# Tool error rate
sum(rate(gibson_tool_calls_total{status="error"}[5m]))
  / sum(rate(gibson_tool_calls_total[5m]))

# Average mission duration
histogram_quantile(0.95, rate(gibson_mission_duration_seconds_bucket[1h]))

# Active missions
gibson_missions_active

# Findings by severity
sum(rate(gibson_findings_submitted_total[1h])) by (severity)

# Token usage per model
sum(rate(gibson_llm_tokens_input_total[1h]) + rate(gibson_llm_tokens_output_total[1h])) by (model)
```

### Kubernetes ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: gibson
  namespace: gibson-system
spec:
  selector:
    matchLabels:
      app: gibson
  endpoints:
    - port: metrics
      interval: 30s
      path: /metrics
```

---

## Health Endpoints

### Endpoints

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `GET /healthz` | Liveness probe | 200 if alive, 503 if dead |
| `GET /readyz` | Readiness probe | 200 if ready, 503 if not ready |

### Configuration

```yaml
health:
  port: 8080                     # Health endpoint port
```

### Response Format

```json
{
  "status": "healthy",
  "timestamp": "2024-03-09T10:30:00Z",
  "checks": [
    {"name": "redis", "status": "healthy", "message": "connected"},
    {"name": "neo4j", "status": "healthy", "message": "connected"},
    {"name": "etcd", "status": "healthy", "message": "connected"}
  ]
}
```

### Health States

| State | HTTP Code | Description |
|-------|-----------|-------------|
| `healthy` | 200 | All systems operational |
| `degraded` | 200 | Operational but reduced performance |
| `unhealthy` | 503 | Not operational |

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 15
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
```

### Registered Health Checks

| Check | Type | Description |
|-------|------|-------------|
| `redis` | Readiness | Redis connection and ping |
| `neo4j` | Readiness | Neo4j connection |
| `etcd` | Readiness | etcd connection |
| `daemon` | Liveness | Daemon process health |

---

## Event Types

Gibson emits structured events for all significant operations:

### Mission Events
- `mission_start` - Mission execution started
- `mission_complete` - Mission completed successfully
- `mission_failed` - Mission failed with error

### Agent Events
- `agent_start` - Agent task started
- `agent_end` - Agent task completed
- `agent_error` - Agent encountered error

### LLM Events
- `llm_request` - LLM request sent
- `llm_response` - LLM response received
- `decision` - Orchestrator decision made

### Tool Events
- `tool_call` - Tool invocation started
- `tool_result` - Tool execution completed

### Other Events
- `finding` - Finding discovered
- `memory_store` - Memory stored
- `memory_recall` - Memory retrieved
- `graph_store` - Entity stored in graph
- `error` - General error occurred

---

## Cost Tracking

Gibson tracks LLM costs per mission and agent:

```go
// Get mission cost
cost, _ := h.CostTracker().GetMissionCost(missionID)

// Get agent cost
cost, _ := h.CostTracker().GetAgentCost(missionID, "network-recon")

// Set cost threshold (alerts when exceeded)
h.CostTracker().SetThreshold(missionID, 10.00) // $10 USD

// Check if threshold exceeded
exceeded := h.CostTracker().CheckThreshold(missionID, currentCost)
```

Cost is recorded on spans as `gibson.llm.cost` attribute.

---

## Middleware Logging Levels

The harness middleware supports different verbosity levels:

| Level | Output |
|-------|--------|
| `quiet` | No logs |
| `normal` | Start/complete/failed only |
| `verbose` | Include timing, token usage, summaries |
| `debug` | Include truncated request/response (redacted) |

---

## Full Configuration Reference

```yaml
# Logging
logging:
  level: info                    # debug, info, warn, error
  format: json                   # json or text

# OpenTelemetry Tracing (includes GenAI spans)
tracing:
  enabled: true
  provider: otlp                 # otlp or noop
  endpoint: "localhost:4317"
  service_name: gibson-daemon
  sample_rate: 1.0
  tls_cert_file: ""
  tls_key_file: ""
  insecure_mode: false

# Prometheus Metrics
metrics:
  enabled: true
  provider: prometheus           # prometheus or otlp
  port: 9090

# GenAI Content Logging (prompts/completions in traces)
content_logging:
  enabled: true
  max_prompt_length: 10000
  max_completion_length: 10000

# Health Endpoints
health:
  port: 8080
```

**Environment Variables:**
```bash
# Logging
GIBSON_LOG_LEVEL=debug

# Tracing
OTEL_TRACING_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=localhost:4317
```
