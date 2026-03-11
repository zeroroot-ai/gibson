# Gibson Observability Dashboards

Gibson provides Grafana dashboards for monitoring agent execution, LLM usage, and mission performance through OpenTelemetry and Prometheus.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     Observability Dashboard Stack                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Gibson Missions ──► OpenTelemetry ──► Grafana Dashboards               │
│         │                                     │                          │
│         │                                     ├── Mission Overview       │
│         │                                     ├── Agent Performance      │
│         │                                     ├── LLM Analytics          │
│         │                                     └── Knowledge Graph        │
│         │                                                                │
│         └──► Neo4j GraphRAG ──► Graph Explorer                          │
│                                                                          │
│   ┌──────────────┐  ┌─────────────┐  ┌────────────────┐                 │
│   │    OTLP      │  │    Loki     │  │   Prometheus   │                 │
│   │  Collector   │──│    Logs     │  │    Metrics     │                 │
│   │ (port 4317)  │  │ (port 3100) │  │  (port 9090)   │                 │
│   └──────────────┘  └─────────────┘  └────────────────┘                 │
│          │                │                  │                           │
│          └────────────────┴──────────────────┘                          │
│                           │                                              │
│                           ▼                                              │
│                   ┌──────────────┐                                      │
│                   │   Grafana    │                                      │
│                   │ (port 3000)  │                                      │
│                   └──────────────┘                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

## Dashboard Suite

### 1. Mission Overview Dashboard

**Purpose**: Real-time monitoring of mission execution

**Key Metrics:**
- Active missions count
- Completed missions (last hour)
- Failed missions (last hour)
- Total LLM cost (USD)
- Token consumption rate

**Panels:**
- **Active Missions Table** - Mission name, status, duration, agents deployed
- **Mission Timeline** - Gantt-style view of mission execution
- **Success/Failure Rate** - Time series of mission outcomes
- **Recent Errors** - Latest mission errors with stack traces

**PromQL Examples:**
```promql
# Active missions
gibson_missions_active

# Mission success rate (last hour)
sum(rate(gibson_missions_total{status="success"}[1h])) / sum(rate(gibson_missions_total[1h]))

# Average mission duration
histogram_quantile(0.95, rate(gibson_mission_duration_seconds_bucket[1h]))
```

### 2. Agent Performance Dashboard

**Purpose**: Deep-dive into agent execution metrics

**Key Metrics:**
- Agent execution counts by type
- Average agent duration
- Tool call frequency
- Error rates per agent

**Panels:**
- **Agent Execution Heatmap** - Agent activity over time
- **Tool Usage by Agent** - Bar chart of tool invocations
- **Agent Duration Distribution** - Histogram of execution times
- **Agent Error Log** - Loki panel showing agent errors

**PromQL Examples:**
```promql
# Agent executions per minute
sum(rate(gibson_agent_executions_total[1m])) by (agent_name)

# Agent error rate
sum(rate(gibson_agent_executions_total{status="error"}[5m])) by (agent_name) /
sum(rate(gibson_agent_executions_total[5m])) by (agent_name)

# Tool calls per agent
sum(rate(gibson_tool_calls_total[1h])) by (agent_name, tool)
```

### 3. LLM Analytics Dashboard

**Purpose**: Track LLM usage, costs, and performance using OpenTelemetry GenAI conventions

**Key Metrics:**
- Total tokens (input/output)
- Cost per model
- Latency percentiles
- Completion success rate

**Panels:**
- **Token Usage Over Time** - Stacked area chart by model
- **Cost Breakdown** - Pie chart by provider/model
- **Latency Heatmap** - Response time distribution
- **Model Comparison** - Table comparing models on cost/latency

**PromQL Examples:**
```promql
# Total tokens per hour by model
sum(rate(gibson_llm_tokens_input_total[1h]) + rate(gibson_llm_tokens_output_total[1h])) by (model)

# LLM cost per hour
sum(rate(gibson_llm_cost_usd[1h])) by (provider, model)

# P95 latency by model
histogram_quantile(0.95, rate(gibson_llm_latency_ms_bucket[5m])) by (model)
```

### 4. Knowledge Graph Dashboard

**Purpose**: Visualize GraphRAG entity growth and relationships

**Key Metrics:**
- Total entities stored
- Entities by type (Host, Port, Service, etc.)
- Relationships created
- Query performance

**Panels:**
- **Entity Growth Over Time** - Cumulative entity count
- **Entity Distribution** - Pie chart by type
- **Neo4j Query Latency** - Time series of query performance
- **Recent Graph Operations** - Log of graph writes

**PromQL Examples:**
```promql
# Graph write operations
sum(rate(gibson_graph_operations_total[1m])) by (operation)

# Entity count by type
gibson_graph_entities_total by (entity_type)
```

## Configuration

### Grafana Data Sources

Configure these data sources in Grafana:

**Prometheus:**
```yaml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    url: http://prometheus:9090
    isDefault: true
```

**Loki:**
```yaml
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    url: http://loki:3100
```

**Tempo (Traces):**
```yaml
apiVersion: 1
datasources:
  - name: Tempo
    type: tempo
    url: http://tempo:3200
```

### Gibson Configuration

```yaml
observability:
  tracing:
    enabled: true
    provider: "otlp"
    endpoint: "http://otel-collector:4317"
    service_name: "gibson"
  metrics:
    enabled: true
    provider: "prometheus"
    port: 9090
  content_logging:
    enabled: true
    max_prompt_length: 10000
    max_completion_length: 10000
```

## Deployment

### Local Development

```bash
# Start observability stack with Docker Compose
docker-compose -f docker-compose.observability.yaml up -d

# Access Grafana
open http://localhost:3000

# Default credentials: admin/admin
```

**docker-compose.observability.yaml:**
```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  loki:
    image: grafana/loki:latest
    ports:
      - "3100:3100"

  tempo:
    image: grafana/tempo:latest
    ports:
      - "3200:3200"
      - "4317:4317"

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
```

### Kubernetes Deployment

```bash
# Deploy with Helm
helm upgrade --install gibson ./helm/gibson \
  --namespace gibson-system \
  --create-namespace \
  --set observability.grafana.enabled=true \
  --set observability.prometheus.enabled=true \
  --set observability.loki.enabled=true \
  --set observability.tempo.enabled=true
```

**Helm Values:**
```yaml
observability:
  grafana:
    enabled: true
    ingress:
      enabled: true
      host: grafana.example.com
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true
  loki:
    enabled: true
  tempo:
    enabled: true
```

## Neo4j Integration

### Graph Explorer Links

Gibson generates Neo4j Browser URLs for exploring mission graphs:

**Link Format:**
```
http://neo4j.example.com/browser/?cmd=play&arg={encoded-cypher-query}
```

**Example Queries:**

**Full Mission Graph:**
```cypher
MATCH (n)-[r]-(m)
WHERE n.mission_id = 'mission-abc123' OR m.mission_id = 'mission-abc123'
RETURN n, r, m
```

**Hosts with Ports:**
```cypher
MATCH (h:Host)-[:HAS_PORT]->(p:Port)
WHERE h.mission_id = 'mission-abc123'
RETURN h, p
```

### Configuration

```yaml
graphrag:
  enabled: true
  neo4j:
    uri: "bolt://neo4j:7687"
    username: "neo4j"
    password: "${NEO4J_PASSWORD}"

observability:
  neo4j_browser_url: "http://neo4j.example.com:7474"
```

## Alerting

### Prometheus Alerting Rules

```yaml
groups:
  - name: gibson
    rules:
      - alert: HighMissionFailureRate
        expr: sum(rate(gibson_missions_total{status="failed"}[5m])) / sum(rate(gibson_missions_total[5m])) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High mission failure rate"

      - alert: LLMCostSpike
        expr: sum(rate(gibson_llm_cost_usd[1h])) > 10
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "LLM cost exceeding $10/hour"

      - alert: AgentStuck
        expr: gibson_agent_execution_duration_seconds > 3600
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Agent execution exceeding 1 hour"
```

## Troubleshooting

### No Metrics in Grafana

1. Check Prometheus is scraping Gibson:
   ```bash
   curl http://prometheus:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job=="gibson")'
   ```

2. Verify Gibson metrics endpoint:
   ```bash
   curl http://gibson:9090/metrics | grep gibson_
   ```

3. Check ServiceMonitor is deployed:
   ```bash
   kubectl get servicemonitor -n gibson-system
   ```

### No Traces in Tempo

1. Verify OTLP endpoint is configured:
   ```bash
   kubectl exec -n gibson deploy/gibson -- env | grep OTEL
   ```

2. Check Tempo is receiving traces:
   ```bash
   curl http://tempo:3200/api/search
   ```

### Logs Not Appearing in Loki

1. Check Promtail is running:
   ```bash
   kubectl get pods -n gibson-system -l app=promtail
   ```

2. Verify log format is JSON:
   ```bash
   kubectl logs -n gibson-system deploy/gibson | head -5
   ```

## Related Documentation

- [LOGGING.md](LOGGING.md) - Complete observability configuration
- [MISSIONS.md](MISSIONS.md) - Mission execution and orchestration
- [observability/activity-logging.md](observability/activity-logging.md) - Activity stream events
