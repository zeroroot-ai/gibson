# Activity Stream Logging

Gibson's activity stream logging provides real-time visibility into agent decision loops, LLM interactions, and tool executions via structured JSON events sent to Loki and visualized in Grafana.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GIBSON_ACTIVITY_LOG_ENABLED` | `true` | Enable/disable activity logging |
| `GIBSON_ACTIVITY_LOG_LEVEL` | `normal` | Verbosity: quiet, normal, verbose, debug |
| `GIBSON_ACTIVITY_LOG_MAX_CONTENT` | `500` | Max content length before truncation |
| `GIBSON_ACTIVITY_LOG_OUTPUT` | `stdout` | Output: stdout, file, both |
| `GIBSON_ACTIVITY_LOG_FILE` | `` | File path (required when output includes file) |

### YAML Configuration

```yaml
activity_logging:
  enabled: true
  level: verbose
  max_content_length: 1000
  output: stdout
  buffer_size: 10000
  include_langfuse_urls: true
```

### Verbosity Levels

| Level | Events Logged |
|-------|---------------|
| `quiet` | ERROR, FINDING only |
| `normal` | AGENT_START, AGENT_END, FINDING, ERROR, DECISION |
| `verbose` | All events (LLM content truncated) |
| `debug` | All events (full content, no truncation) |

## Event Types

| Event Type | Description | Payload Fields |
|------------|-------------|----------------|
| `AGENT_START` | Agent begins execution | task_description, task_id |
| `AGENT_END` | Agent completes | status, duration_ms, finding_count |
| `LLM_PROMPT` | Message sent to LLM | slot, role, content, message_index |
| `LLM_RESPONSE` | LLM response received | slot, provider, model, content, tokens |
| `TOOL_CALL` | Tool invocation | tool_name, parameters |
| `TOOL_RESULT` | Tool execution result | tool_name, success, result, latency_ms |
| `FINDING` | Security finding discovered | title, severity, confidence, category |
| `DECISION` | Orchestrator decision | action, target, reasoning, confidence |
| `ERROR` | Error occurred | operation, error, error_type |

## Event Schema

```json
{
  "timestamp": "2026-03-01T02:15:33.123Z",
  "level": "INFO",
  "event_type": "LLM_PROMPT",
  "mission_id": "miss_abc123",
  "agent_name": "api-discovery",
  "trace_id": "abc123def456",
  "span_id": "span789",
  "langfuse_trace_id": "lf_xyz",
  "payload": {
    "slot": "primary",
    "role": "system",
    "content": "You are an API discovery specialist...",
    "content_truncated": false,
    "content_length": 1234,
    "message_index": 0
  }
}
```

## Loki Label Strategy

### Labels (Low Cardinality)

Used for stream selection, indexed by Loki:

| Label | Values | Description |
|-------|--------|-------------|
| `app` | `gibson` | Application name |
| `component` | `activity` | Distinguishes from other logs |
| `event_type` | 13 values | Event category |
| `agent_name` | ~20 values | Agent producing the event |
| `level` | INFO, WARN, ERROR, DEBUG | Log level |

### High Cardinality Fields (In Log Line)

Queryable via LogQL JSON parsing:

- `mission_id` - Unique per mission
- `trace_id` - OpenTelemetry trace ID
- `span_id` - OpenTelemetry span ID
- `langfuse_trace_id` - Langfuse trace link

## LogQL Query Examples

### Basic Queries

```logql
# All activity events
{app="gibson", component="activity"}

# Events for a specific mission
{app="gibson", component="activity"} |= "miss_abc123"

# All LLM prompts
{app="gibson", component="activity", event_type="LLM_PROMPT"}

# All findings
{app="gibson", component="activity", event_type="FINDING"}

# Errors only
{app="gibson", component="activity", level="ERROR"}
```

### Filtered by Agent

```logql
# All events from api-discovery agent
{app="gibson", component="activity", agent_name="api-discovery"}

# LLM responses from network-recon
{app="gibson", component="activity", event_type="LLM_RESPONSE", agent_name="network-recon"}
```

### JSON Field Extraction

```logql
# Findings with severity
{app="gibson", component="activity", event_type="FINDING"}
| json
| payload_severity="critical"

# Tool calls taking more than 5 seconds
{app="gibson", component="activity", event_type="TOOL_RESULT"}
| json
| payload_latency_ms > 5000

# LLM responses with high token usage
{app="gibson", component="activity", event_type="LLM_RESPONSE"}
| json
| payload_output_tokens > 1000
```

### Aggregations

```logql
# Event count by type (last hour)
sum by (event_type) (count_over_time({app="gibson", component="activity"}[1h]))

# Events per minute
sum(rate({app="gibson", component="activity"}[1m]))

# Findings by severity
sum by (payload_severity) (
  count_over_time({app="gibson", component="activity", event_type="FINDING"} | json [1h])
)
```

### Correlation Queries

```logql
# Full trace for a mission (ordered by time)
{app="gibson", component="activity"} |= "miss_abc123" | line_format "{{.timestamp}} {{.event_type}} {{.agent_name}}"

# Link to Langfuse trace
{app="gibson", component="activity"}
| json
| langfuse_trace_id != ""
| line_format "Langfuse: https://langfuse.example.com/trace/{{.langfuse_trace_id}}"
```

## Grafana Dashboard

The Activity Stream dashboard provides:

1. **Activity Stream Panel** (70% of view)
   - Real-time event log with live tail
   - Color-coded by event type
   - Expandable rows for full content
   - Filterable by mission, agent, event type

2. **Knowledge Graph Panel**
   - Nodes discovered count
   - Hosts, endpoints, findings

3. **Mission Status Panel**
   - Current mission state
   - Agent status
   - Finding summary

### Color Coding

| Event Type | Color |
|------------|-------|
| AGENT_START | Green |
| AGENT_END | Green (dimmed) |
| LLM_PROMPT | Blue |
| LLM_RESPONSE | Cyan |
| TOOL_CALL | Yellow |
| TOOL_RESULT | Yellow (dimmed) |
| FINDING | Orange/Red (by severity) |
| DECISION | Purple |
| ERROR | Red (bright) |

## Prometheus Metrics

Activity logging exposes Prometheus metrics:

```promql
# Total events by type
gibson_activity_events_total{event_type="LLM_PROMPT"}

# Dropped events (buffer overflow)
gibson_activity_events_dropped_total

# Current buffer size
gibson_activity_buffer_size
```

## Troubleshooting

### No Events in Loki

1. Check activity logging is enabled:
   ```bash
   kubectl exec -n gibson deploy/gibson -- env | grep GIBSON_ACTIVITY
   ```

2. Check Promtail is running:
   ```bash
   kubectl get pods -n gibson -l app.kubernetes.io/component=promtail
   ```

3. Check Promtail logs:
   ```bash
   kubectl logs -n gibson -l app.kubernetes.io/component=promtail
   ```

### Events Not Parsed Correctly

1. Verify JSON format in Gibson logs:
   ```bash
   kubectl logs -n gibson deploy/gibson | grep '"event_type"'
   ```

2. Check Promtail pipeline stages are matching

### High Memory Usage

1. Reduce buffer size:
   ```yaml
   activity_logging:
     buffer_size: 1000
   ```

2. Increase verbosity level (fewer events):
   ```yaml
   activity_logging:
     level: normal  # instead of verbose
   ```

### Events Being Dropped

Check the `gibson_activity_events_dropped_total` metric. If high:
- Increase buffer size
- Reduce logging level
- Check Loki ingestion rate
