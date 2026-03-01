# Activity Stream Logging - Requirements Specification

## Overview

**Spec Name:** activity-stream-logging
**Version:** 1.0.0
**Created:** 2026-03-01
**Status:** Draft

### Problem Statement

Gibson is an autonomous security testing framework that orchestrates LLM-powered agents. During mission execution, critical activities occur across the system:

- **Agent LLM interactions**: System prompts, user messages, assistant responses, tool calls
- **Tool executions**: Which tools are called, with what parameters, and their results
- **Orchestrator decisions**: Agent selection, execution flow decisions, mission state changes
- **Discovery events**: Assets found, vulnerabilities detected, knowledge graph updates

Currently, this activity data is:
1. **Only visible in Langfuse** - requires switching to a separate UI, no real-time streaming
2. **Not logged to stdout/stderr** - container logs don't contain LLM content (intentionally, but limits observability)
3. **Not queryable via Loki/Grafana** - no structured event stream for dashboarding
4. **Fragmented** - different systems log different aspects with no unified view

Security operators need a **single, real-time activity stream** that shows the complete decision-making process of Gibson agents as it happens - like a terminal view but structured, color-coded, and filterable.

### Goals

1. **Unified Activity Stream**: Single source for all agent activities with consistent structure
2. **Real-Time Visibility**: Stream events as they happen with sub-second latency
3. **Grafana Integration**: Display activity in Grafana Loki Logs panel with color-coding
4. **Full LLM Content**: Include actual prompts and responses (with optional truncation)
5. **Structured Format**: JSON logs with consistent schema for parsing and filtering
6. **Correlation**: Link events to missions, agents, and traces (Langfuse/OpenTelemetry)
7. **Production-Ready**: Minimal performance impact, configurable verbosity levels

### Target User Experience

Grafana dashboard with a large activity stream panel showing:
```
[02:15:33] API-DISCOVERY  STARTING     Starting API discovery for target: crapi.local
[02:15:34] API-DISCOVERY  PROMPT       "You are an API discovery specialist. Your goal is..."
[02:15:36] API-DISCOVERY  RESPONSE     "I'll start by probing common API paths to discover..."
[02:15:36] API-DISCOVERY  TOOL_CALL    httpx_probe targets=["/api", "/v1", "/swagger.json"]
[02:15:38] API-DISCOVERY  TOOL_RESULT  Found 3 endpoints: /api (200), /v1 (200), /swagger.json (200)
[02:15:38] ORCHESTRATOR   DECISION     continue - Agent progressing well, 15 endpoints discovered
[02:15:39] API-DISCOVERY  FINDING      [MEDIUM] Exposed Swagger documentation at /swagger.json
```

---

## Functional Requirements

### FR-1: Event Types and Schema

#### FR-1.1: Core Event Types
**As a** security operator
**I want** all significant agent activities captured as typed events
**So that** I can understand exactly what Gibson is doing

**Event Types:**
- `AGENT_START` - Agent begins executing a task
- `AGENT_END` - Agent completes execution
- `LLM_PROMPT` - System prompt or user message sent to LLM
- `LLM_RESPONSE` - LLM response received
- `TOOL_CALL` - Tool invocation with parameters
- `TOOL_RESULT` - Tool execution result
- `FINDING` - Security finding discovered
- `DECISION` - Orchestrator decision made
- `ERROR` - Error occurred
- `MEMORY_STORE` - Data stored to memory
- `MEMORY_RECALL` - Data retrieved from memory
- `GRAPHRAG_STORE` - Asset/relationship stored to knowledge graph
- `DELEGATION` - Agent delegated to sub-agent

**Acceptance Criteria:**
- [ ] All event types defined with consistent schema
- [ ] Events include timestamp, mission_id, agent_name, event_type, and payload
- [ ] Payloads are type-specific with documented fields
- [ ] Events are JSON-serializable for Loki ingestion

#### FR-1.2: Event Schema Definition
**As a** developer
**I want** a well-defined event schema
**So that** I can parse and filter events reliably

**Schema:**
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

**Acceptance Criteria:**
- [ ] Schema documented with all fields and types
- [ ] Required vs optional fields clearly defined
- [ ] Payload schemas defined per event type
- [ ] Schema versioning for future evolution

#### FR-1.3: Content Truncation
**As a** operator with limited log storage
**I want** configurable content truncation
**So that** I can balance detail vs storage costs

**Acceptance Criteria:**
- [ ] Configurable max content length (default: 500 chars)
- [ ] `content_truncated: true` flag when truncated
- [ ] `content_length` always shows original length
- [ ] Full content available via Langfuse trace_id link
- [ ] Truncation preserves beginning and end with "..." in middle

---

### FR-2: Logging Infrastructure

#### FR-2.1: Structured Logger
**As a** developer
**I want** a dedicated activity logger component
**So that** I can emit events from anywhere in the codebase

**Acceptance Criteria:**
- [ ] `ActivityLogger` interface with `Emit(event ActivityEvent)` method
- [ ] Thread-safe implementation
- [ ] Async buffered writes to avoid blocking agent execution
- [ ] Graceful shutdown with event flushing
- [ ] Configurable output (stdout, file, both)

#### FR-2.2: JSON Output Format
**As a** Promtail/Loki consumer
**I want** events logged as single-line JSON
**So that** they can be ingested and parsed by Loki

**Acceptance Criteria:**
- [ ] Each event is one JSON line (no multi-line)
- [ ] Consistent field ordering for grep-ability
- [ ] No nested objects beyond payload (flat top-level)
- [ ] UTF-8 encoding with proper escaping
- [ ] Labels suitable for Loki stream selection

#### FR-2.3: Log Levels
**As a** operator
**I want** configurable verbosity levels
**So that** I can tune the amount of logging

**Levels:**
- `QUIET` - Only errors and findings
- `NORMAL` - Agent start/end, findings, errors, decisions
- `VERBOSE` - All events including LLM content
- `DEBUG` - Full content with no truncation

**Acceptance Criteria:**
- [ ] Level configurable via environment variable `GIBSON_ACTIVITY_LOG_LEVEL`
- [ ] Level configurable in config.yaml
- [ ] Level changeable at runtime via admin API
- [ ] Default level is `NORMAL`

---

### FR-3: Integration Points

#### FR-3.1: Harness Integration
**As a** harness developer
**I want** activity logging integrated into the harness
**So that** all LLM and tool calls are automatically logged

**Acceptance Criteria:**
- [ ] `Complete()` logs LLM_PROMPT and LLM_RESPONSE events
- [ ] `CompleteWithTools()` logs tool calls within response
- [ ] `CallToolProto()` logs TOOL_CALL and TOOL_RESULT events
- [ ] `SubmitFinding()` logs FINDING events
- [ ] Activity logger injected via harness factory

#### FR-3.2: Orchestrator Integration
**As a** orchestrator developer
**I want** decision events logged
**So that** the reasoning behind mission flow is visible

**Acceptance Criteria:**
- [ ] `DECISION` events logged with action and reasoning
- [ ] Agent selection decisions logged
- [ ] Mission state transitions logged
- [ ] Checkpoint creation logged
- [ ] Error recovery decisions logged

#### FR-3.3: Callback Service Integration
**As a** daemon developer
**I want** callback events logged
**So that** agent-daemon communication is visible

**Acceptance Criteria:**
- [ ] LLM requests via callback logged
- [ ] Tool dispatch via callback logged
- [ ] Memory operations via callback logged
- [ ] GraphRAG operations via callback logged

#### FR-3.4: Langfuse Correlation
**As a** operator debugging issues
**I want** events linked to Langfuse traces
**So that** I can drill down into full details

**Acceptance Criteria:**
- [ ] `langfuse_trace_id` included in all events when available
- [ ] `langfuse_span_id` included for nested operations
- [ ] Events include direct Langfuse URL when configured
- [ ] Correlation maintained across agent delegation

---

### FR-4: Grafana Dashboard

#### FR-4.1: Activity Stream Panel
**As a** security operator
**I want** a large activity stream panel in Grafana
**So that** I can watch agent activity in real-time

**Acceptance Criteria:**
- [ ] Loki Logs panel configured for activity events
- [ ] Real-time streaming (live tail mode)
- [ ] Color-coded by event type
- [ ] Filterable by mission_id, agent_name, event_type
- [ ] Expandable rows for full content
- [ ] Time range selection

#### FR-4.2: Color Coding
**As a** operator scanning logs quickly
**I want** events visually distinguished by type
**So that** I can identify important events at a glance

**Color Scheme:**
- `AGENT_START` - Green
- `AGENT_END` - Green (dimmed)
- `LLM_PROMPT` - Blue
- `LLM_RESPONSE` - Cyan
- `TOOL_CALL` - Yellow
- `TOOL_RESULT` - Yellow (dimmed)
- `FINDING` - Red/Orange based on severity
- `DECISION` - Purple
- `ERROR` - Red (bright)

**Acceptance Criteria:**
- [ ] Color rules defined in Grafana panel
- [ ] Severity-based coloring for findings (critical=red, high=orange, etc.)
- [ ] Consistent with existing Grafana theme

#### FR-4.3: Dashboard Layout
**As a** operator monitoring Gibson
**I want** a focused dashboard with activity stream
**So that** I can see what matters

**Dashboard Contents:**
1. **Activity Stream** (large, 70% of view) - Real-time event log
2. **Knowledge Graph Stats** (small) - Nodes discovered count
3. **Mission Status** (small) - Current mission state

**Acceptance Criteria:**
- [ ] Dashboard JSON template created
- [ ] Dashboard deployed via ConfigMap
- [ ] Variables for mission_id filtering
- [ ] Auto-refresh enabled (5s)
- [ ] Time range default: last 1 hour

---

### FR-5: Kubernetes/Loki Integration

#### FR-5.1: Promtail Configuration
**As a** DevOps engineer
**I want** Promtail configured to parse activity logs
**So that** they're properly indexed in Loki

**Acceptance Criteria:**
- [ ] Promtail pipeline for JSON parsing
- [ ] Labels extracted: event_type, agent_name, mission_id, level
- [ ] Timestamp parsing from event JSON
- [ ] Multi-line handling disabled for activity logs

#### FR-5.2: Loki Label Strategy
**As a** Loki administrator
**I want** efficient label cardinality
**So that** queries are fast and storage is optimized

**Labels:**
- `app` = "gibson"
- `component` = "activity" (distinguishes from other gibson logs)
- `event_type` = dynamic (limited set)
- `agent_name` = dynamic (limited set)

**Acceptance Criteria:**
- [ ] Label cardinality documented
- [ ] High-cardinality fields (mission_id, trace_id) in log line, not labels
- [ ] Loki queries documented for common use cases

---

### FR-6: Configuration

#### FR-6.1: Environment Variables
**As a** operator deploying Gibson
**I want** environment-based configuration
**So that** I can configure logging without code changes

**Variables:**
- `GIBSON_ACTIVITY_LOG_ENABLED` - Enable/disable (default: true)
- `GIBSON_ACTIVITY_LOG_LEVEL` - Verbosity (default: NORMAL)
- `GIBSON_ACTIVITY_LOG_MAX_CONTENT` - Max content length (default: 500)
- `GIBSON_ACTIVITY_LOG_OUTPUT` - stdout, file, both (default: stdout)
- `GIBSON_ACTIVITY_LOG_FILE` - File path if output includes file

**Acceptance Criteria:**
- [ ] All variables documented
- [ ] Validation on startup
- [ ] Sensible defaults
- [ ] Override via config.yaml supported

#### FR-6.2: Config File Support
**As a** operator with complex configuration
**I want** YAML configuration for activity logging
**So that** I can version control settings

**Config Section:**
```yaml
activity_logging:
  enabled: true
  level: VERBOSE
  max_content_length: 1000
  output: stdout
  file_path: /var/log/gibson/activity.log
  include_langfuse_urls: true
```

**Acceptance Criteria:**
- [ ] Config section parsed from gibson.yaml
- [ ] Environment variables override config file
- [ ] Schema validation with helpful errors
- [ ] Hot reload for level changes (future)

---

## Non-Functional Requirements

### NFR-1: Performance

#### NFR-1.1: Latency Impact
- Activity logging adds < 1ms to LLM completion calls
- Activity logging adds < 100μs to tool calls
- Async buffering prevents blocking agent execution

#### NFR-1.2: Throughput
- Support 1000 events/second sustained
- Buffer up to 10,000 events before applying backpressure
- Graceful degradation under load (drop events vs block)

#### NFR-1.3: Memory
- Event buffer uses < 10MB RAM
- Events serialized immediately to avoid holding large objects
- Circular buffer discards oldest events under memory pressure

### NFR-2: Reliability

#### NFR-2.1: Event Delivery
- At-least-once delivery for persisted outputs (file)
- Best-effort for stdout (acceptable to lose on crash)
- Flush on graceful shutdown
- Metrics for dropped events

#### NFR-2.2: Error Handling
- Logging errors don't crash the agent
- Malformed events logged with error marker
- Self-monitoring metrics exposed

### NFR-3: Security

#### NFR-3.1: Sensitive Data
- PII/credential detection in content (warning if detected)
- Optional redaction mode for sensitive deployments
- Labels don't contain sensitive data (only event structure)

#### NFR-3.2: Access Control
- Log files have restricted permissions (0640)
- Loki access controlled via Grafana RBAC
- No authentication secrets in events

### NFR-4: Observability

#### NFR-4.1: Metrics
- `gibson_activity_events_total` - Counter by event_type
- `gibson_activity_events_dropped` - Counter of dropped events
- `gibson_activity_buffer_size` - Gauge of buffer utilization
- `gibson_activity_write_latency` - Histogram of write times

---

## Dependencies

### Internal Dependencies
- `internal/harness` - LLM/tool execution context
- `internal/orchestrator` - Decision logging
- `internal/daemon` - Callback service logging
- `internal/observability` - Metrics/tracing integration
- `internal/config` - Configuration loading

### External Dependencies
- `encoding/json` - Standard library JSON
- `log/slog` - Structured logging (Go 1.21+)
- Loki - Log aggregation (existing infrastructure)
- Promtail - Log shipping (existing infrastructure)
- Grafana - Dashboard visualization (existing infrastructure)

---

## Out of Scope (v1)

- Log shipping to external systems (CloudWatch, Datadog, etc.)
- Event filtering at source (all events emitted, filter in Loki)
- Custom event types (fixed set in v1)
- Web UI for activity stream (Grafana only)
- Alerting on event patterns (future integration)
- Event replay/playback
- Agent-side activity logging (daemon only in v1)

---

## Glossary

| Term | Definition |
|------|------------|
| **Activity Event** | A structured log entry capturing agent/system activity |
| **Activity Stream** | Real-time feed of activity events |
| **Loki** | Log aggregation system (Grafana Loki) |
| **Promtail** | Log shipping agent for Loki |
| **Event Type** | Category of activity (LLM_PROMPT, TOOL_CALL, etc.) |
| **Payload** | Event-type-specific data structure |
| **Truncation** | Shortening content to fit storage limits |

---

## Success Metrics

1. **Adoption**: Activity stream panel used by operators during missions
2. **Completeness**: All LLM interactions visible in stream
3. **Latency**: Events appear within 2s of occurrence
4. **Performance**: No measurable impact on mission execution time
5. **Reliability**: < 0.1% event loss under normal operation
6. **Usability**: Operators can debug agent behavior without Langfuse

---

## Related Specifications

- Langfuse integration (existing)
- OpenTelemetry tracing (existing)
- Prometheus metrics (existing)
- Mission Report Synthesis (future integration)
