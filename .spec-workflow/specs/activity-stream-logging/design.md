# Activity Stream Logging - Design Specification

## Overview

**Spec Name:** activity-stream-logging
**Version:** 1.0.0
**Created:** 2026-03-01
**Status:** Draft

This document describes the technical design for implementing real-time activity stream logging in Gibson, enabling Grafana-based visualization of agent decision loops, LLM interactions, and tool executions.

---

## Architecture Overview

### High-Level Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GIBSON DAEMON                                   │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────────────┐  │
│  │ Orchestrator│───▶│   Harness   │───▶│     ActivityLogger              │  │
│  │  (decisions)│    │ (LLM/tools) │    │  ┌─────────────────────────────┐│  │
│  └─────────────┘    └─────────────┘    │  │ JSON Encoder → stdout/file  ││  │
│         │                  │           │  └─────────────────────────────┘│  │
│         │                  │           └─────────────────────────────────┘  │
│         │                  │                            │                    │
│         ▼                  ▼                            ▼                    │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                         Container stdout                                 ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              PROMTAIL                                        │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ Pipeline: JSON parse → Label extraction → Timestamp parse                ││
│  │ Labels: app=gibson, component=activity, event_type, agent_name           ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                                LOKI                                          │
│  Log stream: {app="gibson", component="activity"}                           │
│  Queryable by: event_type, agent_name, mission_id (in log line)             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GRAFANA                                         │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │ Activity Stream Panel (Loki Logs)                                        ││
│  │ Color-coded by event_type, filterable, real-time tail                   ││
│  └─────────────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Design

### 1. ActivityLogger Interface

**Location:** `internal/observability/activity.go`

```go
// ActivityEvent represents a structured activity event for logging.
type ActivityEvent struct {
    Timestamp       time.Time              `json:"timestamp"`
    Level           string                 `json:"level"`
    EventType       ActivityEventType      `json:"event_type"`
    MissionID       string                 `json:"mission_id,omitempty"`
    AgentName       string                 `json:"agent_name,omitempty"`
    TraceID         string                 `json:"trace_id,omitempty"`
    SpanID          string                 `json:"span_id,omitempty"`
    LangfuseTraceID string                 `json:"langfuse_trace_id,omitempty"`
    Payload         map[string]interface{} `json:"payload"`
}

// ActivityEventType defines the type of activity event.
type ActivityEventType string

const (
    EventAgentStart      ActivityEventType = "AGENT_START"
    EventAgentEnd        ActivityEventType = "AGENT_END"
    EventLLMPrompt       ActivityEventType = "LLM_PROMPT"
    EventLLMResponse     ActivityEventType = "LLM_RESPONSE"
    EventToolCall        ActivityEventType = "TOOL_CALL"
    EventToolResult      ActivityEventType = "TOOL_RESULT"
    EventFinding         ActivityEventType = "FINDING"
    EventDecision        ActivityEventType = "DECISION"
    EventError           ActivityEventType = "ERROR"
    EventMemoryStore     ActivityEventType = "MEMORY_STORE"
    EventMemoryRecall    ActivityEventType = "MEMORY_RECALL"
    EventGraphRAGStore   ActivityEventType = "GRAPHRAG_STORE"
    EventDelegation      ActivityEventType = "DELEGATION"
)

// ActivityLevel defines the verbosity level for activity logging.
type ActivityLevel int

const (
    ActivityLevelQuiet   ActivityLevel = iota // Only errors and findings
    ActivityLevelNormal                        // Agent lifecycle, findings, errors, decisions
    ActivityLevelVerbose                       // All events including LLM content (truncated)
    ActivityLevelDebug                         // Full content, no truncation
)

// ActivityLogger emits structured activity events.
type ActivityLogger interface {
    // Emit logs an activity event at the appropriate level.
    Emit(ctx context.Context, event ActivityEvent)

    // EmitAgentStart logs an agent starting execution.
    EmitAgentStart(ctx context.Context, agentName string, taskDescription string)

    // EmitAgentEnd logs an agent completing execution.
    EmitAgentEnd(ctx context.Context, agentName string, status string, durationMs int64)

    // EmitLLMPrompt logs messages sent to an LLM.
    EmitLLMPrompt(ctx context.Context, slot string, messages []llm.Message)

    // EmitLLMResponse logs an LLM response.
    EmitLLMResponse(ctx context.Context, slot string, response *llm.CompletionResponse)

    // EmitToolCall logs a tool invocation.
    EmitToolCall(ctx context.Context, toolName string, params interface{})

    // EmitToolResult logs a tool execution result.
    EmitToolResult(ctx context.Context, toolName string, result interface{}, durationMs int64, err error)

    // EmitFinding logs a security finding discovery.
    EmitFinding(ctx context.Context, finding *agent.Finding)

    // EmitDecision logs an orchestrator decision.
    EmitDecision(ctx context.Context, action string, target string, reasoning string, confidence float64)

    // EmitError logs an error event.
    EmitError(ctx context.Context, operation string, err error)

    // Level returns the current activity logging level.
    Level() ActivityLevel

    // SetLevel changes the activity logging level.
    SetLevel(level ActivityLevel)

    // Flush ensures all buffered events are written.
    Flush() error

    // Close shuts down the logger gracefully.
    Close() error
}
```

### 2. ActivityLogger Implementation

**Location:** `internal/observability/activity_impl.go`

```go
// DefaultActivityLogger implements ActivityLogger with JSON output to stdout.
type DefaultActivityLogger struct {
    mu              sync.Mutex
    level           ActivityLevel
    maxContentLen   int
    output          io.Writer
    encoder         *json.Encoder
    missionID       string
    agentName       string
    langfuseTraceID string

    // Buffer for async writes
    eventChan       chan ActivityEvent
    doneChan        chan struct{}

    // Metrics
    eventsEmitted   atomic.Int64
    eventsDropped   atomic.Int64
}

// NewActivityLogger creates a new activity logger with the given configuration.
func NewActivityLogger(cfg ActivityLoggerConfig) (*DefaultActivityLogger, error) {
    logger := &DefaultActivityLogger{
        level:         cfg.Level,
        maxContentLen: cfg.MaxContentLength,
        output:        cfg.Output,
        eventChan:     make(chan ActivityEvent, cfg.BufferSize),
        doneChan:      make(chan struct{}),
    }

    logger.encoder = json.NewEncoder(logger.output)

    // Start async writer goroutine
    go logger.writeLoop()

    return logger, nil
}

// writeLoop processes events from the buffer asynchronously.
func (l *DefaultActivityLogger) writeLoop() {
    for {
        select {
        case event := <-l.eventChan:
            if err := l.encoder.Encode(event); err != nil {
                // Log encoding error to stderr, don't block
                fmt.Fprintf(os.Stderr, "activity logger encode error: %v\n", err)
            }
            l.eventsEmitted.Add(1)
        case <-l.doneChan:
            // Drain remaining events
            for {
                select {
                case event := <-l.eventChan:
                    l.encoder.Encode(event)
                default:
                    return
                }
            }
        }
    }
}

// Emit sends an event to the buffer for async writing.
func (l *DefaultActivityLogger) Emit(ctx context.Context, event ActivityEvent) {
    // Check if event should be logged at current level
    if !l.shouldLog(event.EventType) {
        return
    }

    // Enrich event with context
    event = l.enrichEvent(ctx, event)

    // Non-blocking send to buffer
    select {
    case l.eventChan <- event:
        // Event queued
    default:
        // Buffer full, drop event and record metric
        l.eventsDropped.Add(1)
    }
}

// enrichEvent adds context fields from context and logger state.
func (l *DefaultActivityLogger) enrichEvent(ctx context.Context, event ActivityEvent) ActivityEvent {
    // Set timestamp if not provided
    if event.Timestamp.IsZero() {
        event.Timestamp = time.Now().UTC()
    }

    // Extract OpenTelemetry trace context
    if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
        event.TraceID = span.SpanContext().TraceID().String()
        event.SpanID = span.SpanContext().SpanID().String()
    }

    // Extract mission context from middleware context
    if missionID := middleware.GetMissionID(ctx); missionID != "" {
        event.MissionID = missionID
    }
    if agentName := middleware.GetAgentName(ctx); agentName != "" {
        event.AgentName = agentName
    }

    // Add Langfuse trace ID if available
    if l.langfuseTraceID != "" {
        event.LangfuseTraceID = l.langfuseTraceID
    }

    return event
}

// shouldLog determines if an event should be logged at the current level.
func (l *DefaultActivityLogger) shouldLog(eventType ActivityEventType) bool {
    switch l.level {
    case ActivityLevelQuiet:
        return eventType == EventError || eventType == EventFinding
    case ActivityLevelNormal:
        return eventType == EventAgentStart || eventType == EventAgentEnd ||
               eventType == EventFinding || eventType == EventError ||
               eventType == EventDecision
    case ActivityLevelVerbose, ActivityLevelDebug:
        return true
    default:
        return false
    }
}

// truncateContent shortens content if it exceeds maxContentLen.
func (l *DefaultActivityLogger) truncateContent(content string) (string, bool) {
    if l.level == ActivityLevelDebug || len(content) <= l.maxContentLen {
        return content, false
    }

    // Keep beginning and end with ellipsis in middle
    halfLen := (l.maxContentLen - 5) / 2 // 5 chars for " ... "
    return content[:halfLen] + " ... " + content[len(content)-halfLen:], true
}
```

### 3. Event Payload Schemas

**Location:** `internal/observability/activity_payloads.go`

```go
// LLMPromptPayload contains data for LLM_PROMPT events.
type LLMPromptPayload struct {
    Slot             string `json:"slot"`
    Role             string `json:"role"`
    Content          string `json:"content"`
    ContentTruncated bool   `json:"content_truncated"`
    ContentLength    int    `json:"content_length"`
    MessageIndex     int    `json:"message_index"`
    MessageCount     int    `json:"message_count"`
}

// LLMResponsePayload contains data for LLM_RESPONSE events.
type LLMResponsePayload struct {
    Slot             string   `json:"slot"`
    Provider         string   `json:"provider"`
    Model            string   `json:"model"`
    Content          string   `json:"content"`
    ContentTruncated bool     `json:"content_truncated"`
    ContentLength    int      `json:"content_length"`
    InputTokens      int      `json:"input_tokens"`
    OutputTokens     int      `json:"output_tokens"`
    FinishReason     string   `json:"finish_reason"`
    ToolCalls        []string `json:"tool_calls,omitempty"` // Tool names if present
    LatencyMs        int64    `json:"latency_ms"`
}

// ToolCallPayload contains data for TOOL_CALL events.
type ToolCallPayload struct {
    ToolName   string      `json:"tool_name"`
    Parameters interface{} `json:"parameters"`
    Remote     bool        `json:"remote"`
}

// ToolResultPayload contains data for TOOL_RESULT events.
type ToolResultPayload struct {
    ToolName   string      `json:"tool_name"`
    Success    bool        `json:"success"`
    Result     interface{} `json:"result,omitempty"`
    Error      string      `json:"error,omitempty"`
    LatencyMs  int64       `json:"latency_ms"`
    ResultSize int         `json:"result_size"`
}

// FindingPayload contains data for FINDING events.
type FindingPayload struct {
    FindingID   string   `json:"finding_id"`
    Title       string   `json:"title"`
    Severity    string   `json:"severity"`
    Confidence  float64  `json:"confidence"`
    Category    string   `json:"category"`
    CWE         []string `json:"cwe,omitempty"`
    MITRE       []string `json:"mitre,omitempty"`
}

// DecisionPayload contains data for DECISION events.
type DecisionPayload struct {
    Action      string  `json:"action"`
    Target      string  `json:"target,omitempty"`
    Reasoning   string  `json:"reasoning"`
    Confidence  float64 `json:"confidence"`
    Iteration   int     `json:"iteration"`
    TokensUsed  int     `json:"tokens_used"`
}

// AgentStartPayload contains data for AGENT_START events.
type AgentStartPayload struct {
    TaskDescription string `json:"task_description"`
    TaskID          string `json:"task_id,omitempty"`
}

// AgentEndPayload contains data for AGENT_END events.
type AgentEndPayload struct {
    Status       string `json:"status"` // completed, failed, cancelled
    DurationMs   int64  `json:"duration_ms"`
    FindingCount int    `json:"finding_count"`
    ToolCalls    int    `json:"tool_calls"`
    LLMCalls     int    `json:"llm_calls"`
}

// ErrorPayload contains data for ERROR events.
type ErrorPayload struct {
    Operation string `json:"operation"`
    Error     string `json:"error"`
    ErrorType string `json:"error_type,omitempty"`
}
```

---

## Integration Points

### 4. Harness Integration

**Location:** `internal/harness/implementation.go`

The ActivityLogger is injected into the harness via the factory and called at key execution points.

#### Complete() Integration (Lines ~100-206)

```go
func (h *DefaultAgentHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
    ctx, span := h.tracer.Start(ctx, "harness.Complete")
    defer span.End()

    // === ACTIVITY: Emit LLM_PROMPT for each message ===
    h.activityLogger.EmitLLMPrompt(ctx, slot, messages)

    startTime := time.Now()

    // ... existing slot resolution and provider execution ...

    resp, err := provider.Complete(ctx, model.ID, messages, convertedOpts...)
    if err != nil {
        // === ACTIVITY: Emit ERROR on failure ===
        h.activityLogger.EmitError(ctx, "llm_complete", err)
        return nil, err
    }

    // === ACTIVITY: Emit LLM_RESPONSE ===
    h.activityLogger.EmitLLMResponse(ctx, slot, resp)

    return resp, nil
}
```

#### CallToolProto() Integration (Lines ~434-793)

```go
func (h *DefaultAgentHarness) CallToolProto(ctx context.Context, toolName string, input proto.Message, output proto.Message) error {
    ctx, span := h.tracer.Start(ctx, "harness.CallToolProto")
    defer span.End()

    // === ACTIVITY: Emit TOOL_CALL ===
    h.activityLogger.EmitToolCall(ctx, toolName, input)

    startTime := time.Now()

    // ... existing tool lookup and execution ...

    if err != nil {
        // === ACTIVITY: Emit TOOL_RESULT with error ===
        h.activityLogger.EmitToolResult(ctx, toolName, nil, time.Since(startTime).Milliseconds(), err)
        return err
    }

    // === ACTIVITY: Emit TOOL_RESULT on success ===
    h.activityLogger.EmitToolResult(ctx, toolName, output, time.Since(startTime).Milliseconds(), nil)

    return nil
}
```

#### SubmitFinding() Integration

```go
func (h *DefaultAgentHarness) SubmitFinding(ctx context.Context, finding agent.Finding) error {
    // ... existing implementation ...

    // === ACTIVITY: Emit FINDING ===
    h.activityLogger.EmitFinding(ctx, &finding)

    return nil
}
```

### 5. Orchestrator Integration

**Location:** `internal/orchestrator/orchestrator.go`

#### Run() Loop Integration (Lines ~307-585)

```go
func (o *Orchestrator) Run(ctx context.Context, missionID string) error {
    // ... existing setup ...

    // === ACTIVITY: Emit AGENT_START at mission begin ===
    // (Note: This is for the orchestrator itself, not individual agents)

    for {
        // ... OBSERVE phase ...

        // THINK phase
        thinkResult, err := o.thinker.Think(ctx, state, history)

        // === ACTIVITY: Emit DECISION ===
        o.activityLogger.EmitDecision(ctx,
            string(thinkResult.Action),
            thinkResult.NodeID,
            thinkResult.Reasoning,
            thinkResult.Confidence,
        )

        // ... existing decision handling ...
    }
}
```

### 6. Callback Service Integration

**Location:** `internal/harness/callback_service.go`

The callback service receives LLM/tool requests from agents running in separate processes. Activity events are emitted when processing these callbacks.

```go
func (s *HarnessCallbackService) Complete(ctx context.Context, req *api.CompleteRequest) (*api.CompleteResponse, error) {
    // Lookup harness for mission
    harness, err := s.registry.GetHarness(req.MissionId)
    if err != nil {
        return nil, err
    }

    // Convert messages
    messages := convertProtoMessages(req.Messages)

    // === Activity logging happens inside harness.Complete() ===
    resp, err := harness.Complete(ctx, req.Slot, messages)

    return convertResponse(resp), err
}
```

---

## Configuration Design

### 7. Configuration Schema

**Location:** `internal/config/config.go`

```go
// ActivityLoggingConfig configures the activity stream logger.
type ActivityLoggingConfig struct {
    // Enabled controls whether activity logging is active.
    Enabled bool `yaml:"enabled" env:"GIBSON_ACTIVITY_LOG_ENABLED" default:"true"`

    // Level sets the verbosity level (quiet, normal, verbose, debug).
    Level string `yaml:"level" env:"GIBSON_ACTIVITY_LOG_LEVEL" default:"normal"`

    // MaxContentLength is the maximum characters for content fields before truncation.
    MaxContentLength int `yaml:"max_content_length" env:"GIBSON_ACTIVITY_LOG_MAX_CONTENT" default:"500"`

    // Output specifies where to write events (stdout, file, both).
    Output string `yaml:"output" env:"GIBSON_ACTIVITY_LOG_OUTPUT" default:"stdout"`

    // FilePath is the file path when output includes "file".
    FilePath string `yaml:"file_path" env:"GIBSON_ACTIVITY_LOG_FILE" default:""`

    // BufferSize is the event buffer size for async writes.
    BufferSize int `yaml:"buffer_size" default:"10000"`

    // IncludeLangfuseURLs adds Langfuse deep links to events.
    IncludeLangfuseURLs bool `yaml:"include_langfuse_urls" default:"true"`
}
```

**Config File Example (`gibson.yaml`):**

```yaml
activity_logging:
  enabled: true
  level: verbose
  max_content_length: 1000
  output: stdout
  include_langfuse_urls: true
```

---

## Kubernetes/Loki Integration

### 8. Promtail Pipeline Configuration

**Location:** `deploy/helm/gibson/templates/observability/promtail-configmap.yaml`

```yaml
scrape_configs:
  - job_name: gibson-activity
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
        action: keep
        regex: gibson
      - source_labels: [__meta_kubernetes_namespace]
        target_label: namespace
    pipeline_stages:
      # Match activity log lines (JSON with event_type field)
      - match:
          selector: '{app="gibson"}'
          stages:
            - json:
                expressions:
                  timestamp: timestamp
                  level: level
                  event_type: event_type
                  agent_name: agent_name
                  mission_id: mission_id
            - labels:
                event_type:
                agent_name:
                level:
            - timestamp:
                source: timestamp
                format: RFC3339Nano
            - output:
                source: message
```

### 9. Loki Label Strategy

**Labels (low cardinality):**
- `app` = "gibson" (static)
- `component` = "activity" (static, distinguishes from other gibson logs)
- `event_type` = dynamic (13 possible values)
- `agent_name` = dynamic (limited set of agent names)
- `level` = dynamic (INFO, WARN, ERROR, DEBUG)

**In Log Line (high cardinality, queryable via LogQL):**
- `mission_id` - unique per mission
- `trace_id` - unique per trace
- `span_id` - unique per span
- `langfuse_trace_id` - unique per Langfuse trace

**LogQL Query Examples:**

```logql
# All activity events for a mission
{app="gibson", component="activity"} |= "miss_abc123"

# All LLM prompts from api-discovery agent
{app="gibson", component="activity", event_type="LLM_PROMPT", agent_name="api-discovery"}

# All findings with severity
{app="gibson", component="activity", event_type="FINDING"} | json | severity="critical"

# Errors in last hour
{app="gibson", component="activity", level="ERROR"}

# Tool calls with duration > 5s
{app="gibson", component="activity", event_type="TOOL_RESULT"} | json | latency_ms > 5000
```

---

## Grafana Dashboard Design

### 10. Dashboard Layout

**Location:** `deploy/helm/gibson/files/dashboards/gibson-activity.json`

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  GIBSON ACTIVITY STREAM                              [Mission: $mission_id] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                                                                        │ │
│  │  ACTIVITY STREAM (Loki Logs Panel)                                    │ │
│  │                                                                        │ │
│  │  [02:15:33] API-DISCOVERY  STARTING   Starting API discovery...       │ │
│  │  [02:15:34] API-DISCOVERY  PROMPT     "You are an API discovery..."   │ │
│  │  [02:15:36] API-DISCOVERY  RESPONSE   "I'll start by probing..."      │ │
│  │  [02:15:36] API-DISCOVERY  TOOL_CALL  httpx_probe ["/api", "/v1"]     │ │
│  │  [02:15:38] API-DISCOVERY  TOOL_OK    Found 3 endpoints (200ms)       │ │
│  │  [02:15:38] ORCHESTRATOR   DECISION   continue - progressing well     │ │
│  │  [02:15:39] API-DISCOVERY  FINDING    [MEDIUM] Exposed Swagger docs   │ │
│  │                                                                        │ │
│  │                                                        [Live Tail: ON] │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                              │
│  ┌──────────────────────────┐  ┌──────────────────────────────────────────┐ │
│  │  KNOWLEDGE GRAPH          │  │  MISSION STATUS                          │ │
│  │  ┌────────────────────┐  │  │  Mission: crapi-discovery                │ │
│  │  │ Nodes: 47          │  │  │  Status:  Running                        │ │
│  │  │ Hosts: 3           │  │  │  Agent:   api-discovery                  │ │
│  │  │ Endpoints: 28      │  │  │  Uptime:  2m 15s                         │ │
│  │  │ Findings: 5        │  │  │  Findings: 5 (1 High, 4 Medium)          │ │
│  │  └────────────────────┘  │  │  Tokens:  12,450                         │ │
│  └──────────────────────────┘  └──────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11. Panel Configuration

**Activity Stream Panel (Loki Logs):**

```json
{
  "type": "logs",
  "title": "Activity Stream",
  "datasource": "Loki",
  "targets": [
    {
      "expr": "{app=\"gibson\", component=\"activity\"} |= \"$mission_id\"",
      "refId": "A"
    }
  ],
  "options": {
    "showTime": true,
    "showLabels": false,
    "showCommonLabels": false,
    "wrapLogMessage": true,
    "prettifyLogMessage": false,
    "enableLogDetails": true,
    "dedupStrategy": "none",
    "sortOrder": "Ascending"
  },
  "fieldConfig": {
    "overrides": [
      {
        "matcher": { "id": "byName", "options": "event_type" },
        "properties": [
          {
            "id": "custom.displayMode",
            "value": "color-background"
          },
          {
            "id": "mappings",
            "value": [
              { "type": "value", "options": { "AGENT_START": { "color": "green" } } },
              { "type": "value", "options": { "AGENT_END": { "color": "green" } } },
              { "type": "value", "options": { "LLM_PROMPT": { "color": "blue" } } },
              { "type": "value", "options": { "LLM_RESPONSE": { "color": "super-light-blue" } } },
              { "type": "value", "options": { "TOOL_CALL": { "color": "yellow" } } },
              { "type": "value", "options": { "TOOL_RESULT": { "color": "light-yellow" } } },
              { "type": "value", "options": { "FINDING": { "color": "orange" } } },
              { "type": "value", "options": { "DECISION": { "color": "purple" } } },
              { "type": "value", "options": { "ERROR": { "color": "red" } } }
            ]
          }
        ]
      }
    ]
  }
}
```

---

## Error Handling

### 12. Error Scenarios

| Scenario | Handling |
|----------|----------|
| Buffer full | Drop event, increment `gibson_activity_events_dropped` counter |
| JSON encode error | Log to stderr, continue processing |
| File write error | Retry once, then log to stderr |
| Shutdown during events | Drain buffer with 5s timeout |
| Invalid event type | Log warning, emit with type "UNKNOWN" |
| Missing context | Emit event with empty context fields |

---

## Metrics

### 13. Prometheus Metrics

```go
// Counters
gibson_activity_events_total{event_type, agent_name, level}
gibson_activity_events_dropped_total{}

// Gauges
gibson_activity_buffer_size{}
gibson_activity_buffer_capacity{}

// Histograms
gibson_activity_encode_duration_seconds{}
gibson_activity_write_duration_seconds{}
```

---

## Testing Strategy

### 14. Test Approach

**Unit Tests:**
- ActivityLogger level filtering
- Content truncation logic
- Event enrichment from context
- Payload serialization

**Integration Tests:**
- Harness → ActivityLogger integration
- Orchestrator → ActivityLogger integration
- JSON output format validation
- Buffer overflow handling

**E2E Tests:**
- Full pipeline: Harness → stdout → Promtail → Loki → Grafana
- Dashboard query validation
- Real-time tail functionality

---

## Security Considerations

### 15. Data Handling

- **No secrets in labels:** Labels only contain event metadata, not content
- **Content truncation:** Large prompts/responses truncated by default
- **Log permissions:** File output uses 0640 permissions
- **PII warning:** Emit warning metric if potential PII detected in content
- **Redaction mode:** Optional mode to redact content entirely (emit length only)

---

## Library Selection

### Recommended: `log/slog` (Go Standard Library)

**Gibson already uses `log/slog`** in `internal/observability/logging.go` with the existing `TracedLogger` wrapper. This provides:

- **Built-in JSON handler** via `slog.NewJSONHandler()` - perfect for Loki ingestion
- **Trace correlation** already implemented via `WithContext()` extracting OpenTelemetry spans
- **Mission/agent context injection** via existing `TracedLogger.WithContext()`
- **Zero external dependencies** - part of Go 1.21+ standard library
- **Handler composability** - can layer handlers for filtering, routing, etc.

**Existing Implementation (`internal/observability/logging.go:32-127`):**
```go
type TracedLogger struct {
    logger          *slog.Logger
    missionID       string
    agentName       string
    redactSensitive bool
}

func (l *TracedLogger) WithContext(ctx context.Context) *slog.Logger {
    // Adds mission_id, agent_name, trace_id, span_id
}
```

### Why Not Other Libraries?

| Library | Consideration | Decision |
|---------|--------------|----------|
| **zerolog** | Faster JSON encoding, zero-allocation | Not needed - activity logging is not on hot path (under 1000 events/sec), slog performance is sufficient |
| **zap** | Uber's high-perf logger | Adds external dependency, more complex API, slog meets requirements |
| **logrus** | Popular, feature-rich | Deprecated in favor of slog, slower than alternatives |

### Extending Existing Infrastructure

Rather than introducing a new library, we extend the existing `TracedLogger` pattern:

1. **Create `ActivityLogger`** as a specialized wrapper around `slog.Logger`
2. **Reuse `NewJSONHandler()`** for JSON output
3. **Leverage existing trace correlation** from `TracedLogger.WithContext()`
4. **Add activity-specific features**: event typing, buffering, level filtering

**Key Insight:** The activity logger is essentially a specialized `slog` handler/wrapper with:
- Activity-specific event types (enums)
- Structured payloads per event type
- Configurable content truncation
- Async buffered writes

This approach:
- Maintains consistency with existing logging code
- Avoids adding new dependencies
- Uses battle-tested stdlib JSON encoding
- Allows future handler swapping (zerolog backend via slog adapter if needed)

---

## Dependencies

### Internal
- `internal/harness` - Harness interface for injection
- `internal/orchestrator` - Orchestrator integration
- `internal/config` - Configuration loading
- `internal/observability` - Existing TracedLogger and metrics (extend this)
- `internal/middleware` - Context extraction

### External (All Existing)
- `log/slog` - Standard library structured logging (already used)
- `encoding/json` - JSON encoding (stdlib)
- `go.opentelemetry.io/otel/trace` - Trace context extraction (already used)
- Loki - Log storage (existing infrastructure)
- Promtail - Log shipping (existing infrastructure)
- Grafana - Dashboard (existing infrastructure)

**No new external Go dependencies required.**

---

## Rollout Plan

1. **Phase 1:** Implement ActivityLogger and configuration
2. **Phase 2:** Integrate with harness (LLM/tool calls)
3. **Phase 3:** Integrate with orchestrator (decisions)
4. **Phase 4:** Update Promtail pipeline
5. **Phase 5:** Create Grafana dashboard
6. **Phase 6:** Documentation and testing
