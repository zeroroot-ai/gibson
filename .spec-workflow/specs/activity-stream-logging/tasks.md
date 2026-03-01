# Activity Stream Logging - Implementation Tasks

## Overview

**Spec Name:** activity-stream-logging
**Version:** 1.0.0
**Created:** 2026-03-01
**Status:** Draft

---

## Phase 1: Core ActivityLogger Implementation

### Task 1.1: Define ActivityLogger Types and Interface
_File: `internal/observability/activity_types.go`_

- [ ] 1.1.1 Define `ActivityEventType` constants (AGENT_START, LLM_PROMPT, TOOL_CALL, etc.)
- [ ] 1.1.2 Define `ActivityLevel` enum (Quiet, Normal, Verbose, Debug)
- [ ] 1.1.3 Define `ActivityEvent` struct with JSON tags
- [ ] 1.1.4 Define `ActivityLogger` interface with Emit and convenience methods
- [ ] 1.1.5 Define `ActivityLoggerConfig` struct

_Acceptance: All 13 event types defined, interface matches design spec_

---

### Task 1.2: Implement Event Payload Structs
_File: `internal/observability/activity_payloads.go`_

- [ ] 1.2.1 Implement `LLMPromptPayload` struct
- [ ] 1.2.2 Implement `LLMResponsePayload` struct
- [ ] 1.2.3 Implement `ToolCallPayload` struct
- [ ] 1.2.4 Implement `ToolResultPayload` struct
- [ ] 1.2.5 Implement `FindingPayload` struct
- [ ] 1.2.6 Implement `DecisionPayload` struct
- [ ] 1.2.7 Implement `AgentStartPayload` struct
- [ ] 1.2.8 Implement `AgentEndPayload` struct
- [ ] 1.2.9 Implement `ErrorPayload` struct

_Acceptance: All payload structs serializable to JSON with proper tags_

---

### Task 1.3: Implement DefaultActivityLogger
_File: `internal/observability/activity_impl.go`_

- [ ] 1.3.1 Implement `NewActivityLogger()` constructor
- [ ] 1.3.2 Implement async write loop with buffered channel
- [ ] 1.3.3 Implement `Emit()` with level filtering
- [ ] 1.3.4 Implement `enrichEvent()` for context extraction (trace_id, span_id, mission_id)
- [ ] 1.3.5 Implement `shouldLog()` level filtering logic
- [ ] 1.3.6 Implement `truncateContent()` with configurable max length
- [ ] 1.3.7 Implement `Flush()` for graceful buffer drain
- [ ] 1.3.8 Implement `Close()` for shutdown

_Acceptance: Non-blocking emission, context enrichment, graceful shutdown_

---

### Task 1.4: Implement Convenience Emit Methods
_File: `internal/observability/activity_impl.go`_

- [ ] 1.4.1 Implement `EmitAgentStart()`
- [ ] 1.4.2 Implement `EmitAgentEnd()`
- [ ] 1.4.3 Implement `EmitLLMPrompt()` - emit per message with index
- [ ] 1.4.4 Implement `EmitLLMResponse()`
- [ ] 1.4.5 Implement `EmitToolCall()`
- [ ] 1.4.6 Implement `EmitToolResult()`
- [ ] 1.4.7 Implement `EmitFinding()`
- [ ] 1.4.8 Implement `EmitDecision()`
- [ ] 1.4.9 Implement `EmitError()`

_Acceptance: Each method respects verbosity level, constructs correct payload_

---

### Task 1.5: Implement NoopActivityLogger
_File: `internal/observability/activity_noop.go`_

- [ ] 1.5.1 Implement `NoopActivityLogger` satisfying interface
- [ ] 1.5.2 Ensure zero allocations in noop implementation

_Acceptance: All methods no-op, usable when logging disabled_

---

### Task 1.6: Unit Tests for ActivityLogger
_File: `internal/observability/activity_test.go`_

- [ ] 1.6.1 Test level filtering (Quiet, Normal, Verbose, Debug)
- [ ] 1.6.2 Test content truncation logic
- [ ] 1.6.3 Test event enrichment from context
- [ ] 1.6.4 Test buffer overflow behavior
- [ ] 1.6.5 Test JSON serialization of all event types
- [ ] 1.6.6 Test graceful shutdown and flush

_Acceptance: 90%+ code coverage, all scenarios covered_

---

## Phase 2: Configuration Integration

### Task 2.1: Add ActivityLogging Config Schema
_File: `internal/config/config.go`_

- [ ] 2.1.1 Add `ActivityLogging` field to main Config struct
- [ ] 2.1.2 Define `ActivityLoggingConfig` struct with all fields
- [ ] 2.1.3 Add environment variable mappings (GIBSON_ACTIVITY_LOG_*)
- [ ] 2.1.4 Set defaults (enabled=true, level=normal, max_content=500)

_Acceptance: Config loads from YAML and env vars with proper defaults_

---

### Task 2.2: Add Config Validation
_File: `internal/config/validation.go`_

- [ ] 2.2.1 Validate activity logging level is valid enum
- [ ] 2.2.2 Validate max_content_length is positive
- [ ] 2.2.3 Validate output is one of: stdout, file, both
- [ ] 2.2.4 Validate file_path set when output includes file

_Acceptance: Clear error messages for invalid config_

---

## Phase 3: Harness Integration

### Task 3.1: Add ActivityLogger to Harness Factory
_File: `internal/harness/factory.go`_

- [ ] 3.1.1 Add ActivityLogger to HarnessConfig
- [ ] 3.1.2 Create ActivityLogger in factory based on config
- [ ] 3.1.3 Inject into DefaultAgentHarness
- [ ] 3.1.4 Use NoopActivityLogger when disabled

_Acceptance: ActivityLogger available in harness, no nil issues_

---

### Task 3.2: Integrate with Complete()
_File: `internal/harness/implementation.go`_

- [ ] 3.2.1 Add `EmitLLMPrompt()` call before provider.Complete()
- [ ] 3.2.2 Add `EmitLLMResponse()` call after successful completion
- [ ] 3.2.3 Add `EmitError()` call on completion failure
- [ ] 3.2.4 Pass timing information to response event

_Acceptance: All LLM completions emit prompt/response events_

---

### Task 3.3: Integrate with CallToolProto()
_File: `internal/harness/implementation.go`_

- [ ] 3.3.1 Add `EmitToolCall()` before tool execution
- [ ] 3.3.2 Add `EmitToolResult()` after tool execution
- [ ] 3.3.3 Include duration in result event
- [ ] 3.3.4 Handle both local and remote tool calls

_Acceptance: All tool calls emit call/result events with duration_

---

### Task 3.4: Integrate with SubmitFinding()
_File: `internal/harness/implementation.go`_

- [ ] 3.4.1 Add `EmitFinding()` when finding is submitted
- [ ] 3.4.2 Extract severity, confidence, category for payload

_Acceptance: All findings emit FINDING events_

---

### Task 3.5: Harness Integration Tests
_File: `internal/harness/activity_integration_test.go`_

- [ ] 3.5.1 Test Complete() emits LLM_PROMPT and LLM_RESPONSE
- [ ] 3.5.2 Test CallToolProto() emits TOOL_CALL and TOOL_RESULT
- [ ] 3.5.3 Test SubmitFinding() emits FINDING
- [ ] 3.5.4 Test error scenarios emit ERROR events
- [ ] 3.5.5 Verify event payloads contain expected fields

_Acceptance: Integration tests pass with mock providers_

---

## Phase 4: Orchestrator Integration

### Task 4.1: Add ActivityLogger to Orchestrator
_File: `internal/orchestrator/orchestrator.go`_

- [ ] 4.1.1 Add ActivityLogger field to Orchestrator struct
- [ ] 4.1.2 Pass ActivityLogger in orchestrator options
- [ ] 4.1.3 Use NoopActivityLogger when disabled

_Acceptance: ActivityLogger available, no nil pointer issues_

---

### Task 4.2: Emit DECISION Events
_File: `internal/orchestrator/orchestrator.go`_

- [ ] 4.2.1 Emit DECISION event after Think phase returns
- [ ] 4.2.2 Include action, target node, reasoning, confidence
- [ ] 4.2.3 Include iteration count and tokens used

_Acceptance: All orchestrator decisions logged with reasoning_

---

### Task 4.3: Orchestrator Integration Tests
_File: `internal/orchestrator/activity_integration_test.go`_

- [ ] 4.3.1 Test decision events emitted during Run()
- [ ] 4.3.2 Verify decision payloads contain expected fields
- [ ] 4.3.3 Test multiple iterations emit multiple decisions

_Acceptance: Decision logging validated in tests_

---

## Phase 5: Metrics Integration

### Task 5.1: Add Activity Prometheus Metrics
_File: `internal/observability/activity_metrics.go`_

- [ ] 5.1.1 Define `gibson_activity_events_total` counter
- [ ] 5.1.2 Define `gibson_activity_events_dropped_total` counter
- [ ] 5.1.3 Define `gibson_activity_buffer_size` gauge
- [ ] 5.1.4 Register metrics with Prometheus

_Acceptance: Metrics scrapable with bounded cardinality labels_

---

### Task 5.2: Instrument ActivityLogger with Metrics
_File: `internal/observability/activity_impl.go`_

- [ ] 5.2.1 Increment events_total on successful emit
- [ ] 5.2.2 Increment events_dropped on buffer overflow
- [ ] 5.2.3 Update buffer_size gauge on emit/drain

_Acceptance: Metrics accurately reflect activity state_

---

## Phase 6: Kubernetes/Loki Integration

### Task 6.1: Update Promtail ConfigMap
_File: `deploy/helm/gibson/templates/observability/promtail-configmap.yaml`_

- [ ] 6.1.1 Add pipeline stage for JSON parsing
- [ ] 6.1.2 Extract labels: event_type, agent_name, level
- [ ] 6.1.3 Configure timestamp parsing from event JSON
- [ ] 6.1.4 Add relabel config for gibson activity logs

_Acceptance: Promtail parses events, labels extracted for Loki_

---

### Task 6.2: Document Loki Queries
_File: `docs/observability/activity-logging.md`_

- [ ] 6.2.1 Document LogQL queries for common use cases
- [ ] 6.2.2 Document label strategy and cardinality
- [ ] 6.2.3 Provide example queries for debugging

_Acceptance: Operators can query activity logs effectively_

---

## Phase 7: Grafana Dashboard

### Task 7.1: Create Activity Stream Dashboard
_File: `deploy/helm/gibson/files/dashboards/gibson-activity.json`_

- [ ] 7.1.1 Create Activity Stream Logs panel (70% height)
- [ ] 7.1.2 Configure Loki datasource query
- [ ] 7.1.3 Add color rules for event types
- [ ] 7.1.4 Configure live tail mode
- [ ] 7.1.5 Add expandable row details

_Acceptance: Dashboard renders activity stream with color coding_

---

### Task 7.2: Add Knowledge Graph Panel
_File: `deploy/helm/gibson/files/dashboards/gibson-activity.json`_

- [ ] 7.2.1 Add Knowledge Graph stats panel
- [ ] 7.2.2 Show nodes, hosts, endpoints, findings counts
- [ ] 7.2.3 Position in lower left

_Acceptance: Panel shows current graph statistics_

---

### Task 7.3: Add Mission Status Panel
_File: `deploy/helm/gibson/files/dashboards/gibson-activity.json`_

- [ ] 7.3.1 Add Mission Status panel
- [ ] 7.3.2 Show mission, agent, status, uptime, findings
- [ ] 7.3.3 Position in lower right

_Acceptance: Panel shows mission context and finding counts_

---

### Task 7.4: Add Dashboard Variables
_File: `deploy/helm/gibson/files/dashboards/gibson-activity.json`_

- [ ] 7.4.1 Add $mission_id variable for filtering
- [ ] 7.4.2 Add $agent_name variable for filtering
- [ ] 7.4.3 Add $event_type multi-select variable
- [ ] 7.4.4 Configure auto-refresh (5s default)

_Acceptance: Variables filter activity stream, auto-refresh works_

---

### Task 7.5: Deploy Dashboard via Helm
_File: `deploy/helm/gibson/templates/observability/grafana-dashboards-configmap.yaml`_

- [ ] 7.5.1 Add activity dashboard to ConfigMap
- [ ] 7.5.2 Ensure Grafana sidecar picks up dashboard
- [ ] 7.5.3 Test dashboard loads in Grafana

_Acceptance: Dashboard auto-provisioned, no manual import_

---

## Phase 8: Documentation and Testing

### Task 8.1: End-to-End Test
_File: `test/e2e/activity_logging_test.go`_

- [ ] 8.1.1 Run mission with activity logging enabled
- [ ] 8.1.2 Verify events appear in Loki
- [ ] 8.1.3 Verify Grafana dashboard displays events
- [ ] 8.1.4 Test real-time tail functionality

_Acceptance: Full pipeline works, events visible within 2 seconds_

---

### Task 8.2: Performance Test
_File: `test/performance/activity_logging_bench_test.go`_

- [ ] 8.2.1 Benchmark event emission latency
- [ ] 8.2.2 Benchmark buffer throughput
- [ ] 8.2.3 Verify under 1ms overhead per LLM call
- [ ] 8.2.4 Test with 1000 events/second load

_Acceptance: Meets NFR performance requirements_

---

### Task 8.3: Documentation
_File: `docs/observability/activity-logging.md`_

- [ ] 8.3.1 Document configuration options
- [ ] 8.3.2 Document event types and payloads
- [ ] 8.3.3 Document Grafana dashboard usage
- [ ] 8.3.4 Document troubleshooting common issues

_Acceptance: Operators can configure and use activity logging_

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1 | 1.1-1.6 | Core ActivityLogger implementation |
| 2 | 2.1-2.2 | Configuration integration |
| 3 | 3.1-3.5 | Harness integration |
| 4 | 4.1-4.3 | Orchestrator integration |
| 5 | 5.1-5.2 | Metrics integration |
| 6 | 6.1-6.2 | Kubernetes/Loki integration |
| 7 | 7.1-7.5 | Grafana dashboard |
| 8 | 8.1-8.3 | Documentation and testing |

**Total Subtasks:** 85
