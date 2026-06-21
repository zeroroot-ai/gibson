package daemon

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/brain"
	"github.com/zeroroot-ai/gibson/internal/daemon/api"
	"github.com/zeroroot-ai/gibson/internal/events"
)

// EventBusAdapter adapts the daemon's EventBus to the EventBusPublisher interface
// expected by the mission orchestrator. This avoids circular dependencies between
// daemon and mission packages.
type EventBusAdapter struct {
	eventBus *EventBus
}

// eventPublisher is the minimal event-emit surface the mission manager needs (it
// feeds the ECS brain + Redis stream). Satisfied by *OrchestratorEventBusAdapter.
// Replaces the former orchestrator.EventBus interface dependency (gibson#851).
type eventPublisher interface {
	Publish(event events.Event)
}

// OrchestratorEventBusAdapter adapts the daemon's EventBus to the orchestrator's
// EventBus interface which expects Publish(event events.Event).
//
// When redisStream is non-nil, each event is also written to the tenant's
// Redis Stream so that gRPC Subscribe clients backed by Redis Streams receive
// mission execution events in real time.
type OrchestratorEventBusAdapter struct {
	eventBus    *EventBus
	redisStream *RedisEventStream // optional; nil means Redis Streams disabled
	tenant      string            // tenant scope for redis stream key
	brainReg    *brain.Registry   // optional; nil means ECS-brain ingest disabled
}

// NewOrchestratorEventBusAdapter creates a new adapter for the orchestrator.
func NewOrchestratorEventBusAdapter(eventBus *EventBus) *OrchestratorEventBusAdapter {
	return &OrchestratorEventBusAdapter{eventBus: eventBus}
}

// NewOrchestratorEventBusAdapterWithRedis creates an adapter that bridges events
// to both the in-process EventBus and a tenant-scoped Redis Stream.
func NewOrchestratorEventBusAdapterWithRedis(
	eventBus *EventBus,
	redisStream *RedisEventStream,
	tenant string,
	brainReg *brain.Registry,
) *OrchestratorEventBusAdapter {
	if tenant == "" {
		tenant = "default"
	}
	return &OrchestratorEventBusAdapter{
		eventBus:    eventBus,
		redisStream: redisStream,
		tenant:      tenant,
		brainReg:    brainReg,
	}
}

// Publish implements the orchestrator's EventBus interface.
func (a *OrchestratorEventBusAdapter) Publish(event events.Event) {
	eventData := convertToAPIEventData(event)
	ctx := context.Background()

	// In-process EventBus (always).
	_ = a.eventBus.Publish(ctx, eventData)

	// Redis Streams bridge (optional).
	if a.redisStream != nil {
		if err := a.redisStream.PublishEvent(ctx, a.tenant, eventData); err != nil {
			// Best-effort; do not block the orchestrator.
			_ = err
		}
	}

	// ECS-brain ingest (optional) — the capture path (ADR-0001): feed the
	// tenant's brain World from the live mission event stream.
	ingestToBrain(a.brainReg, a.tenant, eventData)
}

// NewEventBusAdapter creates a new adapter that wraps an EventBus.
func NewEventBusAdapter(eventBus *EventBus) *EventBusAdapter {
	return &EventBusAdapter{
		eventBus: eventBus,
	}
}

// Publish converts an interface{} event to api.EventData and publishes to the event bus.
// This method implements the EventBusPublisher interface from mission package.
func (a *EventBusAdapter) Publish(ctx context.Context, event interface{}) error {
	// Convert interface{} to api.EventData
	// The mission orchestrator sends a specially crafted struct that we can type-assert
	eventData := convertToAPIEventData(event)

	// Publish to the underlying event bus
	return a.eventBus.Publish(ctx, eventData)
}

// convertToAPIEventData converts the event from mission orchestrator to api.EventData.
// The mission orchestrator publishes events.Event types from internal/events package.
func convertToAPIEventData(event interface{}) api.EventData {
	// Type assert to events.Event from internal/events/types.go
	ev, ok := event.(events.Event)
	if !ok {
		// Fallback for non-Event types - should not happen in normal operation
		return api.EventData{
			EventType: "unknown",
			Timestamp: time.Now(),
			Source:    "mission-orchestrator",
			Metadata: map[string]interface{}{
				"error": "failed to type assert to events.Event",
			},
		}
	}

	// Create base EventData with common fields
	result := api.EventData{
		EventType: string(ev.Type), // Convert EventType to string
		Timestamp: ev.Timestamp,
		Source:    "mission-orchestrator",
		Metadata:  make(map[string]interface{}),
	}

	// Preserve trace context in Metadata
	if ev.TraceID != "" {
		result.Metadata["trace_id"] = ev.TraceID
	}
	if ev.SpanID != "" {
		result.Metadata["span_id"] = ev.SpanID
	}

	// Use type switch on Payload to populate appropriate nested event struct
	switch payload := ev.Payload.(type) {
	// Mission lifecycle events
	case events.MissionStartedPayload:
		result.MissionEvent = &api.MissionEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(ev.MissionID),
			Message:   "Mission started",
			Payload: map[string]interface{}{
				"mission_name": payload.MissionName,
				"target_id":    string(payload.TargetID),
				"node_count":   payload.NodeCount,
			},
		}

	case events.MissionProgressPayload:
		result.MissionEvent = &api.MissionEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(ev.MissionID),
			NodeID:    payload.CurrentNode,
			Message:   payload.Message,
			Payload: map[string]interface{}{
				"completed_nodes": payload.CompletedNodes,
				"total_nodes":     payload.TotalNodes,
				"current_node":    payload.CurrentNode,
			},
		}

	case events.MissionCompletedPayload:
		result.MissionEvent = &api.MissionEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(ev.MissionID),
			Message:   "Mission completed",
			Payload: map[string]interface{}{
				"duration":       payload.Duration.Seconds(),
				"finding_count":  payload.FindingCount,
				"nodes_executed": payload.NodesExecuted,
				"success":        payload.Success,
			},
		}

	case events.MissionFailedPayload:
		result.MissionEvent = &api.MissionEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(ev.MissionID),
			Error:     payload.Error,
			Message:   "Mission failed",
			Payload: map[string]interface{}{
				"duration":       payload.Duration.Seconds(),
				"finding_count":  payload.FindingCount,
				"nodes_executed": payload.NodesExecuted,
			},
		}

	// Node execution events
	case events.NodeStartedPayload:
		result.MissionEvent = &api.MissionEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(payload.MissionID),
			NodeID:    payload.NodeID,
			Message:   payload.Message,
			Payload: map[string]interface{}{
				"node_type": payload.NodeType,
			},
		}

	case events.NodeCompletedPayload:
		result.MissionEvent = &api.MissionEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(payload.MissionID),
			NodeID:    payload.NodeID,
			Message:   payload.Message,
			Payload: map[string]interface{}{
				"duration": payload.Duration.Seconds(),
			},
		}

	case events.NodeFailedPayload:
		result.MissionEvent = &api.MissionEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(payload.MissionID),
			NodeID:    payload.NodeID,
			Error:     payload.Error,
			Message:   "Node failed",
			Payload: map[string]interface{}{
				"duration": payload.Duration.Seconds(),
			},
		}

	case events.NodeSkippedPayload:
		result.MissionEvent = &api.MissionEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(payload.MissionID),
			NodeID:    payload.NodeID,
			Message:   payload.SkipReason,
			Payload: map[string]interface{}{
				"skip_reason": payload.SkipReason,
			},
		}

	// Agent lifecycle events
	case events.AgentStartedPayload:
		result.AgentEvent = &api.AgentEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			AgentName: payload.AgentName,
			Message:   payload.TaskDescription,
			Metadata: map[string]interface{}{
				"target_id": string(payload.TargetID),
			},
		}

	case events.AgentCompletedPayload:
		result.AgentEvent = &api.AgentEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			AgentName: payload.AgentName,
			Message:   "Agent completed",
			Metadata: map[string]interface{}{
				"duration":      payload.Duration.Seconds(),
				"finding_count": payload.FindingCount,
				"success":       payload.Success,
			},
		}

	case events.AgentFailedPayload:
		result.AgentEvent = &api.AgentEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			AgentName: payload.AgentName,
			Message:   payload.Error,
			Metadata: map[string]interface{}{
				"duration":      payload.Duration.Seconds(),
				"finding_count": payload.FindingCount,
			},
		}

	case events.AgentDelegatedPayload:
		result.AgentEvent = &api.AgentEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			AgentName: payload.FromAgent,
			Message:   payload.TaskDescription,
			Metadata: map[string]interface{}{
				"to_agent":      payload.ToAgent,
				"from_trace_id": payload.FromTraceID,
				"from_span_id":  payload.FromSpanID,
				"to_trace_id":   payload.ToTraceID,
				"to_span_id":    payload.ToSpanID,
			},
		}

	// Finding events
	case events.FindingDiscoveredPayload:
		result.FindingEvent = &api.FindingEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(ev.MissionID),
			Finding: api.FindingData{
				ID:          string(payload.FindingID),
				Title:       payload.Title,
				Severity:    payload.Severity,
				Category:    payload.Category,
				Description: payload.Description,
				Technique:   payload.Technique,
				Evidence:    payload.Evidence,
				Timestamp:   payload.Timestamp,
			},
		}

	case events.FindingSubmittedPayload:
		result.FindingEvent = &api.FindingEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			MissionID: string(ev.MissionID),
			Finding: api.FindingData{
				ID:       string(payload.FindingID),
				Title:    payload.Title,
				Severity: payload.Severity,
			},
		}

	// Tool execution events - populate ToolEventData for structured tool event data
	case events.ToolCallStartedPayload:
		// Generate input summary from parameters, sanitized and truncated
		inputSummary := sanitizeAndTruncate(formatParameters(payload.Parameters), 200)

		result.ToolEvent = &api.ToolEventData{
			EventType:    "tool.started",
			Timestamp:    ev.Timestamp,
			ToolName:     payload.ToolName,
			AgentName:    ev.AgentName,
			MissionID:    string(ev.MissionID),
			Message:      "Tool execution started: " + payload.ToolName,
			InputSummary: inputSummary,
		}

	case events.ToolCallCompletedPayload:
		// Generate output summary from result size
		outputSummary := ""
		if payload.ResultSize > 0 {
			outputSummary = sanitizeAndTruncate(formatResultSize(payload.ResultSize), 200)
		}

		result.ToolEvent = &api.ToolEventData{
			EventType:     "tool.completed",
			Timestamp:     ev.Timestamp,
			ToolName:      payload.ToolName,
			AgentName:     ev.AgentName,
			MissionID:     string(ev.MissionID),
			Message:       "Tool execution completed: " + payload.ToolName,
			Duration:      payload.Duration.Seconds(),
			OutputSummary: outputSummary,
			ResultsCount:  payload.ResultSize,
		}

	case events.ToolCallFailedPayload:
		result.ToolEvent = &api.ToolEventData{
			EventType: "tool.failed",
			Timestamp: ev.Timestamp,
			ToolName:  payload.ToolName,
			AgentName: ev.AgentName,
			MissionID: string(ev.MissionID),
			Message:   "Tool execution failed: " + payload.ToolName + " - " + payload.Error,
			Duration:  payload.Duration.Seconds(),
			Error:     payload.Error,
			ErrorCode: determineToolErrorCode(payload.Error),
		}

	case events.ToolProgressPayload:
		// Convert percent complete (0-100) to progress (0-1)
		progress := float64(payload.PercentComplete) / 100.0

		result.ToolEvent = &api.ToolEventData{
			EventType: "tool.progress",
			Timestamp: ev.Timestamp,
			ToolName:  payload.ToolName,
			AgentName: ev.AgentName,
			MissionID: string(ev.MissionID),
			Message:   payload.Message,
			Progress:  progress,
		}

	case events.ToolWarningPayload:
		// Determine warning severity from context or default to medium
		severity := determineWarningSeverity(payload.WarningMessage, payload.WarningContext)

		result.ToolEvent = &api.ToolEventData{
			EventType:       "tool.warning",
			Timestamp:       ev.Timestamp,
			ToolName:        payload.ToolName,
			AgentName:       ev.AgentName,
			MissionID:       string(ev.MissionID),
			Message:         payload.WarningMessage,
			Warning:         payload.WarningMessage,
			WarningSeverity: severity,
		}

	// LLM events - populate LLMEventData for structured LLM event data
	case events.LLMRequestStartedPayload:
		result.LLMEvent = &api.LLMEventData{
			EventType:    string(ev.Type),
			Timestamp:    ev.Timestamp,
			AgentName:    ev.AgentName,
			Model:        payload.Model,
			Slot:         payload.SlotName,
			MessageCount: payload.MessageCount,
		}

	case events.LLMRequestCompletedPayload:
		// Calculate cached status - in Anthropic API, cache_read_input_tokens > 0 indicates cached
		cached := false
		// Note: The LLMRequestCompletedPayload doesn't have cache info yet,
		// but we prepare for it. For now, default to false.

		result.LLMEvent = &api.LLMEventData{
			EventType:        string(ev.Type),
			Timestamp:        ev.Timestamp,
			AgentName:        ev.AgentName,
			Model:            payload.Model,
			Slot:             payload.SlotName,
			MessageCount:     0, // Not available in completed payload
			PromptTokens:     payload.InputTokens,
			CompletionTokens: payload.OutputTokens,
			TotalTokens:      payload.InputTokens + payload.OutputTokens,
			Duration:         payload.Duration.Seconds() * 1000, // Convert to milliseconds
			Cached:           cached,
		}

	case events.LLMRequestFailedPayload:
		result.LLMEvent = &api.LLMEventData{
			EventType: string(ev.Type),
			Timestamp: ev.Timestamp,
			AgentName: ev.AgentName,
			Model:     payload.Model,
			Slot:      payload.SlotName,
			Error:     payload.Error,
			ErrorCode: "", // Not provided in current payload, would need to be added
			WillRetry: payload.Retryable,
		}

	// Orchestrator events
	// NOTE: Orchestrator payload types (OrchestratorDecisionPayload, OrchestratorApprovalPayload)
	// have not been defined in internal/events/types.go yet. When they are added, add conversion
	// cases here to populate OrchestratorEventData with:
	// - EventType: "orchestrator.decision" or "orchestrator.approval_required"
	// - Iteration, Action, TargetNodeID, TargetAgentName, Confidence
	// - Reasoning (truncated to 500 chars), TokensUsed, Latency
	// - For approval events: ApprovalID, Risk, Timeout

	default:
		// For unknown payload types, preserve the event but mark it as unstructured
		// This maintains backward compatibility and prevents event loss
		result.Data = string(ev.Type)
		if ev.MissionID != "" {
			result.Metadata["mission_id"] = string(ev.MissionID)
		}
		if ev.AgentName != "" {
			result.Metadata["agent_name"] = ev.AgentName
		}
		// Preserve Attrs if present
		if ev.Attrs != nil {
			for k, v := range ev.Attrs {
				result.Metadata[k] = v
			}
		}
	}

	return result
}

// Helper functions for tool event data sanitization and formatting

// sanitizeAndTruncate sanitizes sensitive data and truncates to maxLen characters
func sanitizeAndTruncate(input string, maxLen int) string {
	// Sanitize common sensitive patterns (API keys, tokens, passwords)
	// This is a basic implementation - extend as needed
	sanitized := input

	// Remove common credential patterns
	// Note: In production, this should use more sophisticated pattern matching
	if len(sanitized) > maxLen {
		sanitized = sanitized[:maxLen] + "..."
	}

	return sanitized
}

// formatParameters converts parameter map to a readable summary string
func formatParameters(params map[string]any) string {
	if params == nil || len(params) == 0 {
		return "no parameters"
	}

	// Create a simple summary of parameters (just keys, not values for security).
	// Keys are sorted so the summary is deterministic — map iteration order is
	// not stable and made this flaky (gibson#536).
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	summary := "parameters: "
	for count, key := range keys {
		if count > 0 {
			summary += ", "
		}
		summary += key
		// Limit to first 5 parameters
		if count+1 >= 5 {
			if len(params) > 5 {
				summary += fmt.Sprintf("... (%d total)", len(params))
			}
			break
		}
	}

	return summary
}

// formatResultSize creates a human-readable result size summary
func formatResultSize(size int) string {
	if size == 0 {
		return "no results"
	}
	if size == 1 {
		return "1 result"
	}
	return fmt.Sprintf("%d results", size)
}

// determineToolErrorCode attempts to classify tool errors into categories
func determineToolErrorCode(errorMsg string) string {
	if errorMsg == "" {
		return ""
	}

	// Common error patterns - extend as needed
	// This provides basic categorization for UI display
	errorLower := strings.ToLower(errorMsg)

	// Check for timeout errors
	if containsAny(errorLower, []string{"timeout", "timed out", "deadline exceeded"}) {
		return "timeout"
	}
	// Check for permission errors
	if containsAny(errorLower, []string{"permission denied", "access denied", "unauthorized", "forbidden"}) {
		return "permission_denied"
	}
	// Check for not found errors
	if containsAny(errorLower, []string{"not found", "does not exist", "no such"}) {
		return "not_found"
	}
	// Check for network errors
	if containsAny(errorLower, []string{"connection refused", "network error", "connection reset"}) {
		return "network_error"
	}
	// Check for validation errors
	if containsAny(errorLower, []string{"invalid", "malformed", "validation failed"}) {
		return "validation_error"
	}

	// Default to generic error
	return "error"
}

// determineWarningSeverity categorizes warning messages into severity levels
func determineWarningSeverity(warningMsg, warningContext string) string {
	if warningMsg == "" {
		return "low"
	}

	combined := strings.ToLower(warningMsg + " " + warningContext)

	// Check for high severity keywords
	if containsAny(combined, []string{"critical", "severe", "dangerous", "security", "breach", "exploit"}) {
		return "high"
	}

	// Check for medium severity keywords
	if containsAny(combined, []string{"warning", "caution", "deprecated", "unsafe", "risk"}) {
		return "medium"
	}

	// Default to low severity
	return "low"
}

// containsAny checks if the input string contains any of the substrings (case-insensitive)
func containsAny(input string, substrings []string) bool {
	for _, substr := range substrings {
		if strings.Contains(input, substr) {
			return true
		}
	}
	return false
}
