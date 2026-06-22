package middleware

import (
	"context"
	"time"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/events"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"go.opentelemetry.io/otel/trace"
)

// EventMiddleware creates middleware that emits events to the unified EventBus
// after operations complete. Events are published with proper context fields
// including MissionID, AgentName, TraceID, and SpanID.
//
// The middleware handles nil bus gracefully (no-op) and uses the provided
// ErrorHandler for emission failures rather than silently swallowing errors.
//
// Parameters:
//   - bus: The EventBus to publish events to (nil = no-op middleware)
//   - handler: ErrorHandler for emission failures (must not be nil)
//
// Returns:
//   - Middleware function that emits events after operation execution
//
// Example:
//
//	middleware := EventMiddleware(eventBus, errorHandler)
//	operation := middleware(baseOperation)
func EventMiddleware(bus events.EventBus, handler events.ErrorHandler) Middleware {
	// Handle nil bus gracefully - return no-op middleware
	if bus == nil {
		return func(next Operation) Operation {
			return next
		}
	}

	// Require non-nil error handler
	if handler == nil {
		panic("EventMiddleware requires non-nil ErrorHandler")
	}

	return func(next Operation) Operation {
		return func(ctx context.Context, req any) (any, error) {
			// Execute operation
			result, err := next(ctx, req)

			// Build and emit event after operation completes
			event := buildEvent(ctx, req, result, err)
			if event != nil {
				if pubErr := bus.Publish(ctx, *event); pubErr != nil {
					handler(pubErr, map[string]interface{}{
						"operation":  "event_publish",
						"event_type": event.Type,
						"mission_id": event.MissionID,
						"agent_name": event.AgentName,
					})
				}
			}

			return result, err
		}
	}
}

// buildEvent constructs an Event from the operation context, request, response, and error.
// Returns nil if the operation type cannot be determined or is not supported for event emission.
func buildEvent(ctx context.Context, req any, result any, err error) *events.Event {
	// Get operation type from context
	opType, ok := ctx.Value(CtxOperationType).(OperationType)
	if !ok {
		// Cannot determine operation type, skip event emission
		return nil
	}

	// Map operation type to event type
	eventType, payload := mapOperationToEvent(ctx, opType, req, result, err)
	if eventType == "" {
		// Operation type doesn't produce events
		return nil
	}

	// Build base event with timestamp
	event := &events.Event{
		Type:      eventType,
		Timestamp: time.Now(),
		Payload:   payload,
	}

	// Add mission ID and agent name from context if available
	if missionID, ok := ctx.Value(CtxMissionID).(types.ID); ok {
		event.MissionID = missionID
	}
	if agentName, ok := ctx.Value(CtxAgentName).(string); ok {
		event.AgentName = agentName
	}

	// Add trace context if available
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		event.TraceID = span.SpanContext().TraceID().String()
		event.SpanID = span.SpanContext().SpanID().String()
	}

	return event
}

// mapOperationToEvent maps an operation type and its data to an EventType and payload.
// Returns empty string if the operation doesn't produce events.
func mapOperationToEvent(ctx context.Context, opType OperationType, req any, result any, err error) (events.EventType, any) {
	// Handle error cases - emit failed events
	if err != nil {
		return mapOperationToFailedEvent(ctx, opType, req, err)
	}

	// Handle success cases - emit completed events
	switch opType {
	case OpComplete, OpCompleteWithTools:
		return events.EventLLMRequestCompleted, buildLLMResponsePayload(ctx, result)

	case OpStream:
		return events.EventLLMStreamCompleted, buildLLMStreamCompletedPayload(result)

	case OpCallToolProto:
		return events.EventToolCallCompleted, buildToolResultPayload(req, result)

	case OpQueryPlugin:
		return events.EventPluginQueryCompleted, buildPluginResultPayload(req, result)

	case OpSubmitFinding:
		return events.EventFindingSubmitted, buildFindingPayload(ctx, req)

	case OpDelegateToAgent:
		return events.EventAgentDelegated, buildAgentDelegatedPayload(ctx, req)

	default:
		// Operation type doesn't produce completion events
		return "", nil
	}
}

// mapOperationToFailedEvent maps an operation type and error to a failed EventType and payload.
func mapOperationToFailedEvent(ctx context.Context, opType OperationType, req any, err error) (events.EventType, any) {
	switch opType {
	case OpComplete, OpCompleteWithTools:
		return events.EventLLMRequestFailed, buildLLMRequestFailedPayload(ctx, req, err)

	case OpStream:
		return events.EventLLMRequestFailed, buildLLMRequestFailedPayload(ctx, req, err)

	case OpCallToolProto:
		return events.EventToolCallFailed, buildToolCallFailedPayload(req, err)

	case OpQueryPlugin:
		return events.EventPluginQueryFailed, buildPluginQueryFailedPayload(req, err)

	default:
		// Operation type doesn't produce failure events
		return "", nil
	}
}

// Payload builders for each operation type

// buildLLMResponsePayload builds payload for successful LLM completion
func buildLLMResponsePayload(ctx context.Context, result any) any {
	if result == nil {
		return nil
	}

	resp, ok := result.(*llm.CompletionResponse)
	if !ok {
		return nil
	}

	// Extract provider and slot from context if available
	provider := "unknown"
	slotName := "unknown"
	if p, ok := ctx.Value(CtxProvider).(string); ok && p != "" {
		provider = p
	}
	if s, ok := ctx.Value(CtxSlotName).(string); ok && s != "" {
		slotName = s
	}

	return events.LLMRequestCompletedPayload{
		Provider:       provider,
		SlotName:       slotName,
		Model:          resp.Model,
		InputTokens:    resp.Usage.PromptTokens,
		OutputTokens:   resp.Usage.CompletionTokens,
		StopReason:     string(resp.FinishReason),
		ResponseLength: len(resp.Message.Content),
		// Duration is tracked by middleware, not available here
	}
}

// buildLLMStreamCompletedPayload builds payload for completed stream
func buildLLMStreamCompletedPayload(result any) any {
	// Streaming operations emit their own completion events through the stream wrapper
	// This is a placeholder for future enhancement
	return events.LLMStreamCompletedPayload{
		TotalChunks: 0, // Would need to track through stream
	}
}

// buildToolResultPayload builds payload for successful tool execution
func buildToolResultPayload(req any, result any) any {
	// Extract tool name from request
	toolName := extractToolName(req)

	resultMap, ok := result.(map[string]any)
	resultSize := 0
	if ok {
		resultSize = len(resultMap)
	}

	return events.ToolCallCompletedPayload{
		ToolName:   toolName,
		ResultSize: resultSize,
		Success:    true,
		// Duration is tracked by middleware
	}
}

// buildPluginResultPayload builds payload for successful plugin query
func buildPluginResultPayload(req any, result any) any {
	componentName, method := extractPluginInfo(req)

	return events.PluginQueryCompletedPayload{
		PluginName: componentName,
		Method:     method,
		Success:    true,
		// Duration is tracked by middleware
	}
}

// buildFindingPayload builds payload for finding submission
func buildFindingPayload(ctx context.Context, req any) any {
	// Extract agent name from context
	agentName := "unknown"
	if name, ok := ctx.Value(CtxAgentName).(string); ok && name != "" {
		agentName = name
	}

	// Type assert to finding type
	if finding, ok := req.(*agent.Finding); ok {
		return events.FindingSubmittedPayload{
			FindingID:    finding.ID,
			Title:        finding.Title,
			Severity:     string(finding.Severity),
			AgentName:    agentName,
			TechniqueIDs: finding.CWE, // Use CWE as technique IDs fallback
		}
	}

	// Try FindingRequest wrapper
	if findingReq, ok := req.(FindingRequest); ok {
		if finding, ok := findingReq.Finding.(*agent.Finding); ok {
			return events.FindingSubmittedPayload{
				FindingID:    finding.ID,
				Title:        finding.Title,
				Severity:     string(finding.Severity),
				AgentName:    agentName,
				TechniqueIDs: finding.CWE,
			}
		}
	}

	// Fallback for map type
	if m, ok := req.(map[string]any); ok {
		// Extract technique IDs from map
		techniqueIDs := []string{}
		if ids, ok := m["technique_ids"].([]string); ok {
			techniqueIDs = ids
		} else if ids, ok := m["cwe"].([]string); ok {
			techniqueIDs = ids
		}

		return events.FindingSubmittedPayload{
			Title:        getStringOrDefault(m, "title", "unknown"),
			Severity:     getStringOrDefault(m, "severity", "unknown"),
			AgentName:    agentName,
			TechniqueIDs: techniqueIDs,
		}
	}

	return events.FindingSubmittedPayload{
		Title:     "unknown",
		Severity:  "unknown",
		AgentName: agentName,
	}
}

// buildAgentDelegatedPayload builds payload for agent delegation
func buildAgentDelegatedPayload(ctx context.Context, req any) any {
	// Extract from context
	fromAgent := "unknown"
	if name, ok := ctx.Value(CtxAgentName).(string); ok && name != "" {
		fromAgent = name
	}

	toAgent := "unknown"
	if name, ok := ctx.Value(CtxAgentTargetName).(string); ok && name != "" {
		toAgent = name
	}

	fromTraceID, fromSpanID := GetTraceContext(ctx)

	// Try AgentRequest wrapper
	if agentReq, ok := req.(AgentRequest); ok {
		if agentReq.Name != "" {
			toAgent = agentReq.Name
		}

		taskDesc := ""
		if task, ok := agentReq.Task.(agent.Task); ok {
			taskDesc = task.Description
		}

		return events.AgentDelegatedPayload{
			FromAgent:       fromAgent,
			ToAgent:         toAgent,
			TaskDescription: taskDesc,
			FromTraceID:     fromTraceID,
			FromSpanID:      fromSpanID,
			// ToTraceID and ToSpanID would be set when delegated agent starts
		}
	}

	// Try map type
	if m, ok := req.(map[string]any); ok {
		return events.AgentDelegatedPayload{
			FromAgent:       getStringOrDefault(m, "from_agent", fromAgent),
			ToAgent:         getStringOrDefault(m, "to_agent", toAgent),
			TaskDescription: getStringOrDefault(m, "task_description", ""),
			FromTraceID:     getStringOrDefault(m, "from_trace_id", fromTraceID),
			FromSpanID:      getStringOrDefault(m, "from_span_id", fromSpanID),
			ToTraceID:       getStringOrDefault(m, "to_trace_id", ""),
			ToSpanID:        getStringOrDefault(m, "to_span_id", ""),
		}
	}

	return events.AgentDelegatedPayload{
		FromAgent:   fromAgent,
		ToAgent:     toAgent,
		FromTraceID: fromTraceID,
		FromSpanID:  fromSpanID,
	}
}

// buildLLMRequestFailedPayload builds payload for failed LLM request
func buildLLMRequestFailedPayload(ctx context.Context, req any, err error) any {
	// Extract provider and slot from context if available
	provider := "unknown"
	slotName := "unknown"
	model := "unknown"

	if p, ok := ctx.Value(CtxProvider).(string); ok && p != "" {
		provider = p
	}
	if s, ok := ctx.Value(CtxSlotName).(string); ok && s != "" {
		slotName = s
	}

	// Try to extract model from request
	if chatReq, ok := req.(ChatRequest); ok {
		slotName = chatReq.Slot
	}

	return events.LLMRequestFailedPayload{
		Provider:  provider,
		Model:     model,
		SlotName:  slotName,
		Error:     err.Error(),
		Retryable: false, // Would need to determine from error type
		// Duration tracked by middleware
	}
}

// buildToolCallFailedPayload builds payload for failed tool call
func buildToolCallFailedPayload(req any, err error) any {
	toolName := extractToolName(req)

	return events.ToolCallFailedPayload{
		ToolName: toolName,
		Error:    err.Error(),
		// Duration tracked by middleware
	}
}

// buildPluginQueryFailedPayload builds payload for failed plugin query
func buildPluginQueryFailedPayload(req any, err error) any {
	componentName, method := extractPluginInfo(req)

	return events.PluginQueryFailedPayload{
		PluginName: componentName,
		Method:     method,
		Error:      err.Error(),
		// Duration tracked by middleware
	}
}

// Helper functions to extract data from requests

// getStringOrDefault safely extracts a string value from a map with a default fallback
func getStringOrDefault(m map[string]any, key, defaultVal string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return defaultVal
}

// extractToolName extracts the tool name from a tool call request.
//
// Priority:
//  1. *harnesspb.CallToolProtoRequest — use Name field.
//  2. *harnesspb.QueueToolWorkRequest — use ToolName field.
//  3. map[string]any — legacy/LLM-tool-call fallback, looks for "tool_name" or "name".
func extractToolName(req any) string {
	switch v := req.(type) {
	case *harnesspb.CallToolProtoRequest:
		return v.GetName()
	case *harnesspb.QueueToolWorkRequest:
		return v.GetToolName()
	case map[string]any:
		if name, ok := v["tool_name"].(string); ok {
			return name
		}
		if name, ok := v["name"].(string); ok {
			return name
		}
	}
	return ""
}

// extractPluginInfo extracts plugin name and method from a plugin query request.
//
// Priority:
//  1. *harnesspb.QueryPluginRequest — use Name and Method fields.
//  2. map[string]any — legacy fallback, looks for "plugin_name" and "method".
func extractPluginInfo(req any) (string, string) {
	switch v := req.(type) {
	case *harnesspb.QueryPluginRequest:
		return v.GetName(), v.GetMethod()
	case map[string]any:
		componentName, _ := v["plugin_name"].(string)
		method, _ := v["method"].(string)
		return componentName, method
	}
	return "", ""
}
