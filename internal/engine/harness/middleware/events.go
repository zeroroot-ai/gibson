package middleware

import (
	"context"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/events"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

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
