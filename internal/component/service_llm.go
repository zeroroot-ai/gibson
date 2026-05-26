package component

import (
	"context"
	"encoding/json"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// LLMToolCompleter extends LLMCompleter with tool-calling and structured output support.
// May be nil; CompleteWithTools and CompleteStructured return Unimplemented when nil.
type LLMToolCompleter interface {
	// CompleteWithTools executes a completion with tool definitions.
	// toolsJSON is a JSON-encoded []ToolDefinition.
	// Returns content, finish_reason, model, token usage, and JSON-encoded []ToolCallResult.
	CompleteWithTools(ctx context.Context, tenant, missionID, slot, messagesJSON, toolsJSON string, maxTokens int32, temperature float32) (content, finishReason, modelUsed string, promptTokens, completionTokens int32, toolCallsJSON string, err error)

	// CompleteStructured executes a completion requesting JSON output matching a schema.
	// Returns the raw JSON output and token usage.
	CompleteStructured(ctx context.Context, tenant, missionID, slot, messagesJSON, schemaJSON string, maxTokens int32, temperature float32) (resultJSON string, promptTokens, completionTokens int32, err error)
}

// CompleteWithTools proxies an LLM completion with tool definitions for function-calling support.
func (s *ComponentServiceServer) CompleteWithTools(
	ctx context.Context,
	req *componentpb.CompleteWithToolsRequest,
) (*componentpb.CompleteWithToolsResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.llmToolCompleter == nil {
		return nil, status.Error(codes.Unimplemented, "LLM tool completion not yet wired on this server")
	}

	if req.Slot == "" {
		return nil, status.Error(codes.InvalidArgument, "slot is required")
	}
	if len(req.Messages) == 0 {
		return nil, status.Error(codes.InvalidArgument, "messages is required")
	}

	messagesJSON, err := json.Marshal(req.Messages)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to marshal messages: %v", err)
	}

	toolsJSON, err := json.Marshal(req.Tools)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to marshal tools: %v", err)
	}

	s.logger.DebugContext(ctx, "completeWithTools: routing LLM request",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("slot", req.Slot),
		slog.Int("tool_count", len(req.Tools)),
	)

	missionID, slotOverrides, resolveErr := resolveMissionContext(ctx, s.missionCtx, req.WorkId, tenant, req.Slot, s.logger)
	if resolveErr != nil {
		s.logger.WarnContext(ctx, "completeWithTools: mission context lookup failed; using tenant defaults",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("error", resolveErr.Error()),
		)
	}

	maxTokens, temperature := applySlotOverrides(req.Slot, slotOverrides)

	content, finishReason, _, promptTokens, completionTokens, toolCallsJSON, err := s.llmToolCompleter.CompleteWithTools(
		ctx, tenant, missionID, req.Slot, string(messagesJSON), string(toolsJSON), maxTokens, temperature,
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "completeWithTools: LLM completion failed",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "completion failed: %v", err)
	}

	resp := &componentpb.CompleteWithToolsResponse{
		Response: &componentpb.LLMMessage{
			Role:    "assistant",
			Content: content,
		},
		Usage: &componentpb.TokenUsage{
			InputTokens:  promptTokens,
			OutputTokens: completionTokens,
		},
		FinishReason: finishReason,
	}

	if toolCallsJSON != "" {
		var toolCalls []*componentpb.ToolCallResult
		if err := json.Unmarshal([]byte(toolCallsJSON), &toolCalls); err != nil {
			s.logger.WarnContext(ctx, "completeWithTools: failed to unmarshal tool calls",
				slog.String("error", err.Error()),
			)
		} else {
			resp.ToolCalls = toolCalls
		}
	}

	return resp, nil
}

// CompleteStructured proxies an LLM completion requesting JSON output conforming to a schema.
func (s *ComponentServiceServer) CompleteStructured(
	ctx context.Context,
	req *componentpb.CompleteStructuredRequest,
) (*componentpb.CompleteStructuredResponse, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.llmToolCompleter == nil {
		return nil, status.Error(codes.Unimplemented, "LLM structured completion not yet wired on this server")
	}

	if req.Slot == "" {
		return nil, status.Error(codes.InvalidArgument, "slot is required")
	}
	if len(req.Messages) == 0 {
		return nil, status.Error(codes.InvalidArgument, "messages is required")
	}
	if req.SchemaJson == "" {
		return nil, status.Error(codes.InvalidArgument, "schema_json is required")
	}

	messagesJSON, err := json.Marshal(req.Messages)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to marshal messages: %v", err)
	}

	s.logger.DebugContext(ctx, "completeStructured: routing LLM request",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("slot", req.Slot),
	)

	missionID, slotOverrides, resolveErr := resolveMissionContext(ctx, s.missionCtx, req.WorkId, tenant, req.Slot, s.logger)
	if resolveErr != nil {
		s.logger.WarnContext(ctx, "completeStructured: mission context lookup failed; using tenant defaults",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("error", resolveErr.Error()),
		)
	}

	maxTokens, temperature := applySlotOverrides(req.Slot, slotOverrides)

	resultJSON, promptTokens, completionTokens, err := s.llmToolCompleter.CompleteStructured(
		ctx, tenant, missionID, req.Slot, string(messagesJSON), req.SchemaJson, maxTokens, temperature,
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "completeStructured: LLM completion failed",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "completion failed: %v", err)
	}

	return &componentpb.CompleteStructuredResponse{
		ResultJson: resultJSON,
		Usage: &componentpb.TokenUsage{
			InputTokens:  promptTokens,
			OutputTokens: completionTokens,
		},
	}, nil
}
