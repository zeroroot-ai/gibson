package middleware

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	agentpb "github.com/zero-day-ai/sdk/api/gen/gibson/agent/v1"
	typespb "github.com/zero-day-ai/sdk/api/gen/gibson/types/v1"
	"go.opentelemetry.io/otel/trace"
)

// StreamSender abstracts the gRPC bidirectional stream for sending agent events.
// This interface allows the middleware to send different event types to the client
// without depending on the concrete gRPC stream type.
type StreamSender interface {
	// SendToolCall sends a tool invocation event before the tool is executed.
	SendToolCall(call *agentpb.ToolCallEvent) error

	// SendToolResult sends the result of a tool invocation after execution.
	SendToolResult(result *agentpb.ToolResultEvent) error

	// SendOutput sends a text output chunk (final response or reasoning).
	SendOutput(output *agentpb.OutputChunk) error

	// SendFinding sends a security finding discovered during execution.
	SendFinding(finding *agentpb.FindingEvent) error
}

// StreamingMiddleware creates middleware that emits events to a gRPC stream.
// This replaces the StreamingHarness event emission logic with composable middleware.
//
// The middleware emits events based on operation type:
//   - Tool operations: SendToolCall before execution, SendToolResult after
//   - Chat operations: SendOutput for final responses
//   - Finding submissions: SendFinding when findings are submitted
//
// If stream is nil, the middleware operates in no-op mode (common for non-streaming clients).
//
// Stream send errors are logged but do not fail the operation. This ensures that
// streaming failures don't impact the core agent execution.
func StreamingMiddleware(stream StreamSender, logger *slog.Logger, tracer trace.Tracer) Middleware {
	return func(next Operation) Operation {
		return func(ctx context.Context, req any) (any, error) {
			// No-op if no stream provided (non-streaming execution)
			if stream == nil {
				return next(ctx, req)
			}

			// Get operation type from context
			opType, ok := ctx.Value(CtxOperationType).(OperationType)
			if !ok {
				// No operation type in context, skip streaming
				return next(ctx, req)
			}

			// Get trace information for correlation
			traceID, spanID := extractTraceInfo(ctx, tracer)

			// Generate callID once for tool call/result correlation
			var callID string
			if opType == OpCallToolProto {
				callID = uuid.New().String()
			}

			// Handle pre-execution events (tool calls)
			if opType == OpCallToolProto {
				if err := emitToolCallEvent(ctx, stream, req, callID, traceID, spanID); err != nil {
					if logger != nil {
						logger.Warn("failed to emit tool call event", "error", err)
					}
				}
			}

			// Execute the actual operation
			result, err := next(ctx, req)

			// Handle post-execution events based on operation type
			switch opType {
			case OpCallToolProto:
				if streamErr := emitToolResultEvent(ctx, stream, req, result, err, callID, traceID, spanID); streamErr != nil {
					if logger != nil {
						logger.Warn("failed to emit tool result event", "error", streamErr)
					}
				}

			case OpComplete, OpCompleteWithTools:
				if streamErr := emitOutputEvent(ctx, stream, result, traceID, spanID); streamErr != nil {
					if logger != nil {
						logger.Warn("failed to emit output event", "error", streamErr)
					}
				}

			case OpSubmitFinding:
				if streamErr := emitFindingEvent(ctx, stream, req, traceID, spanID); streamErr != nil {
					if logger != nil {
						logger.Warn("failed to emit finding event", "error", streamErr)
					}
				}
			}

			return result, err
		}
	}
}

// emitToolCallEvent sends a ToolCallEvent before tool execution.
func emitToolCallEvent(ctx context.Context, stream StreamSender, req any, callID, traceID, spanID string) error {
	// Extract tool call information from request
	// The request should be a map[string]any with "name" and "input" fields
	toolReq, ok := req.(map[string]any)
	if !ok {
		return nil // Skip if request format unexpected
	}
	_ = toolReq // Suppress unused warning for now

	toolName, _ := toolReq["name"].(string)
	if toolName == "" {
		return nil
	}

	// Serialize input to JSON
	input, _ := toolReq["input"].(map[string]any)
	inputJSON, err := json.Marshal(input)
	if err != nil {
		return err
	}

	event := buildToolCallEvent(toolName, string(inputJSON), callID, traceID, spanID)
	return stream.SendToolCall(event)
}

// emitToolResultEvent sends a ToolResultEvent after tool execution.
func emitToolResultEvent(ctx context.Context, stream StreamSender, req any, result any, execErr error, callID, traceID, spanID string) error {
	// Serialize output
	var outputJSON string
	if result != nil {
		output, ok := result.(map[string]any)
		if !ok {
			// Wrap non-map results
			output = map[string]any{"result": result}
		}
		outputBytes, err := json.Marshal(output)
		if err != nil {
			return err
		}
		outputJSON = string(outputBytes)
	}

	// Success is true if no execution error occurred
	success := execErr == nil

	event := buildToolResultEvent(callID, outputJSON, success, traceID, spanID)
	return stream.SendToolResult(event)
}

// emitOutputEvent sends an OutputChunk for LLM completion responses.
func emitOutputEvent(ctx context.Context, stream StreamSender, result any, traceID, spanID string) error {
	// Extract content from CompletionResponse
	resp, ok := result.(*llm.CompletionResponse)
	if !ok {
		return nil
	}

	if resp.Message.Content == "" {
		return nil // No content to emit
	}

	event := buildOutputEvent(resp.Message.Content, false, traceID, spanID)
	return stream.SendOutput(event)
}

// emitFindingEvent sends a FindingEvent when a finding is submitted.
func emitFindingEvent(ctx context.Context, stream StreamSender, req any, traceID, spanID string) error {
	// Extract finding from request
	finding, ok := req.(*agent.Finding)
	if !ok {
		return nil
	}

	// Serialize finding to JSON
	findingJSON, err := json.Marshal(finding)
	if err != nil {
		return err
	}

	event := buildFindingEvent(string(findingJSON), traceID, spanID)
	return stream.SendFinding(event)
}

// buildToolCallEvent constructs a ToolCallEvent proto message.
func buildToolCallEvent(toolName, inputJSON, callID, traceID, spanID string) *agentpb.ToolCallEvent {
	// Parse input JSON to map[string]any, then convert to TypedValue map
	var inputMap map[string]any
	if err := json.Unmarshal([]byte(inputJSON), &inputMap); err != nil {
		// If parsing fails, return empty input map
		inputMap = make(map[string]any)
	}

	// Convert to TypedValue map
	inputTypedMap := make(map[string]*commonpb.TypedValue)
	for k, v := range inputMap {
		inputTypedMap[k] = anyToTypedValue(v)
	}

	return &agentpb.ToolCallEvent{
		ToolName: toolName,
		Input:    inputTypedMap,
		CallId:   callID,
	}
}

// buildToolResultEvent constructs a ToolResultEvent proto message.
func buildToolResultEvent(callID, outputJSON string, success bool, traceID, spanID string) *agentpb.ToolResultEvent {
	// Parse output JSON to any, then convert to TypedValue
	var output any
	if err := json.Unmarshal([]byte(outputJSON), &output); err != nil {
		// If parsing fails, use nil output
		output = nil
	}

	return &agentpb.ToolResultEvent{
		CallId:  callID,
		Output:  anyToTypedValue(output),
		Success: success,
	}
}

// buildOutputEvent constructs an OutputChunk proto message.
func buildOutputEvent(content string, isReasoning bool, traceID, spanID string) *agentpb.OutputChunk {
	return &agentpb.OutputChunk{
		Content:     content,
		IsReasoning: isReasoning,
	}
}

// buildFindingEvent constructs a FindingEvent proto message.
func buildFindingEvent(findingJSON, traceID, spanID string) *agentpb.FindingEvent {
	// Parse finding JSON to proto Finding
	var finding typespb.Finding
	if err := json.Unmarshal([]byte(findingJSON), &finding); err != nil {
		// If parsing fails, return empty finding
		return &agentpb.FindingEvent{
			Finding: &typespb.Finding{},
		}
	}

	return &agentpb.FindingEvent{
		Finding: &finding,
	}
}

// extractTraceInfo extracts trace and span IDs from the context.
// Returns empty strings if no trace information is available.
func extractTraceInfo(ctx context.Context, tracer trace.Tracer) (traceID, spanID string) {
	if tracer == nil {
		return "", ""
	}

	span := trace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return "", ""
	}

	return span.SpanContext().TraceID().String(), span.SpanContext().SpanID().String()
}

// gRPCStreamAdapter adapts a grpc.BidiStreamingServer to the StreamSender interface.
// This allows the middleware to work with the actual gRPC stream.
type gRPCStreamAdapter struct {
	stream interface {
		Send(*agentpb.StreamExecuteResponse) error
	}
	sequence int64
}

// NewGRPCStreamAdapter creates a StreamSender from a gRPC bidirectional stream.
func NewGRPCStreamAdapter(stream interface {
	Send(*agentpb.StreamExecuteResponse) error
}) StreamSender {
	return &gRPCStreamAdapter{
		stream:   stream,
		sequence: 0,
	}
}

func (a *gRPCStreamAdapter) nextSequence() int64 {
	a.sequence++
	return a.sequence
}

func (a *gRPCStreamAdapter) SendToolCall(call *agentpb.ToolCallEvent) error {
	msg := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_ToolCall{
			ToolCall: call,
		},
		Sequence:    a.nextSequence(),
		TimestampMs: time.Now().UnixMilli(),
	}
	return a.stream.Send(msg)
}

func (a *gRPCStreamAdapter) SendToolResult(result *agentpb.ToolResultEvent) error {
	msg := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_ToolResult{
			ToolResult: result,
		},
		Sequence:    a.nextSequence(),
		TimestampMs: time.Now().UnixMilli(),
	}
	return a.stream.Send(msg)
}

func (a *gRPCStreamAdapter) SendOutput(output *agentpb.OutputChunk) error {
	msg := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Output{
			Output: output,
		},
		Sequence:    a.nextSequence(),
		TimestampMs: time.Now().UnixMilli(),
	}
	return a.stream.Send(msg)
}

func (a *gRPCStreamAdapter) SendFinding(finding *agentpb.FindingEvent) error {
	msg := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Finding{
			Finding: finding,
		},
		Sequence:    a.nextSequence(),
		TimestampMs: time.Now().UnixMilli(),
	}
	return a.stream.Send(msg)
}

// anyToTypedValue converts a Go any value to a proto TypedValue.
func anyToTypedValue(v any) *commonpb.TypedValue {
	if v == nil {
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_NullValue{
				NullValue: commonpb.NullValue_NULL_VALUE_UNSPECIFIED,
			},
		}
	}

	switch val := v.(type) {
	case string:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_StringValue{StringValue: val},
		}
	case int:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_IntValue{IntValue: int64(val)},
		}
	case int32:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_IntValue{IntValue: int64(val)},
		}
	case int64:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_IntValue{IntValue: val},
		}
	case float32:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: float64(val)},
		}
	case float64:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_DoubleValue{DoubleValue: val},
		}
	case bool:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_BoolValue{BoolValue: val},
		}
	case []byte:
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_BytesValue{BytesValue: val},
		}
	case []any:
		items := make([]*commonpb.TypedValue, len(val))
		for i, item := range val {
			items[i] = anyToTypedValue(item)
		}
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_ArrayValue{
				ArrayValue: &commonpb.TypedArray{Items: items},
			},
		}
	case map[string]any:
		entries := make(map[string]*commonpb.TypedValue)
		for k, v := range val {
			entries[k] = anyToTypedValue(v)
		}
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_MapValue{
				MapValue: &commonpb.TypedMap{Entries: entries},
			},
		}
	default:
		// For unknown types, convert to string representation
		jsonBytes, _ := json.Marshal(v)
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_StringValue{StringValue: string(jsonBytes)},
		}
	}
}
