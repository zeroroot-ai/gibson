package harness

import (
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	commonpb "github.com/zero-day-ai/sdk/api/gen/gibson/common/v1"
	harnesspb "github.com/zero-day-ai/sdk/api/gen/gibson/harness/v1"
	toolpb "github.com/zero-day-ai/sdk/api/gen/gibson/tool/v1"
	"google.golang.org/grpc"
)

// CallToolProtoStream implements the streaming tool execution RPC.
// It resolves the tool endpoint, connects to the tool's StreamExecute RPC,
// and forwards all ToolMessage events back to the calling agent.
func (s *HarnessCallbackService) CallToolProtoStream(req *harnesspb.CallToolProtoStreamRequest, stream harnesspb.HarnessCallbackService_CallToolProtoStreamServer) error {
	ctx := stream.Context()

	// Get harness for tool resolution
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return err
	}

	// Publish tool.call.started event
	s.publishEvent(ctx, "tool.call.started", map[string]interface{}{
		"tool_name":      req.Name,
		"mission_id":     req.Context.MissionId,
		"agent_name":     req.Context.AgentName,
		"task_id":        req.Context.TaskId,
		"parent_span_id": req.Context.SpanId,
		"input_type":     req.InputType,
		"output_type":    req.OutputType,
		"streaming":      true,
	})

	// Get tool descriptor to validate it exists
	toolDesc, err := harness.GetToolDescriptor(ctx, req.Name)
	if err != nil {
		s.logger.Error("tool not found", "error", err, "tool", req.Name)

		// Send error event
		errEvent := &harnesspb.CallToolProtoStreamResponse{
			Payload: &harnesspb.CallToolProtoStreamResponse_Error{
				Error: &harnesspb.ToolErrorEvent{
					Error: &harnesspb.HarnessError{
						Code:    commonpb.ErrorCode_ERROR_CODE_TOOL_NOT_FOUND,
						Message: fmt.Sprintf("tool not found: %s", req.Name),
					},
					Fatal: true,
				},
			},
			TraceId:     req.Context.TraceId,
			SpanId:      req.Context.SpanId,
			Sequence:    1,
			TimestampMs: time.Now().UnixMilli(),
		}

		if sendErr := stream.Send(errEvent); sendErr != nil {
			s.logger.Error("failed to send error event", "error", sendErr)
		}

		return err
	}

	// Resolve tool endpoint
	// Try to get tool from harness (handles both local and remote tools)
	defaultHarness, ok := harness.(*DefaultAgentHarness)
	if !ok {
		s.logger.Error("unexpected harness type", "tool", req.Name)
		return fmt.Errorf("unexpected harness type")
	}

	tool, err := defaultHarness.toolRegistry.Get(req.Name)
	if err != nil && defaultHarness.registryAdapter != nil {
		// Try remote discovery
		tool, err = defaultHarness.registryAdapter.DiscoverTool(ctx, req.Name)
	}

	if err != nil {
		s.logger.Error("failed to resolve tool endpoint", "error", err, "tool", req.Name)

		errEvent := &harnesspb.CallToolProtoStreamResponse{
			Payload: &harnesspb.CallToolProtoStreamResponse_Error{
				Error: &harnesspb.ToolErrorEvent{
					Error: &harnesspb.HarnessError{
						Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
						Message: fmt.Sprintf("failed to resolve tool endpoint: %v", err),
					},
					Fatal: true,
				},
			},
			TraceId:     req.Context.TraceId,
			SpanId:      req.Context.SpanId,
			Sequence:    1,
			TimestampMs: time.Now().UnixMilli(),
		}

		if sendErr := stream.Send(errEvent); sendErr != nil {
			s.logger.Error("failed to send error event", "error", sendErr)
		}

		return err
	}

	// Get the gRPC connection to the tool
	// Check if tool is a GRPCToolClient (which has a connection)
	type connTool interface {
		GetConn() *grpc.ClientConn
	}

	var conn *grpc.ClientConn
	if ct, ok := tool.(connTool); ok {
		conn = ct.GetConn()
	} else {
		// Tool is local - not yet supported for streaming
		s.logger.Error("streaming not supported for local tools", "tool", req.Name)

		errEvent := &harnesspb.CallToolProtoStreamResponse{
			Payload: &harnesspb.CallToolProtoStreamResponse_Error{
				Error: &harnesspb.ToolErrorEvent{
					Error: &harnesspb.HarnessError{
						Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
						Message: "streaming not yet supported for local tools",
					},
					Fatal: true,
				},
			},
			TraceId:     req.Context.TraceId,
			SpanId:      req.Context.SpanId,
			Sequence:    1,
			TimestampMs: time.Now().UnixMilli(),
		}

		if sendErr := stream.Send(errEvent); sendErr != nil {
			s.logger.Error("failed to send error event", "error", sendErr)
		}

		return fmt.Errorf("streaming not supported for local tools")
	}

	// Create ToolService client for streaming
	toolClient := toolpb.NewToolServiceClient(conn)

	// Open bidirectional stream to tool
	toolStream, err := toolClient.StreamExecute(ctx)
	if err != nil {
		s.logger.Error("failed to open tool stream", "error", err, "tool", req.Name)

		errEvent := &harnesspb.CallToolProtoStreamResponse{
			Payload: &harnesspb.CallToolProtoStreamResponse_Error{
				Error: &harnesspb.ToolErrorEvent{
					Error: &harnesspb.HarnessError{
						Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
						Message: fmt.Sprintf("failed to connect to tool: %v", err),
					},
					Fatal: true,
				},
			},
			TraceId:     req.Context.TraceId,
			SpanId:      req.Context.SpanId,
			Sequence:    1,
			TimestampMs: time.Now().UnixMilli(),
		}

		if sendErr := stream.Send(errEvent); sendErr != nil {
			s.logger.Error("failed to send error event", "error", sendErr)
		}

		return err
	}

	// Send start request to tool
	startReq := &toolpb.StreamExecuteRequest{
		Payload: &toolpb.StreamExecuteRequest_Start{
			Start: &toolpb.ToolStartRequest{
				InputJson:    string(req.InputJson),
				TimeoutMs:    req.TimeoutMs,
				TraceId:      req.Context.TraceId,
				ParentSpanId: req.Context.SpanId,
			},
		},
	}

	if err := toolStream.Send(startReq); err != nil {
		s.logger.Error("failed to send start request to tool", "error", err, "tool", req.Name)

		errEvent := &harnesspb.CallToolProtoStreamResponse{
			Payload: &harnesspb.CallToolProtoStreamResponse_Error{
				Error: &harnesspb.ToolErrorEvent{
					Error: &harnesspb.HarnessError{
						Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
						Message: fmt.Sprintf("failed to start tool execution: %v", err),
					},
					Fatal: true,
				},
			},
			TraceId:     req.Context.TraceId,
			SpanId:      req.Context.SpanId,
			Sequence:    1,
			TimestampMs: time.Now().UnixMilli(),
		}

		if sendErr := stream.Send(errEvent); sendErr != nil {
			s.logger.Error("failed to send error event", "error", sendErr)
		}

		return err
	}

	// Close send side after starting
	if err := toolStream.CloseSend(); err != nil {
		s.logger.Warn("failed to close tool stream send", "error", err, "tool", req.Name)
	}

	// Generate call_id for this tool execution
	callID := uuid.New().String()

	// Rate limiting for progress events (max 10 events/second = 100ms between events)
	var lastProgressEvent time.Time
	var lastProgressPercent int32

	// Stall detection timer - emit event if no progress for 30 seconds
	stallTimer := time.NewTimer(30 * time.Second)
	defer stallTimer.Stop()

	// Channel to signal progress updates
	progressUpdated := make(chan struct{}, 1)

	// Goroutine to detect stalls
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-progressUpdated:
				// Reset timer on progress
				if !stallTimer.Stop() {
					select {
					case <-stallTimer.C:
					default:
					}
				}
				stallTimer.Reset(30 * time.Second)
			case <-stallTimer.C:
				// No progress for 30 seconds - emit stall event
				s.publishEvent(ctx, "tool.progress_stalled", map[string]interface{}{
					"tool_name":             req.Name,
					"call_id":               callID,
					"last_progress_percent": lastProgressPercent,
					"stall_duration_ms":     30000,
					"mission_id":            req.Context.MissionId,
					"agent_name":            req.Context.AgentName,
					"task_id":               req.Context.TaskId,
				})
				// Reset timer to continue monitoring
				stallTimer.Reset(30 * time.Second)
			}
		}
	}()

	// Forward all messages from tool to agent
	sequence := int64(0)
	for {
		toolMsg, err := toolStream.Recv()
		if err != nil {
			if err == io.EOF {
				// Stream completed normally
				s.logger.Debug("tool stream completed", "tool", req.Name)
				break
			}

			s.logger.Error("error receiving from tool stream", "error", err, "tool", req.Name)

			// Send error to agent
			sequence++
			errEvent := &harnesspb.CallToolProtoStreamResponse{
				Payload: &harnesspb.CallToolProtoStreamResponse_Error{
					Error: &harnesspb.ToolErrorEvent{
						Error: &harnesspb.HarnessError{
							Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
							Message: fmt.Sprintf("tool stream error: %v", err),
						},
						Fatal: true,
					},
				},
				TraceId:     req.Context.TraceId,
				SpanId:      req.Context.SpanId,
				Sequence:    sequence,
				TimestampMs: time.Now().UnixMilli(),
			}

			if sendErr := stream.Send(errEvent); sendErr != nil {
				s.logger.Error("failed to send error event", "error", sendErr)
			}

			return err
		}

		sequence++

		// Convert ToolMessage to CallToolProtoStreamResponse
		var response *harnesspb.CallToolProtoStreamResponse

		switch payload := toolMsg.Payload.(type) {
		case *toolpb.StreamExecuteResponse_Progress:
			response = &harnesspb.CallToolProtoStreamResponse{
				Payload: &harnesspb.CallToolProtoStreamResponse_Progress{
					Progress: &harnesspb.ToolProgressEvent{
						Percent: payload.Progress.Percent,
						Stage:   payload.Progress.Stage,
						Message: payload.Progress.Message,
					},
				},
				TraceId:     toolMsg.TraceId,
				SpanId:      toolMsg.SpanId,
				Sequence:    sequence,
				TimestampMs: toolMsg.TimestampMs,
			}

			// Forward progress to EventBus with rate limiting (max 10 events/second)
			now := time.Now()
			if now.Sub(lastProgressEvent) > 100*time.Millisecond {
				s.publishEvent(ctx, "tool.progress", map[string]interface{}{
					"tool_name":        req.Name,
					"call_id":          callID,
					"percent_complete": payload.Progress.Percent,
					"phase":            payload.Progress.Stage,
					"message":          payload.Progress.Message,
					"mission_id":       req.Context.MissionId,
					"agent_name":       req.Context.AgentName,
					"task_id":          req.Context.TaskId,
				})
				lastProgressEvent = now
			}

			// Update progress tracking for stall detection
			lastProgressPercent = payload.Progress.Percent
			select {
			case progressUpdated <- struct{}{}:
			default:
			}

		case *toolpb.StreamExecuteResponse_Partial:
			response = &harnesspb.CallToolProtoStreamResponse{
				Payload: &harnesspb.CallToolProtoStreamResponse_Partial{
					Partial: &harnesspb.ToolPartialResultEvent{
						OutputJson:  []byte(payload.Partial.OutputJson),
						Description: payload.Partial.Description,
					},
				},
				TraceId:     toolMsg.TraceId,
				SpanId:      toolMsg.SpanId,
				Sequence:    sequence,
				TimestampMs: toolMsg.TimestampMs,
			}

			// Forward partial result to EventBus
			// Note: Description field indicates if this is incremental
			s.publishEvent(ctx, "tool.partial_result", map[string]interface{}{
				"tool_name":      req.Name,
				"call_id":        callID,
				"partial_output": payload.Partial.OutputJson,
				"is_incremental": payload.Partial.Description != "", // Use description field to indicate incremental
				"description":    payload.Partial.Description,
				"mission_id":     req.Context.MissionId,
				"agent_name":     req.Context.AgentName,
				"task_id":        req.Context.TaskId,
			})

		case *toolpb.StreamExecuteResponse_Warning:
			response = &harnesspb.CallToolProtoStreamResponse{
				Payload: &harnesspb.CallToolProtoStreamResponse_Warning{
					Warning: &harnesspb.ToolWarningEvent{
						Message: payload.Warning.Message,
						Code:    payload.Warning.Code,
					},
				},
				TraceId:     toolMsg.TraceId,
				SpanId:      toolMsg.SpanId,
				Sequence:    sequence,
				TimestampMs: toolMsg.TimestampMs,
			}

			// Forward warning to EventBus
			s.publishEvent(ctx, "tool.warning", map[string]interface{}{
				"tool_name":       req.Name,
				"call_id":         callID,
				"warning_message": payload.Warning.Message,
				"warning_context": payload.Warning.Code, // Use code field as context
				"warning_code":    payload.Warning.Code,
				"mission_id":      req.Context.MissionId,
				"agent_name":      req.Context.AgentName,
				"task_id":         req.Context.TaskId,
			})

		case *toolpb.StreamExecuteResponse_Complete:
			response = &harnesspb.CallToolProtoStreamResponse{
				Payload: &harnesspb.CallToolProtoStreamResponse_Complete{
					Complete: &harnesspb.ToolCompleteEvent{
						OutputJson: []byte(payload.Complete.OutputJson),
					},
				},
				TraceId:     toolMsg.TraceId,
				SpanId:      toolMsg.SpanId,
				Sequence:    sequence,
				TimestampMs: toolMsg.TimestampMs,
			}

			// Publish tool.call.completed event
			s.publishEvent(ctx, "tool.call.completed", map[string]interface{}{
				"tool_name":      req.Name,
				"mission_id":     req.Context.MissionId,
				"agent_name":     req.Context.AgentName,
				"task_id":        req.Context.TaskId,
				"parent_span_id": req.Context.SpanId,
				"streaming":      true,
			})

		case *toolpb.StreamExecuteResponse_Error:
			// Map error code string to ErrorCode enum
			// Default to INTERNAL if code is not recognized
			errorCode := commonpb.ErrorCode_ERROR_CODE_INTERNAL
			if payload.Error.Error != nil {
				switch payload.Error.Error.Code {
				case "invalid_input":
					errorCode = commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
				case "timeout":
					errorCode = commonpb.ErrorCode_ERROR_CODE_TIMEOUT
				case "permission_denied":
					errorCode = commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED
				default:
					errorCode = commonpb.ErrorCode_ERROR_CODE_INTERNAL
				}
			}

			response = &harnesspb.CallToolProtoStreamResponse{
				Payload: &harnesspb.CallToolProtoStreamResponse_Error{
					Error: &harnesspb.ToolErrorEvent{
						Error: &harnesspb.HarnessError{
							Code:    errorCode,
							Message: payload.Error.Error.Message,
						},
						Fatal: payload.Error.Fatal,
					},
				},
				TraceId:     toolMsg.TraceId,
				SpanId:      toolMsg.SpanId,
				Sequence:    sequence,
				TimestampMs: toolMsg.TimestampMs,
			}

			// Publish tool.call.failed event
			s.publishEvent(ctx, "tool.call.failed", map[string]interface{}{
				"tool_name":      req.Name,
				"mission_id":     req.Context.MissionId,
				"agent_name":     req.Context.AgentName,
				"task_id":        req.Context.TaskId,
				"error":          payload.Error.Error.Message,
				"parent_span_id": req.Context.SpanId,
				"streaming":      true,
			})

		default:
			s.logger.Warn("unknown tool message type", "tool", req.Name)
			continue
		}

		// Send response to agent
		if err := stream.Send(response); err != nil {
			s.logger.Error("failed to send response to agent", "error", err, "tool", req.Name)
			return err
		}

		// Log progress events
		if progress, ok := response.Payload.(*harnesspb.CallToolProtoStreamResponse_Progress); ok {
			s.logger.Debug("tool progress",
				"tool", req.Name,
				"percent", progress.Progress.Percent,
				"stage", progress.Progress.Stage,
				"message", progress.Progress.Message,
			)
		}
	}

	// Suppress unused variable warning
	_ = toolDesc

	s.logger.Debug("streaming tool call completed", "tool", req.Name)
	return nil
}
