// Package harness — DefaultAgentHarness streaming-tool dispatch.
//
// CallToolProtoStream is the streaming counterpart to CallToolProto. It
// resolves the tool the same way as CallToolProto, then opens the tool's
// gRPC StreamExecute bidi stream and translates each ToolStreamResponse
// payload variant into the matching SDK ToolStreamCallback invocation.
//
// Spec: headline-feature-completion R1.
package harness

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/tool"
	"github.com/zeroroot-ai/gibson/internal/types"
	toolpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tool/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	sdkagent "github.com/zeroroot-ai/sdk/agent"
)

// CallToolProtoStream invokes a tool with streaming event callbacks.
//
// Discovery follows the same path as CallToolProto:
//  1. ComponentRegistry direct gRPC endpoint, when registered with one.
//  2. RegistryAdapter fallback (Redis-backed).
//
// The resolved tool MUST expose an underlying gRPC connection (so we can
// open ToolService.StreamExecute). In-process tools without a connection
// degrade gracefully: we run a synchronous CallToolProto and emit a single
// "complete" partial via the callback.
//
// On stream completion, the final tool output is unmarshalled into
// `response` and (when callback is non-nil) is also delivered as a
// partial result.
func (h *DefaultAgentHarness) CallToolProtoStream(
	ctx context.Context,
	name string,
	request proto.Message,
	response proto.Message,
	callback sdkagent.ToolStreamCallback,
) error {
	ctx, span := h.tracer.Start(ctx, "harness.CallToolProtoStream")
	defer span.End()

	if request == nil || response == nil {
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("CallToolProtoStream: nil request or response for tool %s", name),
			nil,
		)
	}

	h.logger.Debug("calling tool with streaming proto messages",
		"tool", name,
		"input_type", string(request.ProtoReflect().Descriptor().FullName()),
		"output_type", string(response.ProtoReflect().Descriptor().FullName()))

	// Resolve the tool via the same dispatch path CallToolProto uses.
	resolved, err := h.resolveToolForStreaming(ctx, name)
	if err != nil {
		return err
	}

	// If the resolved tool exposes a gRPC connection, use the streaming
	// path. Otherwise degrade to non-streaming: run CallToolProto and
	// emit a single "complete" callback.
	type connTool interface {
		GetConn() *grpc.ClientConn
	}

	ct, hasConn := resolved.(connTool)
	if !hasConn || ct.GetConn() == nil {
		h.logger.Debug("tool has no gRPC connection; degrading to non-streaming dispatch",
			"tool", name)
		// Fall back to non-streaming execution. After CallToolProto fills
		// `response`, deliver a final partial to the callback so callers
		// observing the stream see the same shape they'd get from a true
		// streaming tool.
		if cpErr := h.CallToolProto(ctx, name, request, response); cpErr != nil {
			if callback != nil {
				callback.OnError(cpErr, true)
			}
			return cpErr
		}
		if callback != nil {
			callback.OnPartial(response, false)
		}
		return nil
	}

	conn := ct.GetConn()
	toolClient := toolpb.NewToolServiceClient(conn)

	// Open bidi stream.
	toolStream, err := toolClient.StreamExecute(ctx)
	if err != nil {
		wrapped := types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("CallToolProtoStream: open stream for tool %s: %v", name, err),
			err,
		)
		if callback != nil {
			callback.OnError(wrapped, true)
		}
		return wrapped
	}

	// Marshal request to JSON (the wire format used by ToolStartRequest).
	jsonBytes, err := protojson.Marshal(request)
	if err != nil {
		wrapped := types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("CallToolProtoStream: marshal input for tool %s: %v", name, err),
			err,
		)
		if callback != nil {
			callback.OnError(wrapped, true)
		}
		return wrapped
	}

	startReq := &toolpb.StreamExecuteRequest{
		Payload: &toolpb.StreamExecuteRequest_Start{
			Start: &toolpb.ToolStartRequest{
				InputJson: string(jsonBytes),
			},
		},
	}
	if err := toolStream.Send(startReq); err != nil {
		wrapped := types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("CallToolProtoStream: send Start to tool %s: %v", name, err),
			err,
		)
		if callback != nil {
			callback.OnError(wrapped, true)
		}
		return wrapped
	}
	// Half-close the send side — we send no further client messages.
	if err := toolStream.CloseSend(); err != nil {
		h.logger.Warn("CloseSend on tool stream failed", "tool", name, "error", err)
	}

	// Auth context: surface the tenant from the caller's ctx for any
	// metric/log enrichment downstream observers expect.
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		h.logger.Debug("CallToolProtoStream: empty tenant in caller ctx", "tool", name)
	}

	for {
		toolMsg, recvErr := toolStream.Recv()
		if errors.Is(recvErr, io.EOF) {
			// Clean stream end. If the tool emitted Complete we'll have
			// already populated `response`; if not, treat the empty
			// stream as success-with-empty-output.
			return nil
		}
		if recvErr != nil {
			wrapped := types.WrapError(
				ErrHarnessToolExecutionFailed,
				fmt.Sprintf("CallToolProtoStream: recv from tool %s: %v", name, recvErr),
				recvErr,
			)
			if callback != nil {
				callback.OnError(wrapped, true)
			}
			return wrapped
		}

		switch payload := toolMsg.Payload.(type) {

		case *toolpb.StreamExecuteResponse_Progress:
			if callback != nil && payload.Progress != nil {
				callback.OnProgress(int(payload.Progress.Percent), payload.Progress.Stage, payload.Progress.Message)
			}

		case *toolpb.StreamExecuteResponse_Partial:
			if callback != nil && payload.Partial != nil {
				// Best-effort: unmarshal the partial JSON into a fresh
				// instance of the response proto so the callback gets a
				// typed snapshot. On unmarshal failure we still notify
				// the caller via OnPartial(nil, …).
				snapshot := proto.Clone(response)
				proto.Reset(snapshot)
				if uErr := protojson.Unmarshal([]byte(payload.Partial.OutputJson), snapshot); uErr != nil {
					h.logger.Debug("CallToolProtoStream: partial unmarshal failed",
						"tool", name, "error", uErr)
					callback.OnPartial(nil, false)
				} else {
					callback.OnPartial(snapshot, false)
				}
			}

		case *toolpb.StreamExecuteResponse_Warning:
			if callback != nil && payload.Warning != nil {
				callback.OnWarning(payload.Warning.Message, payload.Warning.Code)
			}

		case *toolpb.StreamExecuteResponse_Complete:
			if payload.Complete == nil {
				continue
			}
			// Populate the caller-supplied `response` with the final output.
			proto.Reset(response)
			if uErr := protojson.Unmarshal([]byte(payload.Complete.OutputJson), response); uErr != nil {
				wrapped := types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("CallToolProtoStream: unmarshal complete output for tool %s: %v", name, uErr),
					uErr,
				)
				if callback != nil {
					callback.OnError(wrapped, true)
				}
				return wrapped
			}
			if callback != nil {
				callback.OnPartial(response, false)
			}
			return nil

		case *toolpb.StreamExecuteResponse_Error:
			if payload.Error == nil || payload.Error.Error == nil {
				continue
			}
			fatal := payload.Error.Fatal
			toolErr := fmt.Errorf("tool %s: %s: %s", name, payload.Error.Error.Code, payload.Error.Error.Message)
			if callback != nil {
				callback.OnError(toolErr, fatal)
			}
			if fatal {
				return toolErr
			}

		default:
			h.logger.Debug("CallToolProtoStream: unknown payload variant; skipping",
				"tool", name)
		}
	}
}

// resolveToolForStreaming locates a tool for streaming dispatch. It
// reuses the same precedence as CallToolProto (component registry direct
// endpoint → registry adapter), but does not enter the work-queue or
// sandboxed-executor branches — both of which are non-streaming today.
//
// On miss, returns a wrapped tool-not-found error.
func (h *DefaultAgentHarness) resolveToolForStreaming(ctx context.Context, name string) (tool.Tool, error) {
	// Component registry path with direct gRPC endpoint.
	if h.componentRegistry != nil {
		tenant := auth.TenantStringFromContext(ctx)
		if tenant != "" {
			instances, discErr := h.componentRegistry.Discover(ctx, tenant, "tool", name)
			if discErr == nil && len(instances) > 0 {
				if endpoint := instances[0].Metadata["grpc_endpoint"]; endpoint != "" && h.registryAdapter != nil {
					if remoteTool, adapterErr := h.registryAdapter.DiscoverTool(ctx, name); adapterErr == nil {
						return remoteTool, nil
					}
				}
			}
		}
	}

	// Registry adapter fallback.
	if h.registryAdapter != nil {
		remoteTool, discErr := h.registryAdapter.DiscoverTool(ctx, name)
		if discErr == nil {
			return remoteTool, nil
		}
		return nil, types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool not found via streaming registry adapter: %s (%v)", name, discErr),
			discErr,
		)
	}

	return nil, types.WrapError(
		ErrHarnessToolExecutionFailed,
		fmt.Sprintf("tool not found and no streaming discovery path available: %s", name),
		nil,
	)
}

// Compile-time assertion that the GRPCToolClient adapter exposes the
// connection used by streaming dispatch. Catches drift if the type
// stops implementing GetConn.
var _ interface {
	GetConn() *grpc.ClientConn
} = (*component.GRPCToolClient)(nil)
