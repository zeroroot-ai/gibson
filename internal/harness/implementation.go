package harness

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
	"github.com/zero-day-ai/sdk/codegen/workspace"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/protoresolver"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// DefaultAgentHarness is the production implementation of the AgentHarness interface.
// It provides agents with access to all framework capabilities including LLM operations,
// tool execution, plugin queries, sub-agent delegation, finding management, memory storage,
// and observability primitives.
//
// The harness orchestrates interactions between agents and the Gibson platform,
// handling:
//   - LLM provider management and slot-based model selection
//   - Tool registration, validation, and execution
//   - Plugin lifecycle and communication
//   - Sub-agent discovery and delegation
//   - Finding storage and querying
//   - Memory tier coordination (working, mission, long-term)
//   - Distributed tracing and structured logging
//   - Metrics collection and token usage tracking
//
// All methods are safe for concurrent use. The harness ensures thread-safety
// for shared resources and coordinates access across multiple agents.
type DefaultAgentHarness struct {
	// LLM components
	slotManager llm.SlotManager
	llmRegistry llm.LLMRegistry

	// Tool and plugin registries
	toolRegistry   tool.ToolRegistry
	pluginRegistry plugin.PluginRegistry

	// Registry adapter for unified component discovery via etcd
	// Used for agent delegation operations (DelegateToAgent, ListAgents)
	registryAdapter registry.ComponentDiscovery

	// Memory and storage
	memoryStore  memory.MemoryManager
	findingStore FindingStore

	// Factory for creating child harnesses during delegation
	factory HarnessFactory

	// Context information
	missionCtx      MissionContext
	targetInfo      TargetInfo
	contextProvider MissionContextProvider

	// Observability
	tracer     trace.Tracer
	logger     *slog.Logger
	metrics    MetricsRecorder
	tokenUsage llm.TokenTracker

	// Knowledge graph integration
	graphRAGBridge      GraphRAGBridge
	graphRAGQueryBridge GraphRAGQueryBridge

	// Mission management (optional, nil = mission methods return error)
	missionClient MissionOperator
	spawnLimits   SpawnLimits

	// Event logging for structured observability
	eventLogger EventLogger

	// resolver provides dynamic proto type resolution for tool execution
	resolver protoresolver.ProtoResolver

	// checkpointAccess provides checkpoint operations (nil if checkpointing disabled)
	checkpointAccess CheckpointAccess

	// workspaceManager provides access to Git repository workspaces (nil if not configured)
	workspaceManager workspace.WorkspaceManager

	// categoryClassifier provides semantic category normalization (nil if disabled)
	categoryClassifier CategoryClassifier

	// taxonomyRegistry provides read-only access to the taxonomy registry for querying
	// available node types, relationships, and extensions in the knowledge graph.
	taxonomyRegistry sdkgraphrag.TaxonomyIntrospector
}

// Ensure DefaultAgentHarness implements AgentHarness
var _ AgentHarness = (*DefaultAgentHarness)(nil)

// Ensure DefaultAgentHarness implements agent.AgentHarness (the minimal interface)
var _ agent.AgentHarness = (*DefaultAgentHarness)(nil)

// ────────────────────────────────────────────────────────────────────────────
// LLM Access Methods
// ────────────────────────────────────────────────────────────────────────────

// Complete performs a synchronous LLM completion using the specified slot.
func (h *DefaultAgentHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.Complete")
	defer span.End()

	// Apply completion options
	options := applyOptions(opts...)

	// Create slot definition for the named slot
	slotDef := agent.NewSlotDefinition(slot, "LLM slot", true)

	// Resolve slot to provider and model
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, nil)
	if err != nil {
		h.logger.Error("failed to resolve LLM slot",
			"slot", slot,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			fmt.Sprintf("failed to resolve slot %s", slot),
			err,
		)
	}

	// Build completion request
	req := llm.CompletionRequest{
		Model:    modelInfo.Name,
		Messages: messages,
	}

	// Apply options to request
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		// Prepend system message if provided
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Emit LLM request event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventLLMRequest, "llm request", LLMRequestEventData{
			Model:        modelInfo.Name,
			MessageCount: len(req.Messages),
			Slot:         slot,
		})
	}

	// Execute completion
	resp, err := provider.Complete(ctx, req)
	if err != nil {
		h.logger.Error("LLM completion failed",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			"LLM completion failed",
			err,
		)
	}

	// Track token usage
	scope := llm.UsageScope{
		MissionID: h.missionCtx.ID,
		AgentName: h.missionCtx.CurrentAgent,
		SlotName:  slot,
	}
	tokenUsage := llm.TokenUsage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}
	err = h.tokenUsage.RecordUsage(scope, provider.Name(), resp.Model, tokenUsage)
	if err != nil {
		h.logger.Warn("failed to record token usage",
			"error", err)
		// Don't fail the request if tracking fails
	}

	// Record metrics
	h.metrics.RecordCounter("llm.completions", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
		"status":   "success",
	})
	h.metrics.RecordCounter("llm.tokens.input", int64(resp.Usage.PromptTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
	})
	h.metrics.RecordCounter("llm.tokens.output", int64(resp.Usage.CompletionTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
	})

	h.logger.Debug("LLM completion successful",
		"slot", slot,
		"provider", provider.Name(),
		"model", resp.Model,
		"input_tokens", resp.Usage.PromptTokens,
		"output_tokens", resp.Usage.CompletionTokens)

	// Emit LLM response event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventLLMResponse, "llm response", LLMResponseEventData{
			Model:            resp.Model,
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.PromptTokens + resp.Usage.CompletionTokens,
			Slot:             slot,
		})
	}

	return resp, nil
}

// CompleteWithTools performs a completion with tool-calling capabilities.
func (h *DefaultAgentHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CompleteWithTools")
	defer span.End()

	// Apply completion options
	options := applyOptions(opts...)

	// Create slot definition for the named slot
	slotDef := agent.NewSlotDefinition(slot, "LLM slot", true)

	// Resolve slot to provider and model
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, nil)
	if err != nil {
		h.logger.Error("failed to resolve LLM slot",
			"slot", slot,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			fmt.Sprintf("failed to resolve slot %s", slot),
			err,
		)
	}

	// Build completion request
	req := llm.CompletionRequest{
		Model:    modelInfo.Name,
		Messages: messages,
	}

	// Apply options to request
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Emit LLM request event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventLLMRequest, "llm request with tools", LLMRequestEventData{
			Model:        modelInfo.Name,
			MessageCount: len(req.Messages),
			Slot:         slot,
		})
	}

	// Execute completion with tools
	resp, err := provider.CompleteWithTools(ctx, req, tools)
	if err != nil {
		h.logger.Error("LLM completion with tools failed",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			"LLM completion with tools failed",
			err,
		)
	}

	// Track token usage
	scope := llm.UsageScope{
		MissionID: h.missionCtx.ID,
		AgentName: h.missionCtx.CurrentAgent,
		SlotName:  slot,
	}
	tokenUsage := llm.TokenUsage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}
	err = h.tokenUsage.RecordUsage(scope, provider.Name(), resp.Model, tokenUsage)
	if err != nil {
		h.logger.Warn("failed to record token usage",
			"error", err)
	}

	// Record metrics
	h.metrics.RecordCounter("llm.completions.with_tools", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
		"status":   "success",
	})
	h.metrics.RecordCounter("llm.tokens.input", int64(resp.Usage.PromptTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
	})
	h.metrics.RecordCounter("llm.tokens.output", int64(resp.Usage.CompletionTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
	})

	h.logger.Debug("LLM completion with tools successful",
		"slot", slot,
		"provider", provider.Name(),
		"model", resp.Model,
		"tool_calls", len(resp.Message.ToolCalls),
		"input_tokens", resp.Usage.PromptTokens,
		"output_tokens", resp.Usage.CompletionTokens)

	// Emit LLM response event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventLLMResponse, "llm response with tools", LLMResponseEventData{
			Model:            resp.Model,
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.PromptTokens + resp.Usage.CompletionTokens,
			Slot:             slot,
		})
	}

	return resp, nil
}

// Stream performs a streaming LLM completion, returning chunks as they arrive.
func (h *DefaultAgentHarness) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (<-chan llm.StreamChunk, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.Stream")
	defer span.End()

	// Apply completion options
	options := applyOptions(opts...)

	// Create slot definition for the named slot
	slotDef := agent.NewSlotDefinition(slot, "LLM slot", true)

	// Resolve slot to provider and model
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, nil)
	if err != nil {
		h.logger.Error("failed to resolve LLM slot",
			"slot", slot,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			fmt.Sprintf("failed to resolve slot %s", slot),
			err,
		)
	}

	// Build completion request
	req := llm.CompletionRequest{
		Model:    modelInfo.Name,
		Messages: messages,
	}

	// Apply options to request
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Execute streaming completion
	chunks, err := provider.Stream(ctx, req)
	if err != nil {
		h.logger.Error("LLM stream failed",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			"LLM stream failed",
			err,
		)
	}

	// Record metrics
	h.metrics.RecordCounter("llm.streams", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
		"status":   "started",
	})

	h.logger.Debug("LLM stream started",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name)

	// Wrap channel to record stream completion and aggregate response
	wrappedChan := make(chan llm.StreamChunk)
	go func() {
		defer close(wrappedChan)

		for chunk := range chunks {
			wrappedChan <- chunk

			// If this is the final chunk, record completion metrics
			// Note: Token usage tracking for streaming requires provider-specific support
			// and is typically only available after the stream completes
			if chunk.FinishReason != "" {
				// Record completion metrics
				h.metrics.RecordCounter("llm.streams.completed", 1, map[string]string{
					"slot":     slot,
					"provider": provider.Name(),
					"model":    modelInfo.Name,
				})

				h.logger.Debug("LLM stream completed",
					"slot", slot,
					"provider", provider.Name(),
					"model", modelInfo.Name,
					"finish_reason", string(chunk.FinishReason))
			}
		}
	}()

	return wrappedChan, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Tool Execution Methods
// ────────────────────────────────────────────────────────────────────────────

// getToolMetadata extracts metadata (including FileDescriptorSet) from a tool.
// Supports GRPCToolClient and RedisToolProxy.
func getToolMetadata(t tool.Tool) map[string]string {
	// Check if tool is GRPCToolClient
	if grpcClient, ok := t.(*registry.GRPCToolClient); ok {
		if md := grpcClient.Metadata(); md != nil {
			return md
		}
	}

	// Check if tool is RedisToolProxy
	if redisProxy, ok := t.(*RedisToolProxy); ok {
		return redisProxy.Metadata()
	}

	// No metadata available
	return nil
}

// CallToolProto executes a registered tool using proto message input/output.
// This is the preferred method for tools with proto schemas, providing type safety
// and schema validation at the protocol level.
func (h *DefaultAgentHarness) CallToolProto(ctx context.Context, name string, request proto.Message, response proto.Message) error {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CallToolProto")
	defer span.End()

	h.logger.Debug("calling tool with proto messages",
		"tool", name,
		"input_type", string(request.ProtoReflect().Descriptor().FullName()),
		"output_type", string(response.ProtoReflect().Descriptor().FullName()))

	// Try to get tool from local registry first
	t, err := h.toolRegistry.Get(name)
	if err != nil {
		// Tool not found locally - try to discover via registry adapter
		if h.registryAdapter != nil {
			h.logger.Debug("tool not found locally, attempting remote discovery",
				"tool", name)

			remoteTool, discErr := h.registryAdapter.DiscoverTool(ctx, name)
			if discErr != nil {
				h.logger.Error("tool not found (local or remote)",
					"tool", name,
					"local_error", err,
					"discovery_error", discErr)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("tool not found: %s (local: %v, remote: %v)", name, err, discErr),
					err,
				)
			}

			// Use discovered remote tool
			t = remoteTool
			h.logger.Debug("discovered remote tool",
				"tool", name,
				"version", remoteTool.Version())
		} else {
			// No registry adapter, can't discover remotely
			h.logger.Error("tool not found locally and no registry adapter available",
				"tool", name,
				"error", err)
			return types.WrapError(
				ErrHarnessToolExecutionFailed,
				fmt.Sprintf("tool not found: %s", name),
				err,
			)
		}
	}

	// Check if tool supports proto execution by type assertion
	// The SDK tool.Tool interface has proto methods, but internal tool.Tool does not
	type protoTool interface {
		InputMessageType() string
		OutputMessageType() string
		ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error)
	}

	protoT, ok := t.(protoTool)
	if !ok {
		// Tool doesn't support proto - this is an error
		h.logger.Error("tool does not support proto execution",
			"tool", name)
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool %s does not support proto execution (use CallTool instead)", name),
			nil,
		)
	}

	inputType := protoT.InputMessageType()
	outputType := protoT.OutputMessageType()

	if inputType == "" || outputType == "" {
		// Tool doesn't support proto - this is an error
		h.logger.Error("tool does not support proto execution",
			"tool", name,
			"input_type", inputType,
			"output_type", outputType)
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool %s does not support proto execution (use CallTool instead)", name),
			nil,
		)
	}

	// Verify message types match
	expectedInputType := string(request.ProtoReflect().Descriptor().FullName())
	expectedOutputType := string(response.ProtoReflect().Descriptor().FullName())

	// Note: inputType and outputType from tool might be in format "package.Message"
	// while proto reflection gives "package.Message" - they should match
	//
	// However, agents using the SDK structpb fallback will send google.protobuf.Struct
	// when the tool expects a specific proto type. In this case, we need to convert
	// the Struct to the tool's expected type using the ProtoResolver.
	actualRequest := request
	if inputType != expectedInputType {
		// Check if the request is a structpb.Struct that needs conversion
		if structInput, ok := request.(*structpb.Struct); ok && expectedInputType == "google.protobuf.Struct" {
			h.logger.Debug("converting structpb.Struct input to typed message",
				"tool", name,
				"target_type", inputType)

			// Get tool metadata for resolver
			toolMetadata := getToolMetadata(t)
			if toolMetadata == nil {
				h.logger.Error("tool has no metadata for input conversion",
					"tool", name,
					"expected", inputType)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("cannot convert input: tool %s has no metadata", name),
					nil,
				)
			}

			// Convert Struct to JSON
			marshaler := protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: false,
			}
			jsonBytes, err := marshaler.Marshal(structInput)
			if err != nil {
				h.logger.Error("failed to marshal struct input",
					"tool", name,
					"error", err)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("failed to convert input: %v", err),
					err,
				)
			}

			// Log the JSON being converted (INFO level for debugging)
			h.logger.Info("converting structpb.Struct to typed message via resolver",
				"tool", name,
				"target_type", inputType,
				"json", string(jsonBytes))

			// Use resolver to unmarshal JSON into typed proto message
			dynamicMsg, err := h.resolver.UnmarshalJSON(ctx, inputType, jsonBytes, toolMetadata)
			if err != nil {
				h.logger.Error("failed to unmarshal input to typed message via resolver",
					"tool", name,
					"target_type", inputType,
					"json", string(jsonBytes),
					"error", err)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("failed to convert input to %s: %v", inputType, err),
					err,
				)
			}

			h.logger.Debug("successfully converted structpb.Struct to typed message via resolver",
				"tool", name,
				"target_type", inputType)

			// Use the converted message
			actualRequest = dynamicMsg
		} else {
			h.logger.Error("input message type mismatch",
				"tool", name,
				"expected", inputType,
				"provided", expectedInputType)
			return types.WrapError(
				ErrHarnessToolExecutionFailed,
				fmt.Sprintf("input message type mismatch: tool expects %s, got %s", inputType, expectedInputType),
				nil,
			)
		}
	}

	// Determine if tool is local or remote for logging
	isRemote := false
	if h.registryAdapter != nil {
		// Check if tool implements registry gRPC client (remote)
		if _, ok := t.(*registry.GRPCToolClient); ok {
			isRemote = true
		}
	}

	// Emit tool call event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventToolCall, "tool call", ToolCallEventData{
			ToolName: name,
		})
	}

	// Execute tool with proto messages (using actualRequest which may be converted)
	outputMsg, err := protoT.ExecuteProto(ctx, actualRequest)

	if err != nil {
		h.logger.Error("tool execution failed",
			"tool", name,
			"remote", isRemote,
			"error", err)

		// Record failure metrics
		h.metrics.RecordCounter("tools.executions", 1, map[string]string{
			"tool":   name,
			"remote": fmt.Sprintf("%t", isRemote),
			"status": "failed",
			"mode":   "proto",
		})

		// Emit tool result event (failure)
		if h.eventLogger != nil {
			h.eventLogger.Event(ctx, EventToolResult, "tool result", ToolResultEventData{
				ToolName: name,
				Success:  false,
				Error:    err.Error(),
			})
		}

		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool execution failed: %s", name),
			err,
		)
	}

	// Verify output type matches - or convert if necessary
	actualOutputType := string(outputMsg.ProtoReflect().Descriptor().FullName())
	if actualOutputType != expectedOutputType {
		// Check if the output is a structpb.Struct that needs conversion to typed message
		// This happens when tools return generic JSON via subprocess execution
		if structOutput, ok := outputMsg.(*structpb.Struct); ok && actualOutputType == "google.protobuf.Struct" {
			h.logger.Debug("converting structpb.Struct output to typed message",
				"tool", name,
				"target_type", expectedOutputType)

			// Convert Struct to JSON, then unmarshal into the response message
			marshaler := protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: false,
			}
			jsonBytes, err := marshaler.Marshal(structOutput)
			if err != nil {
				h.logger.Error("failed to marshal struct output",
					"tool", name,
					"error", err)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("failed to convert tool output: %v", err),
					err,
				)
			}

			// Unmarshal JSON into the typed response message
			unmarshaler := protojson.UnmarshalOptions{
				DiscardUnknown: true,
			}
			if err := unmarshaler.Unmarshal(jsonBytes, response); err != nil {
				h.logger.Error("failed to unmarshal output to typed message",
					"tool", name,
					"target_type", expectedOutputType,
					"error", err)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("failed to convert tool output to %s: %v", expectedOutputType, err),
					err,
				)
			}

			// Skip the normal merge since we've directly populated the response
			goto metricsSuccess
		}

		h.logger.Error("output message type mismatch",
			"tool", name,
			"expected", expectedOutputType,
			"actual", actualOutputType)
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("output message type mismatch: expected %s, got %s", expectedOutputType, actualOutputType),
			nil,
		)
	}

	// Merge the output message into the response parameter
	proto.Merge(response, outputMsg)

metricsSuccess:

	// Record success metrics
	h.metrics.RecordCounter("tools.executions", 1, map[string]string{
		"tool":   name,
		"remote": fmt.Sprintf("%t", isRemote),
		"status": "success",
		"mode":   "proto",
	})

	h.logger.Debug("tool execution successful with proto",
		"tool", name,
		"remote", isRemote)

	// Emit tool result event (success)
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventToolResult, "tool result", ToolResultEventData{
			ToolName: name,
			Success:  true,
		})
	}

	return nil
}

// ListTools returns descriptors for all registered tools.
func (h *DefaultAgentHarness) ListTools() []ToolDescriptor {
	// Get local tools from registry
	localToolDescriptors := h.toolRegistry.List()

	// Convert from tool.ToolDescriptor to harness.ToolDescriptor
	descriptors := make([]ToolDescriptor, 0, len(localToolDescriptors))
	for _, t := range localToolDescriptors {
		descriptors = append(descriptors, ToolDescriptor{
			Name:            t.Name,
			Description:     t.Description,
			Version:         t.Version,
			Tags:            t.Tags,
			InputProtoType:  t.InputMessageType,
			OutputProtoType: t.OutputMessageType,
			// InputSchema and OutputSchema are legacy fields, left empty for now
			// They can be populated by calling GetToolDescriptor() which fetches from the tool
		})
	}

	// If registry adapter is available, add remote tools
	if h.registryAdapter != nil {
		ctx := context.Background()
		remoteTools, err := h.registryAdapter.ListTools(ctx)
		if err != nil {
			h.logger.Warn("failed to list remote tools",
				"error", err)
			// Continue with just local tools
		} else {
			// Add remote tools to the list
			// Use a map to deduplicate by name (local takes precedence)
			localNames := make(map[string]struct{})
			for _, desc := range descriptors {
				localNames[desc.Name] = struct{}{}
			}

			// Add remote tools that don't exist locally
			for _, remoteTool := range remoteTools {
				if _, exists := localNames[remoteTool.Name]; !exists {
					descriptors = append(descriptors, ToolDescriptor{
						Name:        remoteTool.Name,
						Description: remoteTool.Description,
						Version:     remoteTool.Version,
						Tags:        []string{}, // Remote tool info doesn't include tags
						// Note: InputSchema and OutputSchema would require fetching descriptor
						// from each tool, which is expensive. Leave empty for now.
					})
				}
			}
		}
	}

	return descriptors
}

// GetToolDescriptor returns the descriptor for a specific tool by name.
// This retrieves tool metadata including output schema with taxonomy mappings
// for entity extraction.
func (h *DefaultAgentHarness) GetToolDescriptor(ctx context.Context, name string) (*ToolDescriptor, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GetToolDescriptor")
	defer span.End()

	// Try to get tool from local registry first
	t, err := h.toolRegistry.Get(name)
	if err == nil {
		// Use FromTool helper which handles both proto and legacy tools
		desc := FromTool(t)
		return &desc, nil
	}

	// Tool not found locally - try to discover via registry adapter
	if h.registryAdapter != nil {
		h.logger.Debug("tool not found locally, attempting remote discovery for descriptor",
			"tool", name)

		remoteTool, discErr := h.registryAdapter.DiscoverTool(ctx, name)
		if discErr != nil {
			h.logger.Error("tool not found (local or remote)",
				"tool", name,
				"local_error", err,
				"discovery_error", discErr)
			return nil, types.WrapError(
				ErrHarnessToolExecutionFailed,
				fmt.Sprintf("tool not found: %s", name),
				err,
			)
		}

		// Build descriptor from discovered remote tool using FromTool helper
		desc := FromTool(remoteTool)
		return &desc, nil
	}

	// No registry adapter available
	return nil, types.WrapError(
		ErrHarnessToolExecutionFailed,
		fmt.Sprintf("tool not found: %s", name),
		err,
	)
}

// GetToolCapabilities retrieves runtime capabilities for a specific registered tool.
// Returns nil if the tool doesn't implement CapabilityProvider.
func (h *DefaultAgentHarness) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GetToolCapabilities")
	defer span.End()

	h.logger.Debug("retrieving capabilities for tool", "tool", toolName)

	// Try to get tool from local registry first
	t, err := h.toolRegistry.Get(toolName)
	if err != nil {
		// Tool not found locally - try to discover via registry adapter
		if h.registryAdapter != nil {
			h.logger.Debug("tool not found locally, attempting remote discovery for capabilities",
				"tool", toolName)

			remoteTool, discErr := h.registryAdapter.DiscoverTool(ctx, toolName)
			if discErr != nil {
				h.logger.Error("tool not found (local or remote)",
					"tool", toolName,
					"local_error", err,
					"discovery_error", discErr)
				return nil, types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("tool not found: %s", toolName),
					err,
				)
			}

			// Use discovered remote tool
			t = remoteTool
		} else {
			// No registry adapter, can't discover remotely
			h.logger.Error("tool not found locally and no registry adapter available",
				"tool", toolName,
				"error", err)
			return nil, types.WrapError(
				ErrHarnessToolExecutionFailed,
				fmt.Sprintf("tool not found: %s", toolName),
				err,
			)
		}
	}

	// Check if tool implements CapabilityProvider
	type capabilityProvider interface {
		Capabilities(ctx context.Context) *sdktypes.Capabilities
	}

	if provider, ok := t.(capabilityProvider); ok {
		caps := provider.Capabilities(ctx)
		if caps != nil {
			h.logger.Debug("retrieved capabilities for tool",
				"tool", toolName,
				"has_root", caps.HasRoot,
				"has_sudo", caps.HasSudo,
				"can_raw_socket", caps.CanRawSocket,
				"blocked_args_count", len(caps.BlockedArgs))
			return caps, nil
		}
	}

	// Tool doesn't implement CapabilityProvider or returned nil
	h.logger.Debug("tool does not provide capabilities",
		"tool", toolName)
	return nil, nil
}

// GetAllToolCapabilities returns capabilities for all registered tools.
// Tools that don't implement CapabilityProvider are excluded from the result.
func (h *DefaultAgentHarness) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GetAllToolCapabilities")
	defer span.End()

	h.logger.Debug("retrieving capabilities for all tools")

	// Get all tool descriptors from local registry
	toolDescriptors := h.toolRegistry.List()

	result := make(map[string]*sdktypes.Capabilities)

	// Query each tool for capabilities
	for _, desc := range toolDescriptors {
		// Get the tool instance
		t, err := h.toolRegistry.Get(desc.Name)
		if err != nil {
			h.logger.Warn("failed to get tool from registry",
				"tool", desc.Name,
				"error", err)
			continue
		}

		// Check if tool implements CapabilityProvider
		// Use SDK helper to safely check and retrieve capabilities
		type capabilityProvider interface {
			Capabilities(ctx context.Context) *sdktypes.Capabilities
		}

		if provider, ok := t.(capabilityProvider); ok {
			caps := provider.Capabilities(ctx)
			if caps != nil {
				result[desc.Name] = caps
				h.logger.Debug("retrieved capabilities for tool",
					"tool", desc.Name,
					"has_root", caps.HasRoot,
					"has_sudo", caps.HasSudo,
					"can_raw_socket", caps.CanRawSocket,
					"blocked_args_count", len(caps.BlockedArgs))
			}
		}
	}

	// If registry adapter is available, query remote tools as well
	if h.registryAdapter != nil {
		remoteTools, err := h.registryAdapter.ListTools(ctx)
		if err != nil {
			h.logger.Warn("failed to list remote tools for capabilities",
				"error", err)
			// Continue with just local tools
		} else {
			// Query remote tools for capabilities
			for _, remoteTool := range remoteTools {
				// Skip if already have local tool with same name
				if _, exists := result[remoteTool.Name]; exists {
					continue
				}

				// Discover the remote tool
				t, err := h.registryAdapter.DiscoverTool(ctx, remoteTool.Name)
				if err != nil {
					h.logger.Warn("failed to discover remote tool",
						"tool", remoteTool.Name,
						"error", err)
					continue
				}

				// Check if remote tool implements CapabilityProvider
				type capabilityProvider interface {
					Capabilities(ctx context.Context) *sdktypes.Capabilities
				}

				if provider, ok := t.(capabilityProvider); ok {
					caps := provider.Capabilities(ctx)
					if caps != nil {
						result[remoteTool.Name] = caps
						h.logger.Debug("retrieved capabilities for remote tool",
							"tool", remoteTool.Name,
							"has_root", caps.HasRoot,
							"has_sudo", caps.HasSudo,
							"can_raw_socket", caps.CanRawSocket,
							"blocked_args_count", len(caps.BlockedArgs))
					}
				}
			}
		}
	}

	h.logger.Info("retrieved tool capabilities",
		"tools_with_capabilities", len(result))

	return result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Plugin Access Methods
// ────────────────────────────────────────────────────────────────────────────

// QueryPlugin calls a method on a registered plugin with the given parameters.
func (h *DefaultAgentHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.QueryPlugin")
	defer span.End()

	h.logger.Debug("querying plugin",
		"plugin", name,
		"method", method,
		"params", params)

	// Try to get plugin from local registry first
	p, err := h.pluginRegistry.Get(name)
	if err != nil {
		// Plugin not found locally - try to discover via registry adapter
		if h.registryAdapter != nil {
			h.logger.Debug("plugin not found locally, attempting remote discovery",
				"plugin", name)

			remotePlugin, discErr := h.registryAdapter.DiscoverPlugin(ctx, name)
			if discErr != nil {
				h.logger.Error("plugin not found (local or remote)",
					"plugin", name,
					"local_error", err,
					"discovery_error", discErr)
				return nil, types.WrapError(
					ErrHarnessPluginNotFound,
					fmt.Sprintf("plugin not found: %s (local: %v, remote: %v)", name, err, discErr),
					err,
				)
			}

			// Use discovered remote plugin
			p = remotePlugin
			h.logger.Debug("discovered remote plugin",
				"plugin", name,
				"version", remotePlugin.Version())
		} else {
			// No registry adapter, can't discover remotely
			h.logger.Error("plugin not found locally and no registry adapter available",
				"plugin", name,
				"error", err)
			return nil, types.WrapError(
				ErrHarnessPluginNotFound,
				fmt.Sprintf("plugin not found: %s", name),
				err,
			)
		}
	}

	// Determine if plugin is local or remote for logging
	isRemote := false
	if h.registryAdapter != nil {
		// Check if plugin implements registry gRPC client (remote)
		if _, ok := p.(*registry.GRPCPluginClient); ok {
			isRemote = true
		}
	}

	// Query plugin
	result, err := p.Query(ctx, method, params)
	if err != nil {
		h.logger.Error("plugin query failed",
			"plugin", name,
			"method", method,
			"remote", isRemote,
			"error", err)

		// Record failure metrics
		h.metrics.RecordCounter("plugins.queries", 1, map[string]string{
			"plugin": name,
			"method": method,
			"remote": fmt.Sprintf("%t", isRemote),
			"status": "failed",
		})

		return nil, types.WrapError(
			ErrHarnessPluginMethodNotFound,
			fmt.Sprintf("plugin query failed: %s.%s", name, method),
			err,
		)
	}

	// Record success metrics
	h.metrics.RecordCounter("plugins.queries", 1, map[string]string{
		"plugin": name,
		"method": method,
		"remote": fmt.Sprintf("%t", isRemote),
		"status": "success",
	})

	h.logger.Debug("plugin query successful",
		"plugin", name,
		"method", method,
		"remote", isRemote)

	return result, nil
}

// ListPlugins returns descriptors for all registered plugins.
func (h *DefaultAgentHarness) ListPlugins() []PluginDescriptor {
	// Get local plugins from registry
	localPluginDescriptors := h.pluginRegistry.List()

	// Convert from plugin.PluginDescriptor to harness.PluginDescriptor
	descriptors := make([]PluginDescriptor, 0, len(localPluginDescriptors))
	for _, p := range localPluginDescriptors {
		descriptors = append(descriptors, PluginDescriptor{
			Name:       p.Name,
			Version:    p.Version,
			Methods:    p.Methods,
			IsExternal: p.IsExternal,
			Status:     p.Status,
		})
	}

	// If registry adapter is available, add remote plugins
	if h.registryAdapter != nil {
		ctx := context.Background()
		remotePlugins, err := h.registryAdapter.ListPlugins(ctx)
		if err != nil {
			h.logger.Warn("failed to list remote plugins",
				"error", err)
			// Continue with just local plugins
		} else {
			// Add remote plugins to the list
			// Use a map to deduplicate by name (local takes precedence)
			localNames := make(map[string]struct{})
			for _, desc := range descriptors {
				localNames[desc.Name] = struct{}{}
			}

			// Add remote plugins that don't exist locally
			for _, remotePlugin := range remotePlugins {
				if _, exists := localNames[remotePlugin.Name]; !exists {
					descriptors = append(descriptors, PluginDescriptor{
						Name:       remotePlugin.Name,
						Version:    remotePlugin.Version,
						Methods:    []plugin.MethodDescriptor{}, // Would require fetching from plugin
						IsExternal: true,                        // All remote plugins are external
						Status:     plugin.PluginStatusUninitialized,
					})
				}
			}
		}
	}

	return descriptors
}

// ────────────────────────────────────────────────────────────────────────────
// Sub-Agent Delegation Methods
// ────────────────────────────────────────────────────────────────────────────

// DelegateToAgent delegates a task to another registered agent for execution.
func (h *DefaultAgentHarness) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.DelegateToAgent")
	defer span.End()

	h.logger.Info("delegating to agent",
		"agent", name,
		"task_id", task.ID.String(),
		"task_name", task.Name)

	// Update mission context for child agent
	childMissionCtx := h.missionCtx
	childMissionCtx.CurrentAgent = name

	// Create child harness for the sub-agent
	childHarness, err := h.factory(ctx, childMissionCtx, h.targetInfo)
	if err != nil {
		h.logger.Error("failed to create child harness",
			"agent", name,
			"error", err)
		return agent.Result{}, types.WrapError(
			ErrHarnessDelegationFailed,
			"failed to create child harness",
			err,
		)
	}

	// Convert harness.AgentHarness to agent.AgentHarness
	// DefaultAgentHarness implements both interfaces, so this is a type assertion
	agentHarness, ok := childHarness.(agent.AgentHarness)
	if !ok {
		h.logger.Error("child harness does not implement agent.AgentHarness",
			"agent", name)
		return agent.Result{}, types.NewError(
			ErrHarnessDelegationFailed,
			"child harness does not implement agent.AgentHarness",
		)
	}

	// Use registry adapter for delegation
	if h.registryAdapter == nil {
		h.logger.Error("no registry adapter available for delegation", "agent", name)
		return agent.Result{}, types.NewError(
			ErrHarnessDelegationFailed,
			"registry adapter not configured for agent delegation",
		)
	}

	h.logger.Debug("using registry adapter for delegation", "agent", name)
	result, err := h.registryAdapter.DelegateToAgent(ctx, name, task, agentHarness)

	if err != nil {
		h.logger.Error("agent execution failed",
			"agent", name,
			"task_id", task.ID.String(),
			"error", err)

		// Record failure metrics
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent":  name,
			"status": "failed",
		})

		return result, types.WrapError(
			ErrHarnessDelegationFailed,
			fmt.Sprintf("agent execution failed: %s", name),
			err,
		)
	}

	// Submit findings from sub-agent to our finding store
	for _, finding := range result.Findings {
		err := h.SubmitFinding(ctx, finding)
		if err != nil {
			h.logger.Warn("failed to submit sub-agent finding",
				"agent", name,
				"finding", finding.Title,
				"error", err)
		}
	}

	// Record success metrics
	h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
		"agent":  name,
		"status": "success",
	})
	h.metrics.RecordCounter("agents.findings_from_delegation", int64(len(result.Findings)), map[string]string{
		"agent": name,
	})

	h.logger.Info("agent execution completed",
		"agent", name,
		"task_id", task.ID.String(),
		"status", result.Status,
		"findings_count", len(result.Findings))

	return result, nil
}

// ListAgents returns descriptors for all registered agents.
func (h *DefaultAgentHarness) ListAgents() []AgentDescriptor {
	// Use registry adapter for listing agents
	if h.registryAdapter == nil {
		h.logger.Warn("no registry adapter available for listing agents")
		return []AgentDescriptor{}
	}

	h.logger.Debug("using registry adapter for listing agents")

	// Get agents from registry adapter
	agentInfos, err := h.registryAdapter.ListAgents(context.Background())
	if err != nil {
		h.logger.Error("failed to list agents from registry adapter", "error", err)
		// Return empty list on error rather than panicking
		return []AgentDescriptor{}
	}

	// Convert from registry.AgentInfo to harness.AgentDescriptor
	descriptors := make([]AgentDescriptor, len(agentInfos))
	for i, info := range agentInfos {
		descriptors[i] = AgentDescriptor{
			Name:         info.Name,
			Version:      info.Version,
			Description:  info.Description,
			Capabilities: info.Capabilities,
			Slots:        []agent.SlotDefinition{}, // AgentInfo doesn't include slots
			IsExternal:   true,                     // All registry adapter agents are external
		}
	}
	return descriptors
}

// ────────────────────────────────────────────────────────────────────────────
// Findings Management Methods
// ────────────────────────────────────────────────────────────────────────────

// SubmitFinding stores a security finding for the current mission.
func (h *DefaultAgentHarness) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.SubmitFinding")
	defer span.End()

	// Store original category before classification
	originalCategory := finding.Category

	// Apply category classification if classifier is configured
	if h.categoryClassifier != nil {
		normalizedCategory, err := h.categoryClassifier.Classify(ctx, finding.Category, finding.Description)
		if err != nil {
			// Graceful degradation: log warning and continue with original category
			h.logger.Warn("category classification failed, using original category",
				"original_category", finding.Category,
				"error", err)
		} else {
			// Update finding category with normalized value
			finding.Category = normalizedCategory

			// Add metadata about classification
			if finding.Metadata == nil {
				finding.Metadata = make(map[string]any)
			}
			finding.Metadata["original_category"] = originalCategory

			// Log normalization if category changed
			if normalizedCategory != originalCategory {
				h.logger.Info("normalized finding category",
					"original_category", originalCategory,
					"normalized_category", normalizedCategory,
					"finding_id", finding.ID.String())
			}
		}
	}

	h.logger.Info("submitting finding",
		"finding_id", finding.ID.String(),
		"title", finding.Title,
		"severity", finding.Severity,
		"confidence", finding.Confidence,
		"category", finding.Category)

	// Store finding
	err := h.findingStore.Store(ctx, h.missionCtx.ID, finding)
	if err != nil {
		h.logger.Error("failed to submit finding",
			"finding_id", finding.ID.String(),
			"error", err)

		// Record failure metrics
		h.metrics.RecordCounter("findings.submissions", 1, map[string]string{
			"severity": string(finding.Severity),
			"status":   "failed",
		})

		return types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to submit finding",
			err,
		)
	}

	// Record success metrics
	h.metrics.RecordCounter("findings.submissions", 1, map[string]string{
		"severity": string(finding.Severity),
		"status":   "success",
	})
	h.metrics.RecordCounter("findings.by_severity", 1, map[string]string{
		"severity": string(finding.Severity),
	})

	h.logger.Debug("finding submitted successfully",
		"finding_id", finding.ID.String(),
		"title", finding.Title)

	// Emit finding event
	if h.eventLogger != nil {
		targetAsset := ""
		if finding.TargetID != nil {
			targetAsset = finding.TargetID.String()
		}
		h.eventLogger.Event(ctx, EventFinding, "finding submitted", FindingEventData{
			Severity:    string(finding.Severity),
			Title:       finding.Title,
			Confidence:  fmt.Sprintf("%.2f", finding.Confidence),
			TargetAsset: targetAsset,
		})
	}

	// Async store to GraphRAG knowledge graph (non-blocking)
	// This happens after local store succeeds to ensure findings are never lost
	// GraphRAG is a required core component - always store
	var targetID *types.ID
	if h.targetInfo.ID != "" {
		id, err := types.ParseID(string(h.targetInfo.ID))
		if err == nil {
			targetID = &id
		}
	}
	h.graphRAGBridge.StoreAsync(ctx, finding, h.missionCtx.ID, targetID)

	return nil
}

// GetFindings retrieves findings for the current mission, optionally filtered.
func (h *DefaultAgentHarness) GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GetFindings")
	defer span.End()

	h.logger.Debug("retrieving findings",
		"mission_id", h.missionCtx.ID.String())

	// Get findings from store
	findings, err := h.findingStore.Get(ctx, h.missionCtx.ID, filter)
	if err != nil {
		h.logger.Error("failed to get findings",
			"mission_id", h.missionCtx.ID.String(),
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to get findings",
			err,
		)
	}

	h.logger.Debug("findings retrieved",
		"mission_id", h.missionCtx.ID.String(),
		"count", len(findings))

	return findings, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Memory Access Methods
// ────────────────────────────────────────────────────────────────────────────

// Memory provides access to the unified memory store.
func (h *DefaultAgentHarness) Memory() memory.MemoryStore {
	return h.memoryStore
}

// Checkpoint provides access to the checkpointing system for state management.
// Returns a no-op implementation if checkpointing is not configured.
func (h *DefaultAgentHarness) Checkpoint() CheckpointAccess {
	if h.checkpointAccess == nil {
		// Return a disabled checkpoint access implementation
		return NewHarnessCheckpointMethods(nil, "", "", 0)
	}
	return h.checkpointAccess
}

// ────────────────────────────────────────────────────────────────────────────
// Workspace Access Methods
// ────────────────────────────────────────────────────────────────────────────

// Workspace returns the primary workspace for single-repository missions.
// This is a convenience method that returns the first workspace defined in the mission configuration.
// Returns nil if no workspaces are configured for this mission.
//
// Example:
//
//	ws := harness.Workspace()
//	if ws == nil {
//	    return errors.New("no workspace configured")
//	}
//	content, err := ws.ReadFile(ctx, "main.go")
func (h *DefaultAgentHarness) Workspace() workspace.Workspace {
	ctx, span := h.tracer.Start(context.Background(), "harness.Workspace")
	defer span.End()
	_ = ctx // Context used by tracer

	if h.workspaceManager == nil {
		h.logger.Debug("workspace manager not configured")
		return nil
	}

	ws := h.workspaceManager.Primary()
	if ws != nil {
		h.logger.Debug("returning primary workspace", "name", ws.Name(), "path", ws.Path())
	}
	return ws
}

// Workspaces returns all workspaces keyed by repository name.
// For multi-repository missions, use this to access specific workspaces by name.
// Returns an empty map if no workspaces are configured.
//
// Example:
//
//	workspaces := harness.Workspaces()
//	if ws, ok := workspaces["backend"]; ok {
//	    editor := ws.Editor()
//	    // Perform editing operations
//	}
func (h *DefaultAgentHarness) Workspaces() map[string]workspace.Workspace {
	ctx, span := h.tracer.Start(context.Background(), "harness.Workspaces")
	defer span.End()
	_ = ctx // Context used by tracer

	if h.workspaceManager == nil {
		h.logger.Debug("workspace manager not configured")
		return make(map[string]workspace.Workspace)
	}

	workspaces := h.workspaceManager.All()
	h.logger.Debug("returning all workspaces", "count", len(workspaces))
	return workspaces
}

// ────────────────────────────────────────────────────────────────────────────
// Context Access Methods
// ────────────────────────────────────────────────────────────────────────────

// Mission returns the current mission context.
func (h *DefaultAgentHarness) Mission() MissionContext {
	return h.missionCtx
}

// Target returns information about the current target.
func (h *DefaultAgentHarness) Target() TargetInfo {
	return h.targetInfo
}

// MissionID returns the mission ID for the current execution context.
func (h *DefaultAgentHarness) MissionID() types.ID {
	return h.missionCtx.ID
}

// ────────────────────────────────────────────────────────────────────────────
// Observability Methods
// ────────────────────────────────────────────────────────────────────────────

// Tracer returns the OpenTelemetry tracer for distributed tracing.
func (h *DefaultAgentHarness) Tracer() trace.Tracer {
	return h.tracer
}

// Logger returns the structured logger for this agent execution.
func (h *DefaultAgentHarness) Logger() *slog.Logger {
	return h.logger
}

// Metrics returns the metrics recorder for operational metrics.
func (h *DefaultAgentHarness) Metrics() MetricsRecorder {
	return h.metrics
}

// TokenUsage returns the token usage tracker for the current execution.
func (h *DefaultAgentHarness) TokenUsage() *llm.TokenTracker {
	return &h.tokenUsage
}

// ────────────────────────────────────────────────────────────────────────────
// Minimal agent.AgentHarness Interface Implementation
// ────────────────────────────────────────────────────────────────────────────

// Log implements the minimal agent.AgentHarness interface method.
// It writes a structured log message using the harness logger.
func (h *DefaultAgentHarness) Log(level, message string, fields map[string]any) {
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, k, v)
	}

	switch level {
	case "debug":
		h.logger.Debug(message, attrs...)
	case "info":
		h.logger.Info(message, attrs...)
	case "warn":
		h.logger.Warn(message, attrs...)
	case "error":
		h.logger.Error(message, attrs...)
	default:
		h.logger.Info(message, attrs...)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// GraphRAG Query Methods
// ────────────────────────────────────────────────────────────────────────────

// QueryNodes performs a query against the knowledge graph using proto messages.
// This is the preferred method for GraphRAG queries with explicit proto schemas.
func (h *DefaultAgentHarness) QueryNodes(ctx context.Context, query *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.QueryNodes")
	defer span.End()

	h.logger.Debug("querying graph nodes (proto)",
		"query_text", query.Text,
		"top_k", query.TopK,
		"node_types_count", len(query.NodeTypes))

	// Convert proto query to SDK Query
	sdkQuery, err := protoQueryToSDK(query)
	if err != nil {
		h.logger.Error("failed to convert proto query to SDK query",
			"error", err)
		return nil, fmt.Errorf("failed to convert proto query: %w", err)
	}

	// Delegate to existing QueryGraphRAG implementation
	results, err := h.QueryGraphRAG(ctx, *sdkQuery)
	if err != nil {
		h.logger.Error("query graph nodes (proto) failed",
			"error", err)
		return nil, err
	}

	// Convert SDK results to proto results
	protoResults := make([]*graphragpb.QueryResult, len(results))
	for i, result := range results {
		protoResult, err := sdkResultToProto(result)
		if err != nil {
			h.logger.Error("failed to convert SDK result to proto",
				"index", i,
				"error", err)
			continue
		}
		protoResults[i] = protoResult
	}

	h.logger.Debug("query graph nodes (proto) completed",
		"results_count", len(protoResults))

	return protoResults, nil
}

// protoQueryToSDK converts a proto GraphQuery to SDK Query
func protoQueryToSDK(protoQuery *graphragpb.GraphQuery) (*sdkgraphrag.Query, error) {
	if protoQuery == nil {
		return nil, fmt.Errorf("proto query is nil")
	}

	// NodeTypes is now a repeated string field - just copy directly
	nodeTypes := make([]string, len(protoQuery.NodeTypes))
	copy(nodeTypes, protoQuery.NodeTypes)

	query := &sdkgraphrag.Query{
		Text:      protoQuery.Text,
		TopK:      int(protoQuery.TopK),
		MinScore:  protoQuery.MinScore,
		NodeTypes: nodeTypes,
		// Default values for fields not in proto
		MaxHops:      3,
		VectorWeight: 0.6,
		GraphWeight:  0.4,
	}

	return query, nil
}

// sdkResultToProto converts an SDK Result to proto QueryResult
func sdkResultToProto(sdkResult sdkgraphrag.Result) (*graphragpb.QueryResult, error) {
	// Convert SDK node to proto node
	protoNode, err := sdkNodeToProto(sdkResult.Node)
	if err != nil {
		return nil, fmt.Errorf("failed to convert node: %w", err)
	}

	result := &graphragpb.QueryResult{
		Node:  protoNode,
		Score: sdkResult.Score,
	}

	return result, nil
}

// sdkNodeToProto converts an SDK GraphNode to proto GraphNode
func sdkNodeToProto(sdkNode sdkgraphrag.GraphNode) (*graphragpb.GraphNode, error) {
	// Type is now a string field
	nodeType := sdkNode.Type

	// Convert map[string]any to map[string]*graphragpb.Value
	properties := make(map[string]*graphragpb.Value)
	for k, v := range sdkNode.Properties {
		properties[k] = anyToGraphragpbValue(v)
	}

	node := &graphragpb.GraphNode{
		Id:         sdkNode.ID,
		Type:       nodeType,
		Content:    sdkNode.Content,
		Properties: properties,
	}

	return node, nil
}

// anyToGraphragpbValue converts any to a graphragpb.Value.
func anyToGraphragpbValue(v any) *graphragpb.Value {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return &graphragpb.Value{Kind: &graphragpb.Value_StringValue{StringValue: val}}
	case int:
		return &graphragpb.Value{Kind: &graphragpb.Value_IntValue{IntValue: int64(val)}}
	case int32:
		return &graphragpb.Value{Kind: &graphragpb.Value_IntValue{IntValue: int64(val)}}
	case int64:
		return &graphragpb.Value{Kind: &graphragpb.Value_IntValue{IntValue: val}}
	case float32:
		return &graphragpb.Value{Kind: &graphragpb.Value_DoubleValue{DoubleValue: float64(val)}}
	case float64:
		return &graphragpb.Value{Kind: &graphragpb.Value_DoubleValue{DoubleValue: val}}
	case bool:
		return &graphragpb.Value{Kind: &graphragpb.Value_BoolValue{BoolValue: val}}
	case []byte:
		return &graphragpb.Value{Kind: &graphragpb.Value_BytesValue{BytesValue: val}}
	default:
		return &graphragpb.Value{Kind: &graphragpb.Value_StringValue{StringValue: fmt.Sprintf("%v", val)}}
	}
}

// QueryGraphRAG performs a semantic or hybrid query against the knowledge graph.
// Automatically sets MissionName from harness context if not already set.
func (h *DefaultAgentHarness) QueryGraphRAG(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.QueryGraphRAG")
	defer span.End()

	// Auto-fill MissionName from harness context if not set
	// This is required for mission-scoped queries (same_mission scope)
	if query.MissionName == "" {
		query.MissionName = h.Mission().Name
	}

	h.logger.Debug("querying graphrag",
		"query_text", query.Text,
		"top_k", query.TopK,
		"max_hops", query.MaxHops,
		"mission_name", query.MissionName)

	// Delegate to query bridge
	results, err := h.graphRAGQueryBridge.Query(ctx, query)
	if err != nil {
		h.logger.Error("graphrag query failed",
			"query_text", query.Text,
			"error", err)
		return nil, err
	}

	h.logger.Debug("graphrag query completed",
		"results_count", len(results))

	return results, nil
}

// FindSimilarAttacks searches for attack patterns semantically similar to the given content.
func (h *DefaultAgentHarness) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]sdkgraphrag.AttackPattern, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.FindSimilarAttacks")
	defer span.End()

	h.logger.Debug("finding similar attacks",
		"content_length", len(content),
		"top_k", topK)

	// Delegate to query bridge
	patterns, err := h.graphRAGQueryBridge.FindSimilarAttacks(ctx, content, topK)
	if err != nil {
		h.logger.Error("find similar attacks failed",
			"error", err)
		return nil, err
	}

	h.logger.Debug("find similar attacks completed",
		"patterns_count", len(patterns))

	return patterns, nil
}

// FindSimilarFindings searches for findings semantically similar to the referenced finding.
func (h *DefaultAgentHarness) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]sdkgraphrag.FindingNode, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.FindSimilarFindings")
	defer span.End()

	h.logger.Debug("finding similar findings",
		"finding_id", findingID,
		"top_k", topK)

	// Delegate to query bridge
	findings, err := h.graphRAGQueryBridge.FindSimilarFindings(ctx, findingID, topK)
	if err != nil {
		h.logger.Error("find similar findings failed",
			"finding_id", findingID,
			"error", err)
		return nil, err
	}

	h.logger.Debug("find similar findings completed",
		"findings_count", len(findings))

	return findings, nil
}

// GetAttackChains discovers multi-step attack paths starting from a technique.
func (h *DefaultAgentHarness) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]sdkgraphrag.AttackChain, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GetAttackChains")
	defer span.End()

	h.logger.Debug("getting attack chains",
		"technique_id", techniqueID,
		"max_depth", maxDepth)

	// Delegate to query bridge
	chains, err := h.graphRAGQueryBridge.GetAttackChains(ctx, techniqueID, maxDepth)
	if err != nil {
		h.logger.Error("get attack chains failed",
			"technique_id", techniqueID,
			"error", err)
		return nil, err
	}

	h.logger.Debug("get attack chains completed",
		"chains_count", len(chains))

	return chains, nil
}

// GetRelatedFindings retrieves findings connected via SIMILAR_TO or RELATED_TO relationships.
func (h *DefaultAgentHarness) GetRelatedFindings(ctx context.Context, findingID string) ([]sdkgraphrag.FindingNode, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GetRelatedFindings")
	defer span.End()

	h.logger.Debug("getting related findings",
		"finding_id", findingID)

	// Delegate to query bridge
	findings, err := h.graphRAGQueryBridge.GetRelatedFindings(ctx, findingID)
	if err != nil {
		h.logger.Error("get related findings failed",
			"finding_id", findingID,
			"error", err)
		return nil, err
	}

	h.logger.Debug("get related findings completed",
		"findings_count", len(findings))

	return findings, nil
}

// ────────────────────────────────────────────────────────────────────────────
// GraphRAG Storage Methods
// ────────────────────────────────────────────────────────────────────────────

// StoreNode stores a graph node using proto messages.
// This is the preferred method for storing nodes with explicit proto schemas.
func (h *DefaultAgentHarness) StoreNode(ctx context.Context, node *graphragpb.GraphNode) (string, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.StoreNode")
	defer span.End()

	h.logger.Debug("storing graph node (proto)",
		"node_type", node.Type)

	// Convert proto node to SDK GraphNode
	sdkNode, err := protoNodeToSDK(node)
	if err != nil {
		h.logger.Error("failed to convert proto node to SDK node",
			"error", err)
		return "", fmt.Errorf("failed to convert proto node: %w", err)
	}

	// Delegate to existing StoreGraphNode implementation
	nodeID, err := h.StoreGraphNode(ctx, *sdkNode)
	if err != nil {
		h.logger.Error("store graph node (proto) failed",
			"node_type", node.Type,
			"error", err)
		return "", err
	}

	h.logger.Debug("store graph node (proto) completed",
		"node_id", nodeID)

	return nodeID, nil
}

// protoNodeToSDK converts a proto GraphNode to SDK GraphNode
func protoNodeToSDK(protoNode *graphragpb.GraphNode) (*sdkgraphrag.GraphNode, error) {
	if protoNode == nil {
		return nil, fmt.Errorf("proto node is nil")
	}

	// Convert node type enum to string
	nodeType := protoNode.Type
	// Remove the "NODE_TYPE_" prefix that proto enums have
	if len(nodeType) > 10 && nodeType[:10] == "NODE_TYPE_" {
		nodeType = nodeType[10:]
	}

	// Convert map[string]string to map[string]any
	properties := make(map[string]any)
	for k, v := range protoNode.Properties {
		properties[k] = v
	}

	// Create SDK node (no ID field in proto, will be generated by storage)
	node := &sdkgraphrag.GraphNode{
		Type:       nodeType,
		Content:    protoNode.Content,
		Properties: properties,
	}

	return node, nil
}

// StoreGraphNode stores an arbitrary node in the knowledge graph.
func (h *DefaultAgentHarness) StoreGraphNode(ctx context.Context, node sdkgraphrag.GraphNode) (string, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.StoreGraphNode")
	defer span.End()

	h.logger.Debug("storing graph node",
		"node_type", node.Type)

	// Delegate to query bridge with mission and agent context
	nodeID, err := h.graphRAGQueryBridge.StoreNode(ctx, node, h.missionCtx.ID.String(), h.missionCtx.CurrentAgent)
	if err != nil {
		h.logger.Error("store graph node failed",
			"node_type", node.Type,
			"error", err)
		return "", err
	}

	h.logger.Debug("store graph node completed",
		"node_id", nodeID)

	return nodeID, nil
}

// CreateGraphRelationship creates a relationship between two existing nodes.
func (h *DefaultAgentHarness) CreateGraphRelationship(ctx context.Context, rel sdkgraphrag.Relationship) error {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CreateGraphRelationship")
	defer span.End()

	h.logger.Debug("creating graph relationship",
		"relationship_type", rel.Type,
		"from_id", rel.FromID,
		"to_id", rel.ToID)

	// Delegate to query bridge
	err := h.graphRAGQueryBridge.CreateRelationship(ctx, rel)
	if err != nil {
		h.logger.Error("create graph relationship failed",
			"relationship_type", rel.Type,
			"error", err)
		return err
	}

	h.logger.Debug("create graph relationship completed")

	return nil
}

// StoreGraphBatch stores multiple nodes and relationships atomically.
func (h *DefaultAgentHarness) StoreGraphBatch(ctx context.Context, batch sdkgraphrag.Batch) ([]string, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.StoreGraphBatch")
	defer span.End()

	h.logger.Debug("storing graph batch",
		"nodes_count", len(batch.Nodes),
		"relationships_count", len(batch.Relationships))

	// Delegate to query bridge with mission and agent context
	nodeIDs, err := h.graphRAGQueryBridge.StoreBatch(ctx, batch, h.missionCtx.ID.String(), h.missionCtx.CurrentAgent)
	if err != nil {
		h.logger.Error("store graph batch failed",
			"error", err)
		return nil, err
	}

	h.logger.Debug("store graph batch completed",
		"node_ids_count", len(nodeIDs))

	return nodeIDs, nil
}

// TraverseGraph walks the graph from a starting node following relationships.
func (h *DefaultAgentHarness) TraverseGraph(ctx context.Context, startNodeID string, opts sdkgraphrag.TraversalOptions) ([]sdkgraphrag.TraversalResult, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.TraverseGraph")
	defer span.End()

	h.logger.Debug("traversing graph",
		"start_node_id", startNodeID,
		"max_depth", opts.MaxDepth,
		"direction", opts.Direction)

	// Delegate to query bridge
	results, err := h.graphRAGQueryBridge.Traverse(ctx, startNodeID, opts)
	if err != nil {
		h.logger.Error("traverse graph failed",
			"start_node_id", startNodeID,
			"error", err)
		return nil, err
	}

	h.logger.Debug("traverse graph completed",
		"results_count", len(results))

	return results, nil
}

// GraphRAGHealth returns the health status of the GraphRAG subsystem.
func (h *DefaultAgentHarness) GraphRAGHealth(ctx context.Context) types.HealthStatus {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GraphRAGHealth")
	defer span.End()

	// Delegate to query bridge (GraphRAG is always required)
	status := h.graphRAGQueryBridge.Health(ctx)

	h.logger.Debug("graphrag health check completed",
		"state", status.State,
		"message", status.Message)

	return status
}

// ────────────────────────────────────────────────────────────────────────────
// Mission Context Methods
// ────────────────────────────────────────────────────────────────────────────

// MissionExecutionContext returns comprehensive mission execution information.
// This includes run history, resume status, and memory continuity indicators
// to help agents make informed decisions based on mission history.
func (h *DefaultAgentHarness) MissionExecutionContext() MissionExecutionContextSDK {
	ctx := context.Background()

	// Try to get context from provider
	if h.contextProvider != nil {
		execCtx, err := h.contextProvider.GetContext(ctx)
		if err != nil {
			h.logger.Warn("failed to get mission execution context", "error", err)
			// Fall through to basic context
		} else {
			// Convert internal context to SDK type
			return convertToSDKContext(execCtx)
		}
	}

	// Return basic context from existing Mission() method
	m := h.Mission()
	return MissionExecutionContextSDK{
		MissionID:            m.ID.String(),
		MissionName:          m.Name,
		RunNumber:            1,
		IsResumed:            false,
		PreviousRunID:        "",
		PreviousRunStatus:    "",
		TotalFindingsAllRuns: 0,
		MemoryContinuity:     "first_run",
	}
}

// GetMissionRunHistory returns all runs for the current mission name.
// Results are ordered by run number descending (most recent first).
func (h *DefaultAgentHarness) GetMissionRunHistory(ctx context.Context) ([]MissionRunSummarySDK, error) {
	ctx, span := h.tracer.Start(ctx, "AgentHarness.GetMissionRunHistory")
	defer span.End()

	if h.contextProvider == nil {
		h.logger.Debug("mission context provider not available")
		return []MissionRunSummarySDK{}, nil
	}

	runs, err := h.contextProvider.GetRunHistory(ctx)
	if err != nil {
		h.logger.Error("failed to get run history", "error", err)
		return nil, fmt.Errorf("failed to get mission run history: %w", err)
	}

	// Convert internal runs to SDK type
	result := make([]MissionRunSummarySDK, len(runs))
	for i, r := range runs {
		result[i] = convertToSDKRunSummary(r)
	}

	h.logger.Debug("retrieved mission run history", "count", len(result))
	return result, nil
}

// GetPreviousRunFindings retrieves findings from the previous mission run.
// This enables agents to understand what was discovered in prior attempts.
func (h *DefaultAgentHarness) GetPreviousRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	ctx, span := h.tracer.Start(ctx, "AgentHarness.GetPreviousRunFindings")
	defer span.End()

	if h.contextProvider == nil {
		h.logger.Debug("mission context provider not available")
		return []agent.Finding{}, nil
	}

	prevRun, err := h.contextProvider.GetPreviousRun(ctx)
	if err != nil || prevRun == nil {
		h.logger.Debug("no previous run available")
		return []agent.Finding{}, nil // No previous run
	}

	// Use the finding store to retrieve findings
	if h.findingStore == nil {
		h.logger.Warn("finding store not available")
		return []agent.Finding{}, nil
	}

	findings, err := h.findingStore.Get(ctx, prevRun.MissionID, filter)
	if err != nil {
		h.logger.Error("failed to get previous run findings",
			"previous_run_id", prevRun.MissionID.String(),
			"error", err)
		return nil, fmt.Errorf("failed to get previous run findings: %w", err)
	}

	h.logger.Debug("retrieved previous run findings",
		"previous_run_id", prevRun.MissionID.String(),
		"count", len(findings))
	return findings, nil
}

// GetAllRunFindings retrieves findings from all runs of this mission.
// This provides complete historical context across all mission executions.
func (h *DefaultAgentHarness) GetAllRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	ctx, span := h.tracer.Start(ctx, "AgentHarness.GetAllRunFindings")
	defer span.End()

	if h.contextProvider == nil {
		h.logger.Debug("mission context provider not available")
		return []agent.Finding{}, nil
	}

	if h.findingStore == nil {
		h.logger.Warn("finding store not available")
		return []agent.Finding{}, nil
	}

	// Get all runs for this mission
	runs, err := h.contextProvider.GetRunHistory(ctx)
	if err != nil {
		h.logger.Error("failed to get run history", "error", err)
		return nil, fmt.Errorf("failed to get run history: %w", err)
	}

	// Collect all findings from all runs
	var allFindings []agent.Finding
	for _, run := range runs {
		findings, err := h.findingStore.Get(ctx, run.MissionID, filter)
		if err != nil {
			h.logger.Warn("failed to get findings for run",
				"run_id", run.MissionID.String(),
				"error", err)
			continue // Skip this run but continue with others
		}

		allFindings = append(allFindings, findings...)
	}

	h.logger.Debug("retrieved findings from all runs",
		"total_runs", len(runs),
		"total_findings", len(allFindings))
	return allFindings, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Proto Resolution Methods
// ────────────────────────────────────────────────────────────────────────────

// Resolver returns the ProtoResolver used by this harness for dynamic type resolution.
// This resolver is used to convert between structpb.Struct and strongly-typed proto messages
// when tools use proto schemas not available in the global registry.
//
// Returns:
//   - protoresolver.ProtoResolver: The resolver instance, or nil if not configured
func (h *DefaultAgentHarness) Resolver() protoresolver.ProtoResolver {
	return h.resolver
}

// ────────────────────────────────────────────────────────────────────────────
// Lifecycle Methods
// ────────────────────────────────────────────────────────────────────────────

// Close releases resources held by the harness, including waiting for
// any pending async operations to complete.
//
// This method should be called when the harness is no longer needed, typically
// at the end of an agent's execution or when the mission is complete.
//
// Close performs the following cleanup:
//   - Waits for pending GraphRAG storage operations to complete
//   - Logs any shutdown errors at WARN level
//
// The context can be used to set a timeout for the shutdown.
func (h *DefaultAgentHarness) Close(ctx context.Context) error {
	h.logger.Debug("closing harness")

	// Shutdown GraphRAG bridge and wait for pending operations
	if h.graphRAGBridge != nil {
		if err := h.graphRAGBridge.Shutdown(ctx); err != nil {
			h.logger.Warn("graphrag bridge shutdown error",
				"error", err)
			return err
		}
	}

	h.logger.Debug("harness closed successfully")
	return nil
}
