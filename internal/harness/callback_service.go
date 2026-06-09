package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/graphrag/loader"
	"github.com/zeroroot-ai/gibson/internal/harness/middleware"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/queue"
	"github.com/zeroroot-ai/gibson/internal/types"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
	"github.com/zeroroot-ai/sdk/auth"
	sdkfinding "github.com/zeroroot-ai/sdk/finding"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
	"github.com/zeroroot-ai/sdk/protoresolver"
	"github.com/zeroroot-ai/sdk/schema"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

// CredentialStore provides access to stored credentials.
// This interface is implemented by the daemon's credential manager
// to provide secure credential retrieval with decryption.
type CredentialStore interface {
	// GetCredential retrieves a credential by name, decrypting it if necessary.
	// Returns the credential with its secret value populated.
	GetCredential(ctx context.Context, name string) (*types.Credential, string, error)
}

// EventBusPublisher is an interface for publishing daemon-wide events.
// This allows the callback service to publish tool and LLM events
// to the daemon's event bus for graph processing.
type EventBusPublisher interface {
	Publish(ctx context.Context, event interface{}) error
}

// DiscoveryProcessor processes proto DiscoveryResult from tool responses.
// This interface is implemented by the graphrag/processor package to
// extract, convert, and store discovered entities to Neo4j.
type DiscoveryProcessor interface {
	// Process extracts discovered nodes from a proto DiscoveryResult and stores them in the graph.
	// Takes graphragpb.DiscoveryResult (proto-first approach) for processing.
	Process(ctx context.Context, execCtx loader.ExecContext, discovery *graphragpb.DiscoveryResult) (interface{}, error)
}

// HarnessCallbackService implements the gRPC HarnessCallbackService server.
// It receives harness operation requests from remote agents via gRPC and
// delegates them to the appropriate registered harness instance.
//
// The service uses mission-based harness lookup via CallbackHarnessRegistry,
// requiring explicit mission_id and agent_name in the callback context.
// This enforces clean separation and supports concurrent execution of the
// same agent in different missions.
//
// When an agent running in standalone mode makes a harness call, the SDK's
// CallbackClient sends a gRPC request with context information (mission ID
// and agent name), which is used to look up the correct harness instance.
//
// To register this service with a gRPC server:
//
//	service := harness.NewHarnessCallbackServiceWithRegistry(logger, registry)
//	harnesspb.RegisterHarnessCallbackServiceServer(grpcServer, service)
//
// Before executing an agent task, register its harness:
//
//	registry.RegisterHarnessForMission(missionID, agentName, harness)
//	defer registry.UnregisterHarnessForMission(missionID, agentName)
type HarnessCallbackService struct {
	harnesspb.UnimplementedHarnessCallbackServiceServer

	// activeHarnesses maps task IDs to their corresponding harness instances (legacy mode)
	activeHarnesses sync.Map // map[string]AgentHarness

	// registry provides mission-based harness lookup for external agents (new mode)
	registry *CallbackHarnessRegistry

	// credentialStore provides access to stored credentials
	credentialStore CredentialStore

	// graphLoader loads domain nodes into Neo4j using the GraphNode interface
	graphLoader *loader.GraphLoader

	// eventBus publishes tool and LLM events for graph processing
	eventBus EventBusPublisher

	// spanProcessors receives spans exported from remote agents for tracing integration
	spanProcessors []sdktrace.SpanProcessor

	// tracerProvider for creating real spans from proxy span data
	tracerProvider *sdktrace.TracerProvider

	// metadataInjector adds mission context metadata to graph nodes before storage
	metadataInjector MetadataInjector

	// discoveryProcessor processes DiscoveryResult from tool responses and stores to Neo4j
	discoveryProcessor DiscoveryProcessor

	// queueManager provides access to the Redis work queue for parallel tool execution
	queueManager *QueueManager

	// missionManager provides full mission lifecycle operations (create, run, wait, cancel, etc.).
	// Declared as MissionOperator so the six mission callback stubs can delegate without a cast.
	missionManager MissionOperator

	// authzStore provides per-run authz state lookup (run_id → user_id, tenant_id).
	// Typed as RunAuthzLookup to avoid a circular import (mission→eval→harness).
	// One-code-path slice deploy#195: required for any callback service that
	// will actually serve Authorize calls — the daemon wires this in setup.
	// Tests that build the service directly without it MUST NOT exercise
	// Authorize.
	authzStore RunAuthzLookup

	// componentAuthorizer is the FGA-backed authorizer for component authz decisions.
	// One-code-path slice deploy#195: required for any callback service that
	// will actually serve Authorize calls. The daemon wires this in setup
	// after FGA has been reached.
	componentAuthorizer authz.Authorizer

	// componentRegistry is the tenant-scoped component registry the SearchTools
	// RPC enumerates to build the connector catalog. Wired by the daemon; when
	// nil, SearchTools returns Unavailable.
	componentRegistry component.ComponentRegistry

	// componentAuthzMetrics emits counters for every component Authorize decision.
	// When nil, metrics are not emitted (no-op).
	componentAuthzMetrics ComponentAuthzMetrics

	// resolver provides dynamic proto type resolution using FileDescriptorSets
	resolver protoresolver.ProtoResolver

	// agentOwnerLookup resolves a target agent name to its owning user ID for
	// sub-agent ExecutorUser attribution (spec:
	// llm-user-attribution-governance Requirement 1.5). When nil the
	// DelegateToAgent handler simply does not populate ExecutorUser —
	// EnrichSpan omits the attribute rather than failing the call. The
	// indirection keeps the callback service free of a direct dependency on
	// the component registry.
	agentOwnerLookup AgentOwnerLookup

	// mu protects spanProcessors for concurrent access
	mu sync.RWMutex

	// logger for service-level logging
	logger *slog.Logger
}

// AgentOwnerLookup resolves an agent component name (as registered in the
// daemon's component registry) to the user ID that owns it. Used by
// DelegateToAgent to populate ExecutorUser on the sub-agent's execution
// context so downstream LLM spans carry executor_user_id alongside the
// mission-stable initiator_user_id.
//
// Implementations should return ("", nil) when the owner is not resolvable
// (unknown agent, tenant-shared system agent, etc.) — DelegateToAgent
// treats this as graceful degradation and simply does not set the key.
// Returning a non-nil error aborts the delegation.
type AgentOwnerLookup func(ctx context.Context, agentName string) (userID string, err error)

// CallbackServiceOption configures the callback service.
type CallbackServiceOption func(*HarnessCallbackService)

// WithSpanProcessors adds span processors to receive tracing spans from remote agents.
func WithSpanProcessors(processors ...sdktrace.SpanProcessor) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.spanProcessors = append(s.spanProcessors, processors...)
	}
}

// WithTracerProvider sets the TracerProvider for creating real spans from proxy span data.
// When set, proxy spans from remote agents are re-created as real spans and passed through
// the TracerProvider's span processors (e.g., Langfuse exporter).
func WithTracerProvider(tp *sdktrace.TracerProvider) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.tracerProvider = tp
	}
}

// WithCredentialStore sets the credential store for secure credential retrieval.
// When set, agents can retrieve stored credentials by name via the GetCredential RPC.
func WithCredentialStore(store CredentialStore) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.credentialStore = store
	}
}

// WithEventBus sets the event bus for publishing tool and LLM events.
// When set, the callback service publishes events for tool calls and LLM requests
// that can be consumed by the execution graph engine.
func WithEventBus(eventBus EventBusPublisher) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.eventBus = eventBus
	}
}

// WithGraphLoader sets the GraphLoader for processing DiscoveryResult tool outputs.
// When set, the callback service will check if tool output is a DiscoveryResult
// and use the loader to create nodes and relationships in Neo4j.
func WithGraphLoader(graphLoader *loader.GraphLoader) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.graphLoader = graphLoader
	}
}

// WithDiscoveryProcessor sets the DiscoveryProcessor for automatic graph storage.
// When set, the callback service will extract DiscoveryResult from tool responses
// and automatically persist discovered entities to Neo4j.
func WithDiscoveryProcessor(processor DiscoveryProcessor) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.discoveryProcessor = processor
	}
}

// WithQueueManager sets the QueueManager for Redis-based work queue operations.
// When set, the callback service can queue tool work and stream results back to agents.
func WithQueueManager(queueMgr *QueueManager) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.queueManager = queueMgr
	}
}

// WithMissionManager sets the MissionOperator for agent-driven mission lifecycle operations.
// When set, agents can create, run, wait for, list, cancel, and get results of missions
// through the corresponding harness callback RPCs.
func WithMissionManager(missionMgr MissionOperator) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.missionManager = missionMgr
	}
}

// WithProtoResolver sets the ProtoResolver for dynamic proto type resolution.
// When set, the callback service uses this resolver for CallToolProto requests.
// If not set, a default resolver with standard configuration will be created.
func WithProtoResolver(resolver protoresolver.ProtoResolver) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.resolver = resolver
	}
}

// WithAgentOwnerLookup wires an AgentOwnerLookup so DelegateToAgent can
// populate ExecutorUser on the sub-agent dispatch context. When not
// configured, the handler skips ExecutorUser propagation and EnrichSpan
// omits the executor_user_id span attribute (graceful degradation).
// Typical implementations close over the daemon's ComponentRegistry.
func WithAgentOwnerLookup(fn AgentOwnerLookup) CallbackServiceOption {
	return func(s *HarnessCallbackService) {
		s.agentOwnerLookup = fn
	}
}

// NewHarnessCallbackService creates a new callback service instance with
// task-based harness lookup (legacy mode).
func NewHarnessCallbackService(logger *slog.Logger, opts ...CallbackServiceOption) *HarnessCallbackService {
	if logger == nil {
		logger = slog.Default()
	}

	s := &HarnessCallbackService{
		logger:           logger.With("component", "harness_callback_service"),
		metadataInjector: NewMetadataInjector(),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Create default resolver if none was provided
	if s.resolver == nil {
		s.resolver = protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
	}

	return s
}

// NewHarnessCallbackServiceWithRegistry creates a new callback service instance
// with mission-based harness lookup via the provided registry.
//
// This is the preferred constructor for external agents, as it supports
// concurrent execution of the same agent in different missions.
//
// Parameters:
//   - logger: Structured logger for service events
//   - registry: The harness registry for mission-based lookups
//   - opts: Optional configuration options (e.g., WithSpanProcessors)
//
// Returns:
//   - *HarnessCallbackService: A new service instance ready to be registered
func NewHarnessCallbackServiceWithRegistry(logger *slog.Logger, registry *CallbackHarnessRegistry, opts ...CallbackServiceOption) *HarnessCallbackService {
	if logger == nil {
		logger = slog.Default()
	}

	s := &HarnessCallbackService{
		registry:         registry,
		logger:           logger.With("component", "harness_callback_service"),
		metadataInjector: NewMetadataInjector(),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Create default resolver if none was provided
	if s.resolver == nil {
		s.resolver = protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
	}

	return s
}

// UnregisterHarness removes a harness instance when a task completes.
// This prevents memory leaks from accumulating completed tasks.
func (s *HarnessCallbackService) UnregisterHarness(taskID string) {
	s.activeHarnesses.Delete(taskID)
	s.logger.Debug("unregistered harness for task", "task_id", taskID)
}

// getHarness retrieves the harness for a request based on the context information.
//
// This method requires explicit mission ID and agent name for harness lookup via registry.
// The legacy string parsing and task-based lookup have been removed to enforce the use
// of the explicit mission_id field in ContextInfo.
//
// Parameters:
//   - ctx: Request context
//   - contextInfo: Context information from the gRPC request
//
// Returns:
//   - AgentHarness: The harness instance to use for this request
//   - error: Non-nil if no harness is found or if context info is invalid
func (s *HarnessCallbackService) getHarness(ctx context.Context, contextInfo *harnesspb.ContextInfo) (AgentHarness, error) {
	if contextInfo == nil {
		return nil, status.Error(codes.InvalidArgument, "missing context info in request")
	}

	// Require explicit mission ID and agent name
	if contextInfo.MissionId == "" {
		return nil, status.Error(codes.InvalidArgument, "missing mission_id in context info - ensure agent SDK is v0.7.0+")
	}

	if contextInfo.AgentName == "" {
		return nil, status.Error(codes.InvalidArgument, "missing agent_name in context info")
	}

	// Registry must be configured for mission-based lookup
	if s.registry == nil {
		return nil, status.Error(codes.Internal, "callback registry not configured")
	}

	// Perform registry lookup with explicit mission ID and agent name
	harness, err := s.registry.Lookup(contextInfo.MissionId, contextInfo.AgentName)
	if err != nil {
		s.logger.Error("harness lookup failed",
			"mission_id", contextInfo.MissionId,
			"agent_name", contextInfo.AgentName,
			"task_id", contextInfo.TaskId,
			"error", err,
		)
		return nil, status.Errorf(codes.NotFound, "no active harness for mission %s, agent %s: %v",
			contextInfo.MissionId, contextInfo.AgentName, err)
	}

	s.logger.Debug("harness lookup succeeded",
		"mission_id", contextInfo.MissionId,
		"agent_name", contextInfo.AgentName,
		"task_id", contextInfo.TaskId,
	)

	// Tenant isolation: prevent cross-tenant harness access. Per
	// unified-identity-and-authorization Requirement 8.6, the legacy
	// dev-mode bypass (allowing through when either side was empty)
	// is removed. Identity must always have a tenant by the time it
	// reaches a handler — if it does not, the request is rejected.
	// Mission tenant must always be set — if it is not, the mission
	// was created under broken state and we refuse to operate on it.
	contextTenant := auth.TenantStringFromContext(ctx)
	missionTenant := harness.Mission().TenantID
	if contextTenant == "" || contextTenant == auth.SystemTenantString {
		s.logger.Warn("harness lookup with missing tenant in context",
			slog.String("mission_id", contextInfo.MissionId),
			slog.String("agent_name", contextInfo.AgentName),
		)
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if missionTenant == "" {
		s.logger.Warn("harness lookup against mission with empty tenant",
			slog.String("context_tenant", contextTenant),
			slog.String("mission_id", contextInfo.MissionId),
		)
		return nil, status.Error(codes.PermissionDenied, "mission has no tenant")
	}
	if contextTenant != missionTenant {
		s.logger.Warn("tenant mismatch on harness lookup",
			slog.String("context_tenant", contextTenant),
			slog.String("mission_tenant", missionTenant),
			slog.String("mission_id", contextInfo.MissionId),
			slog.String("agent_name", contextInfo.AgentName),
		)
		return nil, status.Error(codes.PermissionDenied, "tenant mismatch")
	}

	return harness, nil
}

// getGraphRAGHarness retrieves a harness that supports GraphRAG operations.
func (s *HarnessCallbackService) getGraphRAGHarness(ctx context.Context, contextInfo *harnesspb.ContextInfo) (GraphRAGSupport, error) {
	harness, err := s.getHarness(ctx, contextInfo)
	if err != nil {
		return nil, err
	}

	graphRAG, ok := harness.(GraphRAGSupport)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "GraphRAG not supported by this harness")
	}

	return graphRAG, nil
}

// ============================================================================
// LLM Operations
// ============================================================================

// LLMComplete implements the LLM completion RPC.
func (s *HarnessCallbackService) LLMComplete(ctx context.Context, req *harnesspb.LLMCompleteRequest) (*harnesspb.LLMCompleteResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Publish llm.request.started event
	// Include parent_span_id from context so taxonomy engine can create MADE_CALL relationship
	s.publishEvent(ctx, "llm.request.started", map[string]interface{}{
		"slot":           req.Slot,
		"mission_id":     req.Context.MissionId,
		"agent_name":     req.Context.AgentName,
		"task_id":        req.Context.TaskId,
		"message_count":  len(req.Messages),
		"parent_span_id": req.Context.SpanId, // Agent's span ID becomes LLM call's parent
	})

	// Convert proto messages to llm.Message
	messages := s.protoToMessages(req.Messages)

	// Build completion options
	var opts []CompletionOption
	if req.Temperature != nil {
		opts = append(opts, WithTemperature(*req.Temperature))
	}
	if req.MaxTokens != nil {
		opts = append(opts, WithMaxTokens(int(*req.MaxTokens)))
	}
	if req.TopP != nil {
		opts = append(opts, WithTopP(*req.TopP))
	}
	if len(req.Stop) > 0 {
		opts = append(opts, WithStopSequences(req.Stop...))
	}

	// Execute completion
	resp, err := harness.Complete(ctx, req.Slot, messages, opts...)
	if err != nil {
		s.logger.Error("LLM completion failed", "error", err, "task_id", req.Context.TaskId)

		// Publish llm.request.failed event
		s.publishEvent(ctx, "llm.request.failed", map[string]interface{}{
			"slot":           req.Slot,
			"mission_id":     req.Context.MissionId,
			"agent_name":     req.Context.AgentName,
			"task_id":        req.Context.TaskId,
			"error":          err.Error(),
			"parent_span_id": req.Context.SpanId,
		})

		return &harnesspb.LLMCompleteResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Publish llm.request.completed event
	s.publishEvent(ctx, "llm.request.completed", map[string]interface{}{
		"slot":              req.Slot,
		"mission_id":        req.Context.MissionId,
		"agent_name":        req.Context.AgentName,
		"task_id":           req.Context.TaskId,
		"finish_reason":     string(resp.FinishReason),
		"prompt_tokens":     resp.Usage.PromptTokens,
		"completion_tokens": resp.Usage.CompletionTokens,
		"total_tokens":      resp.Usage.PromptTokens + resp.Usage.CompletionTokens,
		"parent_span_id":    req.Context.SpanId,
	})

	// Convert response
	return &harnesspb.LLMCompleteResponse{
		Content:      resp.Message.Content,
		ToolCalls:    s.toolCallsToProto(resp.Message.ToolCalls),
		FinishReason: string(resp.FinishReason),
		Usage: &harnesspb.TokenUsage{
			InputTokens:  int32(resp.Usage.PromptTokens),
			OutputTokens: int32(resp.Usage.CompletionTokens),
			TotalTokens:  int32(resp.Usage.PromptTokens + resp.Usage.CompletionTokens),
		},
	}, nil
}

// LLMCompleteWithTools implements the LLM completion with tools RPC.
func (s *HarnessCallbackService) LLMCompleteWithTools(ctx context.Context, req *harnesspb.LLMCompleteWithToolsRequest) (*harnesspb.LLMCompleteWithToolsResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert proto messages and tools
	messages := s.protoToMessages(req.Messages)
	tools := s.protoToToolDefs(req.Tools)

	// Execute completion with tools
	resp, err := harness.CompleteWithTools(ctx, req.Slot, messages, tools)
	if err != nil {
		s.logger.Error("LLM completion with tools failed", "error", err, "task_id", req.Context.TaskId)
		return &harnesspb.LLMCompleteWithToolsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert response
	return &harnesspb.LLMCompleteWithToolsResponse{
		Content:      resp.Message.Content,
		ToolCalls:    s.toolCallsToProto(resp.Message.ToolCalls),
		FinishReason: string(resp.FinishReason),
		Usage: &harnesspb.TokenUsage{
			InputTokens:  int32(resp.Usage.PromptTokens),
			OutputTokens: int32(resp.Usage.CompletionTokens),
			TotalTokens:  int32(resp.Usage.PromptTokens + resp.Usage.CompletionTokens),
		},
	}, nil
}

// LLMStream implements the streaming LLM completion RPC.
func (s *HarnessCallbackService) LLMStream(req *harnesspb.LLMStreamRequest, stream harnesspb.HarnessCallbackService_LLMStreamServer) error {
	harness, err := s.getHarness(stream.Context(), req.Context)
	if err != nil {
		return err
	}

	// Convert proto messages
	messages := s.protoToMessages(req.Messages)

	// Build completion options
	var opts []CompletionOption
	if req.Temperature != nil {
		opts = append(opts, WithTemperature(*req.Temperature))
	}
	if req.MaxTokens != nil {
		opts = append(opts, WithMaxTokens(int(*req.MaxTokens)))
	}
	if req.TopP != nil {
		opts = append(opts, WithTopP(*req.TopP))
	}
	if len(req.Stop) > 0 {
		opts = append(opts, WithStopSequences(req.Stop...))
	}

	// Execute streaming completion
	chunkChan, err := harness.Stream(stream.Context(), req.Slot, messages, opts...)
	if err != nil {
		s.logger.Error("LLM stream failed", "error", err, "task_id", req.Context.TaskId)
		return status.Errorf(codes.Internal, "stream failed: %v", err)
	}

	// Forward chunks to client
	for chunk := range chunkChan {
		// Check for error in chunk
		if chunk.Error != nil {
			protoChunk := &harnesspb.LLMStreamResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
					Message: chunk.Error.Error(),
				},
			}
			_ = stream.Send(protoChunk)
			return nil
		}

		protoChunk := &harnesspb.LLMStreamResponse{
			Delta:        chunk.Delta.Content,
			FinishReason: string(chunk.FinishReason),
		}

		if err := stream.Send(protoChunk); err != nil {
			s.logger.Error("failed to send stream chunk", "error", err)
			return status.Errorf(codes.Internal, "stream send failed: %v", err)
		}
	}

	return nil
}

// LLMCompleteStructured implements the structured LLM completion RPC.
// This uses provider-native structured output mechanisms (tool_use for Anthropic,
// response_format for OpenAI) to guarantee JSON responses matching the schema.
func (s *HarnessCallbackService) LLMCompleteStructured(ctx context.Context, req *harnesspb.LLMCompleteStructuredRequest) (*harnesspb.LLMCompleteStructuredResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert proto messages to llm.Message
	messages := s.protoToMessages(req.Messages)

	// Parse the schema JSON to reconstruct the schema type
	var schemaData map[string]any
	if err := json.Unmarshal([]byte(req.SchemaJson), &schemaData); err != nil {
		s.logger.Error("failed to parse schema JSON", "error", err, "task_id", req.Context.TaskId)
		return &harnesspb.LLMCompleteStructuredResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("invalid schema JSON: %v", err),
			},
		}, nil
	}

	// Execute structured completion
	// The harness.CompleteStructured method takes a schema type instance
	// For callback mode, we pass the parsed map which will be used to build the response format
	result, err := harness.CompleteStructuredAny(ctx, req.Slot, messages, schemaData)
	if err != nil {
		s.logger.Error("LLM structured completion failed", "error", err, "task_id", req.Context.TaskId)
		return &harnesspb.LLMCompleteStructuredResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Serialize result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		s.logger.Error("failed to serialize structured result", "error", err, "task_id", req.Context.TaskId)
		return &harnesspb.LLMCompleteStructuredResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to serialize result: %v", err),
			},
		}, nil
	}

	// Unmarshal JSON back to any to convert to TypedValue
	var resultData any
	if err := json.Unmarshal(resultJSON, &resultData); err != nil {
		return &harnesspb.LLMCompleteStructuredResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to unmarshal result: %v", err),
			},
		}, nil
	}

	return &harnesspb.LLMCompleteStructuredResponse{
		Result: anyToTypedValue(resultData),
		// Note: Token usage would need to be extracted from the completion response
		// For now we return nil usage since we don't have access to it from CompleteStructuredAny
	}, nil
}

// ============================================================================
// Tool Operations
// ============================================================================

// CallToolProto implements the proto-based tool execution RPC.
// This is the canonical way to execute tools from external agents.
func (s *HarnessCallbackService) CallToolProto(ctx context.Context, req *harnesspb.CallToolProtoRequest) (*harnesspb.CallToolProtoResponse, error) {
	// Meta-tools (search_tools / invoke_tool) are synthetic: they are not
	// registered tools, so intercept before the registry dispatch and resolve
	// them against the connector catalog (ADR-0047 facet 5).
	if isMetaTool(req.GetName()) {
		return s.callMetaTool(ctx, req)
	}

	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
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
	})

	// Get tool descriptor to validate it exists and extract metadata
	toolDesc, err := harness.GetToolDescriptor(ctx, req.Name)
	if err != nil {
		s.logger.Error("tool not found", "error", err, "tool", req.Name)
		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
				Message: fmt.Sprintf("tool not found: %s", req.Name),
			},
		}, nil
	}

	// Extract metadata from tool descriptor for FileDescriptorSet resolution
	toolMetadata := make(map[string]string)
	if toolDesc != nil && toolDesc.Metadata != nil {
		toolMetadata = toolDesc.Metadata
	}

	// Use resolver to unmarshal input JSON into proto message
	requestMsg, err := s.resolver.UnmarshalProtoJSON(ctx, req.InputType, req.InputJson, toolMetadata)
	if err != nil {
		s.logger.Error("failed to resolve and unmarshal input type",
			"error", err,
			"tool", req.Name,
			"input_type", req.InputType)
		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("failed to unmarshal input: %v", err),
			},
		}, nil
	}

	// Create empty output message for tool to fill
	responseMsg, err := s.resolver.ResolveOutputType(ctx, req.OutputType, toolMetadata)
	if err != nil {
		s.logger.Error("failed to resolve output type",
			"error", err,
			"tool", req.Name,
			"output_type", req.OutputType)
		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to resolve output type: %v", err),
			},
		}, nil
	}

	// Execute tool using CallToolProto
	if err := harness.CallToolProto(ctx, req.Name, requestMsg, responseMsg); err != nil {
		s.logger.Error("tool execution failed", "error", err, "tool", req.Name)

		// Publish tool.call.failed event
		s.publishEvent(ctx, "tool.call.failed", map[string]interface{}{
			"tool_name":      req.Name,
			"mission_id":     req.Context.MissionId,
			"agent_name":     req.Context.AgentName,
			"task_id":        req.Context.TaskId,
			"error":          err.Error(),
			"parent_span_id": req.Context.SpanId,
		})

		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Process discovery if present (async, non-blocking)
	if s.discoveryProcessor != nil {
		if pbDiscovery := sdkgraphrag.ExtractDiscovery(responseMsg); pbDiscovery != nil {
			// Build execution context from request context
			execCtx := loader.ExecContext{
				MissionRunID:    req.Context.MissionRunId,
				MissionID:       req.Context.MissionId,
				AgentName:       req.Context.AgentName,
				AgentRunID:      req.Context.AgentRunId,
				ToolExecutionID: req.Context.ToolExecutionId,
			}

			// Process discovery asynchronously with timeout
			// This doesn't block the tool response
			// NOTE: Now passing proto directly (proto-first approach)
			go func() {
				processCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				result, err := s.discoveryProcessor.Process(processCtx, execCtx, pbDiscovery)
				if err != nil {
					s.logger.ErrorContext(processCtx, "failed to process discovery",
						"error", err,
						"tool", req.Name,
						"mission_run_id", execCtx.MissionRunID,
					)
				} else if result != nil {
					// Log success (result type varies by processor implementation)
					s.logger.DebugContext(processCtx, "discovery processed successfully",
						"tool", req.Name,
						"mission_run_id", execCtx.MissionRunID,
					)
				}
			}()
		}
	}

	// Marshal proto response to JSON
	marshaler := protojson.MarshalOptions{
		UseProtoNames: true, // Use snake_case (proto field names) instead of camelCase
	}
	responseJSON, err := marshaler.Marshal(responseMsg)
	if err != nil {
		s.logger.Error("failed to marshal proto response to JSON", "error", err, "tool", req.Name)
		return &harnesspb.CallToolProtoResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to marshal response: %v", err),
			},
		}, nil
	}

	// Publish tool.call.completed event
	s.publishEvent(ctx, "tool.call.completed", map[string]interface{}{
		"tool_name":      req.Name,
		"mission_id":     req.Context.MissionId,
		"agent_name":     req.Context.AgentName,
		"task_id":        req.Context.TaskId,
		"parent_span_id": req.Context.SpanId,
	})

	return &harnesspb.CallToolProtoResponse{
		OutputJson: responseJSON,
	}, nil
}

// ListTools implements the tool listing RPC.
func (s *HarnessCallbackService) ListTools(ctx context.Context, req *harnesspb.ListToolsRequest) (*harnesspb.ListToolsResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Get tool descriptors
	tools := harness.ListTools()

	// At MCP catalog scale the agent does not see the full tool set as native
	// functions; it sees the two meta-tools and discovers via search_tools
	// (ADR-0047 facet 5). Advertise them only when the catalog is wired.
	if s.metaToolsWired() {
		tools = append(tools, metaToolDescriptors()...)
	}

	// Convert to proto with structured schemas (including taxonomy)
	protoTools := make([]*harnesspb.HarnessToolDescriptor, len(tools))
	for i, tool := range tools {
		protoTools[i] = &harnesspb.HarnessToolDescriptor{
			Name:         tool.Name,
			Description:  tool.Description,
			InputSchema:  SchemaToCallbackProto(tool.InputSchema),  // Structured schema with taxonomy
			OutputSchema: SchemaToCallbackProto(tool.OutputSchema), // Structured output schema with taxonomy
		}
	}

	return &harnesspb.ListToolsResponse{
		Tools: protoTools,
	}, nil
}

// QueueToolWork implements the queue-based parallel tool execution RPC.
// It queues multiple tool invocations to Redis for processing by distributed workers.
func (s *HarnessCallbackService) QueueToolWork(ctx context.Context, req *harnesspb.QueueToolWorkRequest) (*harnesspb.QueueToolWorkResponse, error) {
	// Check if queue manager is available
	if s.queueManager == nil {
		s.logger.Error("queue manager not configured", "tool", req.ToolName)
		return &harnesspb.QueueToolWorkResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: "queue-based tool execution not available (Redis not configured)",
			},
		}, nil
	}

	// Publish tool.queue.started event
	s.publishEvent(ctx, "tool.queue.started", map[string]interface{}{
		"tool_name":      req.ToolName,
		"mission_id":     req.Context.MissionId,
		"agent_name":     req.Context.AgentName,
		"task_id":        req.Context.TaskId,
		"parent_span_id": req.Context.SpanId,
		"input_type":     req.InputType,
		"output_type":    req.OutputType,
		"input_count":    len(req.InputJsons),
	})

	// Generate UUID for job ID
	jobID := uuid.New().String()

	// Get queue client
	queueClient := s.queueManager.Client()

	// Validate tool exists by checking Redis tools:available set
	availableTools, err := queueClient.ListTools(ctx)
	if err != nil {
		s.logger.Error("failed to list available tools", "error", err)
		return &harnesspb.QueueToolWorkResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to check tool availability: %v", err),
			},
		}, nil
	}

	// Check if requested tool is available
	toolFound := false
	for _, tool := range availableTools {
		if tool.Name == req.ToolName {
			toolFound = true
			break
		}
	}

	if !toolFound {
		s.logger.Warn("tool not found in queue", "tool", req.ToolName, "available", len(availableTools))
		return &harnesspb.QueueToolWorkResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_NOT_FOUND,
				Message: fmt.Sprintf("tool %s not available in queue (no workers registered)", req.ToolName),
			},
		}, nil
	}

	// Extract trace context from current span
	var traceID, spanID string
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		traceID = spanCtx.TraceID().String()
		spanID = spanCtx.SpanID().String()
	}

	// Current timestamp for submitted_at
	submittedAt := time.Now().UnixMilli()

	// Queue name for this tool
	queueName := fmt.Sprintf("tool:%s:queue", req.ToolName)

	// Push work items to Redis queue
	total := len(req.InputJsons)
	for i, inputJSON := range req.InputJsons {
		workItem := queue.WorkItem{
			JobID:       jobID,
			Index:       i,
			Total:       total,
			Tool:        req.ToolName,
			InputJSON:   inputJSON,
			InputType:   req.InputType,
			OutputType:  req.OutputType,
			TraceID:     traceID,
			SpanID:      spanID,
			SubmittedAt: submittedAt,
		}

		// Validate work item before pushing
		if err := workItem.IsValid(); err != nil {
			s.logger.Error("invalid work item", "error", err, "index", i)
			return &harnesspb.QueueToolWorkResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
					Message: fmt.Sprintf("invalid work item at index %d: %v", i, err),
				},
			}, nil
		}

		// Push to queue
		if err := queueClient.Push(ctx, queueName, workItem); err != nil {
			s.logger.Error("failed to push work item to queue",
				"error", err,
				"tool", req.ToolName,
				"job_id", jobID,
				"index", i,
			)
			return &harnesspb.QueueToolWorkResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
					Message: fmt.Sprintf("failed to queue work item %d: %v", i, err),
				},
			}, nil
		}
	}

	s.logger.Info("queued tool work",
		"tool", req.ToolName,
		"job_id", jobID,
		"count", total,
		"queue", queueName,
	)

	return &harnesspb.QueueToolWorkResponse{
		JobId: jobID,
	}, nil
}

// ToolResults implements the streaming RPC that delivers results from queued tool work.
// It subscribes to the Redis pub/sub channel for the job and streams results as they arrive.
func (s *HarnessCallbackService) ToolResults(req *harnesspb.ToolResultsRequest, stream harnesspb.HarnessCallbackService_ToolResultsServer) error {
	ctx := stream.Context()

	// Check if queue manager is available
	if s.queueManager == nil {
		s.logger.Error("queue manager not configured for ToolResults")
		return status.Error(codes.Internal, "queue-based tool execution not available (Redis not configured)")
	}

	jobID := req.JobId
	if jobID == "" {
		s.logger.Error("missing job_id in ToolResults request")
		return status.Error(codes.InvalidArgument, "job_id is required")
	}

	s.logger.Info("starting ToolResults stream",
		"job_id", jobID,
		"mission_id", req.Context.MissionId,
		"agent_name", req.Context.AgentName,
	)

	// Subscribe to job results channel
	channel := fmt.Sprintf("results:%s", jobID)
	queueClient := s.queueManager.Client()
	resultChan, err := queueClient.Subscribe(ctx, channel)
	if err != nil {
		s.logger.Error("failed to subscribe to results channel",
			"error", err,
			"job_id", jobID,
			"channel", channel,
		)
		return status.Errorf(codes.Internal, "failed to subscribe to results: %v", err)
	}

	s.logger.Info("subscribed to results channel",
		"job_id", jobID,
		"channel", channel,
	)

	// Stream results as they arrive
	// The channel is closed when context is cancelled, so we don't need to track total
	resultCount := 0
	for result := range resultChan {
		resultCount++

		// Convert queue.Result to proto ToolResultResponse
		protoResult := &harnesspb.ToolResultsResponse{
			Index: int32(result.Index),
		}

		if result.Error != "" {
			protoResult.Error = &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: result.Error,
			}
		} else {
			protoResult.OutputJson = result.OutputJSON
		}

		// Send result to stream
		if err := stream.Send(protoResult); err != nil {
			s.logger.Error("failed to send result to stream",
				"error", err,
				"job_id", jobID,
				"index", result.Index,
			)
			return err
		}

		s.logger.Debug("sent result to stream",
			"job_id", jobID,
			"index", result.Index,
			"result_count", resultCount,
		)
	}

	s.logger.Info("ToolResults stream closed",
		"job_id", jobID,
		"results_sent", resultCount,
	)

	return nil
}

// ============================================================================
// Plugin Operations
// ============================================================================

// QueryPlugin implements the plugin query RPC.
func (s *HarnessCallbackService) QueryPlugin(ctx context.Context, req *harnesspb.QueryPluginRequest) (*harnesspb.QueryPluginResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert params from proto map to Go map
	params := typedValueMapToMap(req.Params)

	// Query plugin
	result, err := harness.QueryPlugin(ctx, req.Name, req.Method, params)
	if err != nil {
		s.logger.Error("plugin query failed", "error", err, "plugin", req.Name, "method", req.Method)
		return &harnesspb.QueryPluginResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	return &harnesspb.QueryPluginResponse{
		Result: anyToTypedValue(result),
	}, nil
}

// ListPlugins implements the plugin listing RPC.
func (s *HarnessCallbackService) ListPlugins(ctx context.Context, req *harnesspb.ListPluginsRequest) (*harnesspb.ListPluginsResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Get plugin descriptors
	plugins := harness.ListPlugins()

	// Convert to proto
	protoPlugins := make([]*harnesspb.HarnessPluginDescriptor, len(plugins))
	for i, plugin := range plugins {
		// Extract method names from MethodDescriptor slice
		methodNames := make([]string, len(plugin.Methods))
		for j, method := range plugin.Methods {
			methodNames[j] = method.Name
		}

		protoPlugins[i] = &harnesspb.HarnessPluginDescriptor{
			Name:        plugin.Name,
			Description: "",
			Version:     plugin.Version,
			Methods:     methodNames,
		}
	}

	return &harnesspb.ListPluginsResponse{
		Plugins: protoPlugins,
	}, nil
}

// ============================================================================
// Agent Operations
// ============================================================================

// DelegateToAgent implements the agent delegation RPC.
func (s *HarnessCallbackService) DelegateToAgent(ctx context.Context, req *harnesspb.DelegateToAgentRequest) (*harnesspb.DelegateToAgentResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert proto Task to internal Task
	task := protoTaskToTask(req.Task)

	// Capture start time for agent execution
	agentStartTime := time.Now()

	// Resolve the delegated agent's owning user so ExecutorUser attribution
	// follows the code that's about to run. Graceful on both lookup absence
	// (no hook wired) and lookup miss (unknown agent, system-shared agent).
	// Spec: llm-user-attribution-governance Requirement 1.5.
	if s.agentOwnerLookup != nil {
		if ownerID, lookupErr := s.agentOwnerLookup(ctx, req.Name); lookupErr != nil {
			s.logger.Warn("agent owner lookup failed; skipping executor_user_id attribution",
				"agent", req.Name,
				"error", lookupErr,
			)
		} else if ownerID != "" {
			ctx = auth.ContextWithExecutorUser(ctx, ownerID)
		}
	}

	// Emit agent.started event
	s.publishEvent(ctx, "agent.started", map[string]interface{}{
		"agent_name":       req.Name,
		"task_id":          task.ID.String(),
		"task_description": task.Description,
		"mission_id":       req.Context.MissionId,
		"parent_agent":     req.Context.AgentName,
	})

	// Delegate to agent
	result, err := harness.DelegateToAgent(ctx, req.Name, task)

	// Calculate duration
	durationMs := time.Since(agentStartTime).Milliseconds()
	findingsCount := len(result.Findings)

	// Handle different execution outcomes
	if err != nil {
		s.logger.Error("agent delegation failed", "error", err, "agent", req.Name)

		// Check if context was cancelled
		if ctx.Err() == context.Canceled {
			s.publishEvent(ctx, "agent.cancelled", map[string]interface{}{
				"agent_name":    req.Name,
				"task_id":       task.ID.String(),
				"cancel_reason": "context cancelled",
				"duration_ms":   durationMs,
			})
		} else {
			// Emit agent.failed event
			s.publishEvent(ctx, "agent.failed", map[string]interface{}{
				"agent_name":     req.Name,
				"task_id":        task.ID.String(),
				"error":          err.Error(),
				"duration_ms":    durationMs,
				"findings_count": findingsCount,
			})
		}

		return &harnesspb.DelegateToAgentResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Emit agent.completed event on success
	s.publishEvent(ctx, "agent.completed", map[string]interface{}{
		"agent_name":     req.Name,
		"task_id":        task.ID.String(),
		"duration_ms":    durationMs,
		"findings_count": findingsCount,
		"success":        true,
	})

	return &harnesspb.DelegateToAgentResponse{
		Result: resultToProtoResult(result),
	}, nil
}

// ListAgents implements the agent listing RPC.
func (s *HarnessCallbackService) ListAgents(ctx context.Context, req *harnesspb.ListAgentsRequest) (*harnesspb.ListAgentsResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Get agent descriptors
	agents := harness.ListAgents()

	// Convert to proto
	protoAgents := make([]*harnesspb.HarnessAgentDescriptor, len(agents))
	for i, agent := range agents {
		protoAgents[i] = &harnesspb.HarnessAgentDescriptor{
			Name:        agent.Name,
			Version:     agent.Version,
			Description: agent.Description,
			// Note: Capabilities are []string in the AgentDescriptor
			// but we need to convert them appropriately
		}
	}

	return &harnesspb.ListAgentsResponse{
		Agents: protoAgents,
	}, nil
}

// ============================================================================
// Finding Operations
// ============================================================================

// SubmitFinding implements the finding submission RPC.
func (s *HarnessCallbackService) SubmitFinding(ctx context.Context, req *harnesspb.SubmitFindingRequest) (*harnesspb.SubmitFindingResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert proto Finding to internal Finding
	finding := protoFindingToFinding(req.Finding)

	// Submit finding
	if err := harness.SubmitFinding(ctx, finding); err != nil {
		s.logger.Error("finding submission failed", "error", err)
		return &harnesspb.SubmitFindingResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	return &harnesspb.SubmitFindingResponse{}, nil
}

// GetFindings implements the finding retrieval RPC.
func (s *HarnessCallbackService) GetFindings(ctx context.Context, req *harnesspb.GetFindingsRequest) (*harnesspb.GetFindingsResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert proto FindingFilter to internal FindingFilter
	filter := protoFilterToFindingFilter(req.Filter)

	// Get findings
	findings, err := harness.GetFindings(ctx, filter)
	if err != nil {
		s.logger.Error("get findings failed", "error", err)
		return &harnesspb.GetFindingsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert findings to proto
	protoFindings := make([]*typespb.Finding, len(findings))
	for i, finding := range findings {
		protoFindings[i] = findingToProtoFinding(finding)
	}

	return &harnesspb.GetFindingsResponse{
		Findings: protoFindings,
	}, nil
}

// ============================================================================
// Memory Operations
// ============================================================================

// MemoryGet implements the memory get RPC with tier routing.
func (s *HarnessCallbackService) MemoryGet(ctx context.Context, req *harnesspb.MemoryGetRequest) (*harnesspb.MemoryGetResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Default to WORKING tier for backward compatibility
	tier := req.Tier
	if tier == harnesspb.MemoryTier_MEMORY_TIER_UNSPECIFIED {
		tier = harnesspb.MemoryTier_MEMORY_TIER_WORKING
	}

	switch tier {
	case harnesspb.MemoryTier_MEMORY_TIER_WORKING:
		// Working memory: existing logic
		value, found := harness.Memory().Working().Get(req.Key)
		if !found {
			return &harnesspb.MemoryGetResponse{
				Found: false,
			}, nil
		}

		return &harnesspb.MemoryGetResponse{
			Value: anyToTypedValue(value),
			Found: true,
		}, nil

	case harnesspb.MemoryTier_MEMORY_TIER_MISSION:
		// Mission memory: use Retrieve method
		item, err := harness.Memory().Mission().Retrieve(ctx, req.Key)
		if err != nil {
			// Check for not found error
			if err.Error() == "memory: item not found" || err.Error() == "not found" {
				return &harnesspb.MemoryGetResponse{
					Found: false,
				}, nil
			}
			return &harnesspb.MemoryGetResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
					Message: fmt.Sprintf("failed to retrieve from mission memory: %v", err),
				},
			}, nil
		}

		typedMapMetadata := mapToTypedMap(item.Metadata)
		return &harnesspb.MemoryGetResponse{
			Value:     anyToTypedValue(item.Value),
			Metadata:  typedMapMetadata.Entries,
			Found:     true,
			CreatedAt: item.CreatedAt.Format(time.RFC3339),
		}, nil

	case harnesspb.MemoryTier_MEMORY_TIER_LONG_TERM:
		// Long-term memory does not support Get by key
		return &harnesspb.MemoryGetResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "Long-term memory does not support Get by key. Use LongTermMemorySearch instead.",
			},
		}, nil

	default:
		return &harnesspb.MemoryGetResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("unknown memory tier: %v", tier),
			},
		}, nil
	}
}

// MemorySet implements the memory set RPC with tier routing.
func (s *HarnessCallbackService) MemorySet(ctx context.Context, req *harnesspb.MemorySetRequest) (*harnesspb.MemorySetResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert value from proto TypedValue
	value := typedValueToAny(req.Value)

	// Default to WORKING tier for backward compatibility
	tier := req.Tier
	if tier == harnesspb.MemoryTier_MEMORY_TIER_UNSPECIFIED {
		tier = harnesspb.MemoryTier_MEMORY_TIER_WORKING
	}

	switch tier {
	case harnesspb.MemoryTier_MEMORY_TIER_WORKING:
		// Working memory: existing logic
		if err := harness.Memory().Working().Set(req.Key, value); err != nil {
			return &harnesspb.MemorySetResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
					Message: fmt.Sprintf("failed to set value: %v", err),
				},
			}, nil
		}
		return &harnesspb.MemorySetResponse{}, nil

	case harnesspb.MemoryTier_MEMORY_TIER_MISSION:
		// Mission memory: use Store method
		// Convert metadata from proto TypedMap
		metadata := typedValueMapToMap(req.Metadata)

		if err := harness.Memory().Mission().Store(ctx, req.Key, value, metadata); err != nil {
			return &harnesspb.MemorySetResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
					Message: fmt.Sprintf("failed to store in mission memory: %v", err),
				},
			}, nil
		}
		return &harnesspb.MemorySetResponse{}, nil

	case harnesspb.MemoryTier_MEMORY_TIER_LONG_TERM:
		// Long-term memory does not support Set by key
		return &harnesspb.MemorySetResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "Long-term memory does not support Set by key. Use LongTermMemoryStore instead.",
			},
		}, nil

	default:
		return &harnesspb.MemorySetResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("unknown memory tier: %v", tier),
			},
		}, nil
	}
}

// MemoryDelete implements the memory delete RPC with tier routing.
func (s *HarnessCallbackService) MemoryDelete(ctx context.Context, req *harnesspb.MemoryDeleteRequest) (*harnesspb.MemoryDeleteResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Default to WORKING tier for backward compatibility
	tier := req.Tier
	if tier == harnesspb.MemoryTier_MEMORY_TIER_UNSPECIFIED {
		tier = harnesspb.MemoryTier_MEMORY_TIER_WORKING
	}

	switch tier {
	case harnesspb.MemoryTier_MEMORY_TIER_WORKING:
		// Working memory: existing logic
		harness.Memory().Working().Delete(req.Key)
		return &harnesspb.MemoryDeleteResponse{}, nil

	case harnesspb.MemoryTier_MEMORY_TIER_MISSION:
		// Mission memory: use Delete method
		if err := harness.Memory().Mission().Delete(ctx, req.Key); err != nil {
			return &harnesspb.MemoryDeleteResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
					Message: fmt.Sprintf("failed to delete from mission memory: %v", err),
				},
			}, nil
		}
		return &harnesspb.MemoryDeleteResponse{}, nil

	case harnesspb.MemoryTier_MEMORY_TIER_LONG_TERM:
		// Long-term memory does not support Delete by key
		return &harnesspb.MemoryDeleteResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "Long-term memory does not support Delete by key. Use LongTermMemoryDelete instead.",
			},
		}, nil

	default:
		return &harnesspb.MemoryDeleteResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("unknown memory tier: %v", tier),
			},
		}, nil
	}
}

// MemoryList implements the memory list RPC with tier routing.
func (s *HarnessCallbackService) MemoryList(ctx context.Context, req *harnesspb.MemoryListRequest) (*harnesspb.MemoryListResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Default to WORKING tier for backward compatibility
	tier := req.Tier
	if tier == harnesspb.MemoryTier_MEMORY_TIER_UNSPECIFIED {
		tier = harnesspb.MemoryTier_MEMORY_TIER_WORKING
	}

	switch tier {
	case harnesspb.MemoryTier_MEMORY_TIER_WORKING:
		// List keys from working memory
		// Note: The proto request has a prefix field, but the working memory List() doesn't support prefix filtering
		// We'll get all keys and filter by prefix if needed
		allKeys := harness.Memory().Working().List()

		// Filter by prefix if provided
		var keys []string
		if req.Prefix != "" {
			for _, key := range allKeys {
				if len(key) >= len(req.Prefix) && key[:len(req.Prefix)] == req.Prefix {
					keys = append(keys, key)
				}
			}
		} else {
			keys = allKeys
		}

		return &harnesspb.MemoryListResponse{
			Keys: keys,
		}, nil

	case harnesspb.MemoryTier_MEMORY_TIER_MISSION:
		// Mission memory: use Keys method
		allKeys, err := harness.Memory().Mission().Keys(ctx)
		if err != nil {
			return &harnesspb.MemoryListResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
					Message: fmt.Sprintf("failed to list keys from mission memory: %v", err),
				},
			}, nil
		}

		// Filter by prefix if provided
		var keys []string
		if req.Prefix != "" {
			for _, key := range allKeys {
				if len(key) >= len(req.Prefix) && key[:len(req.Prefix)] == req.Prefix {
					keys = append(keys, key)
				}
			}
		} else {
			keys = allKeys
		}

		return &harnesspb.MemoryListResponse{
			Keys: keys,
		}, nil

	case harnesspb.MemoryTier_MEMORY_TIER_LONG_TERM:
		// Long-term memory does not support listing keys
		return &harnesspb.MemoryListResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "Long-term memory does not support listing keys.",
			},
		}, nil

	default:
		return &harnesspb.MemoryListResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("unknown memory tier: %v", tier),
			},
		}, nil
	}
}

// LongTermMemoryStore implements the long-term memory store RPC.
func (s *HarnessCallbackService) LongTermMemoryStore(ctx context.Context, req *harnesspb.LongTermMemoryStoreRequest) (*harnesspb.LongTermMemoryStoreResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert metadata from proto TypedMap
	metadata := typedValueMapToMap(req.Metadata)

	// Generate UUID for the content - SDK interface returns ID, daemon requires ID input
	id := uuid.New().String()

	// Daemon's LongTermMemory.Store takes (ctx, id, content, metadata)
	err = harness.Memory().LongTerm().Store(ctx, id, req.Content, metadata)
	if err != nil {
		return &harnesspb.LongTermMemoryStoreResponse{
			Error: &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_INTERNAL, Message: err.Error()},
		}, nil
	}

	return &harnesspb.LongTermMemoryStoreResponse{Id: id}, nil
}

// LongTermMemorySearch implements the long-term memory search RPC.
func (s *HarnessCallbackService) LongTermMemorySearch(ctx context.Context, req *harnesspb.LongTermMemorySearchRequest) (*harnesspb.LongTermMemorySearchResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Convert filters from proto TypedMap
	filters := typedValueMapToMap(req.Filters)

	results, err := harness.Memory().LongTerm().Search(ctx, req.Query, int(req.TopK), filters)
	if err != nil {
		return &harnesspb.LongTermMemorySearchResponse{
			Error: &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_INTERNAL, Message: err.Error()},
		}, nil
	}

	pbResults := make([]*harnesspb.LongTermMemoryResult, len(results))
	for i, r := range results {
		typedMapMetadata := mapToTypedMap(r.Item.Metadata)
		pbResults[i] = &harnesspb.LongTermMemoryResult{
			Id:        r.Item.Key,
			Content:   r.Item.Value.(string), // Content is stored as string
			Metadata:  typedMapMetadata.Entries,
			Score:     r.Score,
			CreatedAt: r.Item.CreatedAt.Format(time.RFC3339),
		}
	}

	return &harnesspb.LongTermMemorySearchResponse{Results: pbResults}, nil
}

// LongTermMemoryDelete implements the long-term memory delete RPC.
func (s *HarnessCallbackService) LongTermMemoryDelete(ctx context.Context, req *harnesspb.LongTermMemoryDeleteRequest) (*harnesspb.LongTermMemoryDeleteResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	err = harness.Memory().LongTerm().Delete(ctx, req.Id)
	if err != nil {
		return &harnesspb.LongTermMemoryDeleteResponse{
			Error: &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_INTERNAL, Message: err.Error()},
		}, nil
	}

	return &harnesspb.LongTermMemoryDeleteResponse{}, nil
}

// MissionMemorySearch implements the mission memory search RPC.
func (s *HarnessCallbackService) MissionMemorySearch(ctx context.Context, req *harnesspb.MissionMemorySearchRequest) (*harnesspb.MissionMemorySearchResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	results, err := harness.Memory().Mission().Search(ctx, req.Query, int(req.Limit))
	if err != nil {
		return &harnesspb.MissionMemorySearchResponse{
			Error: &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_INTERNAL, Message: err.Error()},
		}, nil
	}

	pbResults := make([]*harnesspb.MissionMemoryResult, len(results))
	for i, r := range results {
		typedMapMetadata := mapToTypedMap(r.Item.Metadata)
		pbResults[i] = &harnesspb.MissionMemoryResult{
			Key:       r.Item.Key,
			Value:     anyToTypedValue(r.Item.Value),
			Metadata:  typedMapMetadata.Entries,
			Score:     r.Score,
			CreatedAt: r.Item.CreatedAt.Format(time.RFC3339),
			UpdatedAt: r.Item.UpdatedAt.Format(time.RFC3339),
		}
	}

	return &harnesspb.MissionMemorySearchResponse{Results: pbResults}, nil
}

// MissionMemoryHistory implements the mission memory history RPC.
func (s *HarnessCallbackService) MissionMemoryHistory(ctx context.Context, req *harnesspb.MissionMemoryHistoryRequest) (*harnesspb.MissionMemoryHistoryResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	items, err := harness.Memory().Mission().History(ctx, int(req.Limit))
	if err != nil {
		return &harnesspb.MissionMemoryHistoryResponse{
			Error: &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_INTERNAL, Message: err.Error()},
		}, nil
	}

	pbItems := make([]*harnesspb.MissionMemoryItem, len(items))
	for i, item := range items {
		typedMapMetadata := mapToTypedMap(item.Metadata)
		pbItems[i] = &harnesspb.MissionMemoryItem{
			Key:       item.Key,
			Value:     anyToTypedValue(item.Value),
			Metadata:  typedMapMetadata.Entries,
			CreatedAt: item.CreatedAt.Format(time.RFC3339),
			UpdatedAt: item.UpdatedAt.Format(time.RFC3339),
		}
	}

	return &harnesspb.MissionMemoryHistoryResponse{Items: pbItems}, nil
}

// MissionMemoryGetPreviousRunValue implements the mission memory get previous run value RPC.
func (s *HarnessCallbackService) MissionMemoryGetPreviousRunValue(ctx context.Context, req *harnesspb.MissionMemoryGetPreviousRunValueRequest) (*harnesspb.MissionMemoryGetPreviousRunValueResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	value, err := harness.Memory().Mission().GetPreviousRunValue(ctx, req.Key)
	if err != nil {
		// Check for specific errors
		errMsg := err.Error()
		return &harnesspb.MissionMemoryGetPreviousRunValueResponse{
			Found: false,
			Error: &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_NOT_FOUND, Message: errMsg},
		}, nil
	}

	return &harnesspb.MissionMemoryGetPreviousRunValueResponse{
		Value: anyToTypedValue(value),
		Found: true,
	}, nil
}

// MissionMemoryGetValueHistory implements the mission memory get value history RPC.
func (s *HarnessCallbackService) MissionMemoryGetValueHistory(ctx context.Context, req *harnesspb.MissionMemoryGetValueHistoryRequest) (*harnesspb.MissionMemoryGetValueHistoryResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	history, err := harness.Memory().Mission().GetValueHistory(ctx, req.Key)
	if err != nil {
		return &harnesspb.MissionMemoryGetValueHistoryResponse{
			Error: &harnesspb.HarnessError{Code: commonpb.ErrorCode_ERROR_CODE_INTERNAL, Message: err.Error()},
		}, nil
	}

	pbValues := make([]*harnesspb.HistoricalValueItem, len(history))
	for i, h := range history {
		pbValues[i] = &harnesspb.HistoricalValueItem{
			Value:     anyToTypedValue(h.Value),
			RunNumber: int32(h.RunNumber),
			MissionId: h.MissionID,
			StoredAt:  h.StoredAt.Format(time.RFC3339),
		}
	}

	return &harnesspb.MissionMemoryGetValueHistoryResponse{Values: pbValues}, nil
}

// MissionMemoryContinuityMode implements the mission memory continuity mode RPC.
func (s *HarnessCallbackService) MissionMemoryContinuityMode(ctx context.Context, req *harnesspb.MissionMemoryContinuityModeRequest) (*harnesspb.MissionMemoryContinuityModeResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	mode := harness.Memory().Mission().ContinuityMode()
	return &harnesspb.MissionMemoryContinuityModeResponse{
		Mode: string(mode),
	}, nil
}

// ============================================================================
// GraphRAG Query Operations
// ============================================================================

// GraphRAGSupport interface for harnesses that support GraphRAG operations.
// The DefaultAgentHarness and MiddlewareHarness implement these methods.
type GraphRAGSupport interface {
	QueryGraphRAG(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error)
	FindSimilarAttacks(ctx context.Context, content string, topK int) ([]sdkgraphrag.AttackPattern, error)
	FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]sdkgraphrag.FindingNode, error)
	GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]sdkgraphrag.AttackChain, error)
	GetRelatedFindings(ctx context.Context, findingID string) ([]sdkgraphrag.FindingNode, error)
	StoreGraphNode(ctx context.Context, node sdkgraphrag.GraphNode) (string, error)
	CreateGraphRelationship(ctx context.Context, rel sdkgraphrag.Relationship) error
	StoreGraphBatch(ctx context.Context, batch sdkgraphrag.Batch) ([]string, error)
	TraverseGraph(ctx context.Context, startNodeID string, opts sdkgraphrag.TraversalOptions) ([]sdkgraphrag.TraversalResult, error)
	GraphRAGHealth(ctx context.Context) types.HealthStatus
}

// GraphRAGQuery implements the GraphRAG query RPC.
func (s *HarnessCallbackService) GraphRAGQuery(ctx context.Context, req *harnesspb.GraphRAGQueryRequest) (*harnesspb.GraphRAGQueryResponse, error) {
	harness, err := s.getHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Check if harness supports GraphRAG
	graphRAG, ok := harness.(GraphRAGSupport)
	if !ok {
		return &harnesspb.GraphRAGQueryResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: "GraphRAG not supported by this harness",
			},
		}, nil
	}

	// Inject MissionRunID from proto context into Go context for mission-scoped queries
	var missionRunID string
	if req.Context != nil && req.Context.MissionRunId != "" {
		missionRunID = req.Context.MissionRunId
		ctx = ContextWithMissionRunID(ctx, missionRunID)
		s.logger.Info("GraphRAGQuery: injected MissionRunID into context",
			"mission_run_id", missionRunID,
			"agent_name", req.Context.AgentName)
	} else {
		s.logger.Warn("GraphRAGQuery: no MissionRunID in request context",
			"has_context", req.Context != nil)
	}

	// Deserialize query
	query := protoQueryToSDKQuery(req.Query)

	// Ensure query has MissionRunID from context if not explicitly set in the query
	// This is the primary source of MissionRunID - the agent's callback context
	if query.MissionRunID == "" && missionRunID != "" {
		query.MissionRunID = missionRunID
		s.logger.Info("GraphRAGQuery: set query.MissionRunID from context",
			"mission_run_id", missionRunID)
	}
	if query.Text == "" && len(query.NodeTypes) == 0 {
		return &harnesspb.GraphRAGQueryResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "query must have Text or NodeTypes",
			},
		}, nil
	}

	// Execute query
	results, err := graphRAG.QueryGraphRAG(ctx, query)
	if err != nil {
		s.logger.Error("GraphRAG query failed", "error", err)
		return &harnesspb.GraphRAGQueryResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert results to proto
	protoResults := make([]*harnesspb.GraphRAGResult, len(results))
	for i, result := range results {
		protoResults[i] = &harnesspb.GraphRAGResult{
			Node:        s.graphNodeToProto(result.Node),
			Score:       result.Score,
			VectorScore: result.VectorScore,
			GraphScore:  result.GraphScore,
			Path:        result.Path,
			Distance:    int32(result.Distance),
		}
	}

	return &harnesspb.GraphRAGQueryResponse{
		Results: protoResults,
	}, nil
}

// FindSimilarAttacks implements the find similar attacks RPC.
func (s *HarnessCallbackService) FindSimilarAttacks(ctx context.Context, req *harnesspb.FindSimilarAttacksRequest) (*harnesspb.FindSimilarAttacksResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.FindSimilarAttacksResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Find similar attacks
	attacks, err := graphRAG.FindSimilarAttacks(ctx, req.Content, int(req.TopK))
	if err != nil {
		s.logger.Error("find similar attacks failed", "error", err)
		return &harnesspb.FindSimilarAttacksResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert to proto
	protoAttacks := make([]*harnesspb.AttackPattern, len(attacks))
	for i, attack := range attacks {
		protoAttacks[i] = &harnesspb.AttackPattern{
			TechniqueId: attack.TechniqueID,
			Name:        attack.Name,
			Description: attack.Description,
			Tactics:     attack.Tactics,
			Platforms:   attack.Platforms,
			Similarity:  attack.Similarity,
		}
	}

	return &harnesspb.FindSimilarAttacksResponse{
		Attacks: protoAttacks,
	}, nil
}

// FindSimilarFindings implements the find similar findings RPC.
func (s *HarnessCallbackService) FindSimilarFindings(ctx context.Context, req *harnesspb.FindSimilarFindingsRequest) (*harnesspb.FindSimilarFindingsResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.FindSimilarFindingsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Find similar findings
	findings, err := graphRAG.FindSimilarFindings(ctx, req.FindingId, int(req.TopK))
	if err != nil {
		s.logger.Error("find similar findings failed", "error", err)
		return &harnesspb.FindSimilarFindingsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert to proto
	protoFindings := make([]*harnesspb.FindingNode, len(findings))
	for i, finding := range findings {
		protoFindings[i] = &harnesspb.FindingNode{
			Id:          finding.ID,
			Title:       finding.Title,
			Description: finding.Description,
			Severity:    finding.Severity,
			Category:    finding.Category,
			Confidence:  finding.Confidence,
			Similarity:  finding.Similarity,
		}
	}

	return &harnesspb.FindSimilarFindingsResponse{
		Findings: protoFindings,
	}, nil
}

// GetAttackChains implements the get attack chains RPC.
func (s *HarnessCallbackService) GetAttackChains(ctx context.Context, req *harnesspb.GetAttackChainsRequest) (*harnesspb.GetAttackChainsResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.GetAttackChainsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Get attack chains
	chains, err := graphRAG.GetAttackChains(ctx, req.TechniqueId, int(req.MaxDepth))
	if err != nil {
		s.logger.Error("get attack chains failed", "error", err)
		return &harnesspb.GetAttackChainsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert to proto
	protoChains := make([]*harnesspb.AttackChain, len(chains))
	for i, chain := range chains {
		protoSteps := make([]*harnesspb.AttackStep, len(chain.Steps))
		for j, step := range chain.Steps {
			protoSteps[j] = &harnesspb.AttackStep{
				Order:       int32(step.Order),
				TechniqueId: step.TechniqueID,
				NodeId:      step.NodeID,
				Description: step.Description,
				Confidence:  step.Confidence,
			}
		}

		protoChains[i] = &harnesspb.AttackChain{
			Id:       chain.ID,
			Name:     chain.Name,
			Severity: chain.Severity,
			Steps:    protoSteps,
		}
	}

	return &harnesspb.GetAttackChainsResponse{
		Chains: protoChains,
	}, nil
}

// GetRelatedFindings implements the get related findings RPC.
func (s *HarnessCallbackService) GetRelatedFindings(ctx context.Context, req *harnesspb.GetRelatedFindingsRequest) (*harnesspb.GetRelatedFindingsResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.GetRelatedFindingsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Get related findings
	findings, err := graphRAG.GetRelatedFindings(ctx, req.FindingId)
	if err != nil {
		s.logger.Error("get related findings failed", "error", err)
		return &harnesspb.GetRelatedFindingsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert to proto
	protoFindings := make([]*harnesspb.FindingNode, len(findings))
	for i, finding := range findings {
		protoFindings[i] = &harnesspb.FindingNode{
			Id:          finding.ID,
			Title:       finding.Title,
			Description: finding.Description,
			Severity:    finding.Severity,
			Category:    finding.Category,
			Confidence:  finding.Confidence,
			Similarity:  finding.Similarity,
		}
	}

	return &harnesspb.GetRelatedFindingsResponse{
		Findings: protoFindings,
	}, nil
}

// ============================================================================
// GraphRAG Storage Operations
// ============================================================================

// StoreGraphNode implements the store graph node RPC.
func (s *HarnessCallbackService) StoreGraphNode(ctx context.Context, req *harnesspb.StoreGraphNodeRequest) (*harnesspb.StoreGraphNodeResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.StoreGraphNodeResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Inject all context values from proto context into Go context
	var missionRunID, agentRunID string
	if req.Context != nil {
		// Inject MissionID and AgentName for middleware (required by metadataInjector)
		if req.Context.MissionId != "" {
			ctx = middleware.WithMissionContext(ctx, req.Context.MissionId, req.Context.AgentName)
		}
		if req.Context.MissionRunId != "" {
			missionRunID = req.Context.MissionRunId
			ctx = ContextWithMissionRunID(ctx, missionRunID)
		}
		if req.Context.AgentRunId != "" {
			agentRunID = req.Context.AgentRunId
			ctx = ContextWithAgentRunID(ctx, agentRunID)
		}

		s.logger.Info("StoreGraphNode: injected context IDs",
			"mission_id", req.Context.MissionId,
			"mission_run_id", missionRunID,
			"agent_run_id", agentRunID,
			"node_type", req.Node.Type,
			"agent_name", req.Context.AgentName)
	} else {
		s.logger.Warn("StoreGraphNode: no context info in request",
			"node_type", req.Node.Type)
	}

	// Convert proto node to SDK node
	node := s.protoToGraphNode(req.Node)

	// Inject mission context metadata before storage
	if err := s.metadataInjector.Inject(ctx, &node); err != nil {
		s.logger.Error("metadata injection failed", "error", err, "node_type", req.Node.Type)
		return &harnesspb.StoreGraphNodeResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("metadata injection failed: %v", err),
			},
		}, nil
	}

	// Store node
	nodeID, err := graphRAG.StoreGraphNode(ctx, node)
	if err != nil {
		s.logger.Error("store graph node failed", "error", err)
		return &harnesspb.StoreGraphNodeResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	return &harnesspb.StoreGraphNodeResponse{
		NodeId: nodeID,
	}, nil
}

// CreateGraphRelationship implements the create graph relationship RPC.
func (s *HarnessCallbackService) CreateGraphRelationship(ctx context.Context, req *harnesspb.CreateGraphRelationshipRequest) (*harnesspb.CreateGraphRelationshipResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.CreateGraphRelationshipResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert proto relationship to SDK relationship
	rel := s.protoToRelationship(req.Relationship)

	// Create relationship
	if err := graphRAG.CreateGraphRelationship(ctx, rel); err != nil {
		s.logger.Error("create graph relationship failed", "error", err)
		return &harnesspb.CreateGraphRelationshipResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	return &harnesspb.CreateGraphRelationshipResponse{}, nil
}

// StoreGraphBatch implements the store graph batch RPC.
func (s *HarnessCallbackService) StoreGraphBatch(ctx context.Context, req *harnesspb.StoreGraphBatchRequest) (*harnesspb.StoreGraphBatchResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.StoreGraphBatchResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Inject all context values from proto context into Go context for mission-scoped storage
	if req.Context != nil {
		// Inject MissionID and AgentName for middleware (required by metadataInjector)
		if req.Context.MissionId != "" {
			ctx = middleware.WithMissionContext(ctx, req.Context.MissionId, req.Context.AgentName)
		}
		if req.Context.MissionRunId != "" {
			ctx = ContextWithMissionRunID(ctx, req.Context.MissionRunId)
		}
		if req.Context.AgentRunId != "" {
			ctx = ContextWithAgentRunID(ctx, req.Context.AgentRunId)
		}
		s.logger.Info("StoreGraphBatch: injected context IDs",
			"mission_id", req.Context.MissionId,
			"mission_run_id", req.Context.MissionRunId,
			"agent_run_id", req.Context.AgentRunId,
			"node_count", len(req.Nodes),
			"agent_name", req.Context.AgentName)
	} else {
		s.logger.Warn("StoreGraphBatch: no context info in request",
			"node_count", len(req.Nodes))
	}

	// Convert proto batch to SDK batch
	batch := sdkgraphrag.Batch{
		Nodes:         make([]sdkgraphrag.GraphNode, len(req.Nodes)),
		Relationships: make([]sdkgraphrag.Relationship, len(req.Relationships)),
	}

	for i, protoNode := range req.Nodes {
		node := s.protoToGraphNode(protoNode)

		// Inject mission context metadata before storage
		if err := s.metadataInjector.Inject(ctx, &node); err != nil {
			s.logger.Error("metadata injection failed in batch",
				"error", err,
				"node_type", protoNode.Type,
				"node_index", i)
			return &harnesspb.StoreGraphBatchResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
					Message: fmt.Sprintf("metadata injection failed for node %d: %v", i, err),
				},
			}, nil
		}

		batch.Nodes[i] = node
	}

	for i, protoRel := range req.Relationships {
		batch.Relationships[i] = s.protoToRelationship(protoRel)
	}

	// Store batch
	nodeIDs, err := graphRAG.StoreGraphBatch(ctx, batch)
	if err != nil {
		s.logger.Error("store graph batch failed", "error", err)
		return &harnesspb.StoreGraphBatchResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	return &harnesspb.StoreGraphBatchResponse{
		NodeIds: nodeIDs,
	}, nil
}

// TraverseGraph implements the traverse graph RPC.
func (s *HarnessCallbackService) TraverseGraph(ctx context.Context, req *harnesspb.TraverseGraphRequest) (*harnesspb.TraverseGraphResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.TraverseGraphResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert proto options to SDK options
	opts := sdkgraphrag.TraversalOptions{
		MaxDepth:          int(req.Options.MaxDepth),
		RelationshipTypes: req.Options.RelationshipTypes,
		NodeTypes:         req.Options.NodeTypes,
		Direction:         req.Options.Direction,
	}

	// Traverse graph
	results, err := graphRAG.TraverseGraph(ctx, req.StartNodeId, opts)
	if err != nil {
		s.logger.Error("traverse graph failed", "error", err)
		return &harnesspb.TraverseGraphResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert results to proto
	protoResults := make([]*harnesspb.TraversalResult, len(results))
	for i, result := range results {
		protoResults[i] = &harnesspb.TraversalResult{
			Node:     s.graphNodeToProto(result.Node),
			Path:     result.Path,
			Distance: int32(result.Distance),
		}
	}

	return &harnesspb.TraverseGraphResponse{
		Results: protoResults,
	}, nil
}

// GraphRAGHealth implements the GraphRAG health check RPC.
func (s *HarnessCallbackService) GraphRAGHealth(ctx context.Context, req *harnesspb.GraphRAGHealthRequest) (*harnesspb.GraphRAGHealthResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return nil, err
	}

	// Get health status
	healthStatus := graphRAG.GraphRAGHealth(ctx)

	return &harnesspb.GraphRAGHealthResponse{
		Status: &harnesspb.HarnessHealthStatus{
			State:   string(healthStatus.State),
			Message: healthStatus.Message,
		},
	}, nil
}

// ============================================================================
// Distributed Tracing Operations
// ============================================================================

// RecordSpan implements the span recording RPC for distributed tracing.
// It receives spans from remote agents and forwards them to registered span processors.
func (s *HarnessCallbackService) RecordSpan(ctx context.Context, req *harnesspb.RecordSpanRequest) (*harnesspb.RecordSpanResponse, error) {
	if req.Span == nil {
		return &harnesspb.RecordSpanResponse{}, nil
	}

	// Convert proto span to span data and export
	spanData := s.protoToSpanData(req.Span)
	s.exportSpanData(spanData)

	return &harnesspb.RecordSpanResponse{}, nil
}

// RecordSpans implements the batch span recording RPC for distributed tracing.
// It receives multiple spans from remote agents and forwards them to registered span processors.
func (s *HarnessCallbackService) RecordSpans(ctx context.Context, req *harnesspb.RecordSpansRequest) (*harnesspb.RecordSpansResponse, error) {
	for _, protoSpan := range req.Spans {
		if protoSpan == nil {
			continue
		}

		// Convert proto span to span data and export
		spanData := s.protoToSpanData(protoSpan)
		s.exportSpanData(spanData)
	}

	return &harnesspb.RecordSpansResponse{}, nil
}

// exportSpanData creates a real span using the TracerProvider and immediately ends it.
// This allows the span to be processed by registered span processors.
func (s *HarnessCallbackService) exportSpanData(data *proxySpanData) {
	if data == nil || s.tracerProvider == nil {
		return
	}

	// Create parent context with the original trace context
	parentCtx := trace.ContextWithSpanContext(context.Background(), data.Parent)

	// Get tracer from the provider
	tracer := s.tracerProvider.Tracer("gibson-agent-proxy")

	// Create span with original attributes and timing
	_, span := tracer.Start(parentCtx, data.Name,
		trace.WithSpanKind(data.SpanKind),
		trace.WithTimestamp(data.StartTime),
		trace.WithAttributes(data.Attributes...),
	)

	// Add events
	for _, event := range data.Events {
		span.AddEvent(event.Name, trace.WithTimestamp(event.Time), trace.WithAttributes(event.Attributes...))
	}

	// Set status
	span.SetStatus(otelcodes.Code(data.Status.Code), data.Status.Description)

	// End span with original end time
	span.End(trace.WithTimestamp(data.EndTime))
}

// ============================================================================
// Helper Methods for Proto Conversions
// ============================================================================

func (s *HarnessCallbackService) protoToMessages(protoMessages []*harnesspb.LLMMessage) []llm.Message {
	messages := make([]llm.Message, len(protoMessages))
	for i, protoMsg := range protoMessages {
		msg := llm.Message{
			Role:    llm.Role(protoMsg.Role),
			Content: protoMsg.Content,
			Name:    protoMsg.Name,
		}

		if len(protoMsg.ToolCalls) > 0 {
			msg.ToolCalls = make([]llm.ToolCall, len(protoMsg.ToolCalls))
			for j, protoCall := range protoMsg.ToolCalls {
				msg.ToolCalls[j] = llm.ToolCall{
					ID:        protoCall.Id,
					Name:      protoCall.Name,
					Arguments: protoCall.Arguments,
				}
			}
		}

		// Note: proto has ToolResults but internal llm.Message doesn't have ToolResults
		// Tool results are represented differently in the internal API

		messages[i] = msg
	}
	return messages
}

func (s *HarnessCallbackService) toolCallsToProto(calls []llm.ToolCall) []*harnesspb.ToolCall {
	protoCalls := make([]*harnesspb.ToolCall, len(calls))
	for i, call := range calls {
		protoCalls[i] = &harnesspb.ToolCall{
			Id:        call.ID,
			Name:      call.Name,
			Arguments: call.Arguments,
		}
	}
	return protoCalls
}

func (s *HarnessCallbackService) protoToToolDefs(protoTools []*harnesspb.ToolDef) []llm.ToolDef {
	tools := make([]llm.ToolDef, len(protoTools))
	for i, protoTool := range protoTools {
		// Convert JSONSchemaNode to schema.JSON
		var params schema.JSON
		if protoTool.Parameters != nil {
			params = CallbackProtoToSchema(protoTool.Parameters)
		}

		tools[i] = llm.ToolDef{
			Name:        protoTool.Name,
			Description: protoTool.Description,
			Parameters:  params,
		}
	}
	return tools
}

func (s *HarnessCallbackService) graphNodeToProto(node sdkgraphrag.GraphNode) *harnesspb.GraphNode {
	typedMapProps := mapToTypedMap(node.Properties)
	return &harnesspb.GraphNode{
		Id:         node.ID,
		Type:       node.Type,
		Properties: typedMapProps.Entries,
		Content:    node.Content,
		MissionId:  node.MissionID,
		AgentName:  node.AgentName,
		CreatedAt:  node.CreatedAt.Unix(),
		UpdatedAt:  node.UpdatedAt.Unix(),
	}
}

func (s *HarnessCallbackService) protoToGraphNode(protoNode *harnesspb.GraphNode) sdkgraphrag.GraphNode {
	props := typedValueMapToMap(protoNode.Properties)

	return sdkgraphrag.GraphNode{
		ID:         protoNode.Id,
		Type:       protoNode.Type,
		Properties: props,
		Content:    protoNode.Content,
		MissionID:  protoNode.MissionId,
		AgentName:  protoNode.AgentName,
	}
}

func (s *HarnessCallbackService) protoToRelationship(protoRel *harnesspb.Relationship) sdkgraphrag.Relationship {
	props := typedValueMapToMap(protoRel.Properties)

	return sdkgraphrag.Relationship{
		FromID:        protoRel.FromId,
		ToID:          protoRel.ToId,
		Type:          protoRel.Type,
		Properties:    props,
		Bidirectional: protoRel.Bidirectional,
	}
}

// protoToSpanData converts a proto Span to a proxySpanData container.
// Since sdktrace.ReadOnlySpan has an unexported method, we can't implement it directly.
// Instead, we extract the data and export it directly via the Langfuse exporter.
func (s *HarnessCallbackService) protoToSpanData(protoSpan *harnesspb.Span) *proxySpanData {
	// Parse trace ID and span ID from hex strings
	var traceID trace.TraceID
	var spanID trace.SpanID
	var parentSpanID trace.SpanID

	// Convert hex string to TraceID (16 bytes)
	if len(protoSpan.TraceId) == 32 {
		for i := 0; i < 16; i++ {
			_, _ = fmt.Sscanf(protoSpan.TraceId[i*2:i*2+2], "%02x", &traceID[i])
		}
	}

	// Convert hex string to SpanID (8 bytes)
	if len(protoSpan.SpanId) == 16 {
		for i := 0; i < 8; i++ {
			_, _ = fmt.Sscanf(protoSpan.SpanId[i*2:i*2+2], "%02x", &spanID[i])
		}
	}

	// Convert parent span ID if present
	hasParent := false
	if len(protoSpan.ParentSpanId) == 16 {
		hasParent = true
		for i := 0; i < 8; i++ {
			_, _ = fmt.Sscanf(protoSpan.ParentSpanId[i*2:i*2+2], "%02x", &parentSpanID[i])
		}
	}

	// Create span context
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  spanID,
	})

	// Create parent span context
	var parentContext trace.SpanContext
	if hasParent {
		parentContext = trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: traceID,
			SpanID:  parentSpanID,
		})
	}

	// Create proxy span data container
	return s.createProxySpanData(
		protoSpan.Name,
		spanContext,
		parentContext,
		s.protoSpanKindToOtel(protoSpan.Kind),
		time.Unix(0, protoSpan.StartTimeUnixNano),
		time.Unix(0, protoSpan.EndTimeUnixNano),
		s.protoAttributesToOtel(protoSpan.Attributes),
		s.protoEventsToOtel(protoSpan.Events),
		sdktrace.Status{
			Code:        s.protoStatusCodeToOtel(protoSpan.StatusCode),
			Description: protoSpan.StatusMessage,
		},
	)
}

// protoSpanKindToOtel converts proto SpanKind to OpenTelemetry SpanKind.
func (s *HarnessCallbackService) protoSpanKindToOtel(kind harnesspb.SpanKind) trace.SpanKind {
	switch kind {
	case harnesspb.SpanKind_SPAN_KIND_INTERNAL:
		return trace.SpanKindInternal
	case harnesspb.SpanKind_SPAN_KIND_SERVER:
		return trace.SpanKindServer
	case harnesspb.SpanKind_SPAN_KIND_CLIENT:
		return trace.SpanKindClient
	case harnesspb.SpanKind_SPAN_KIND_PRODUCER:
		return trace.SpanKindProducer
	case harnesspb.SpanKind_SPAN_KIND_CONSUMER:
		return trace.SpanKindConsumer
	default:
		return trace.SpanKindUnspecified
	}
}

// protoStatusCodeToOtel converts proto StatusCode to OpenTelemetry status code.
func (s *HarnessCallbackService) protoStatusCodeToOtel(code harnesspb.StatusCode) otelcodes.Code {
	switch code {
	case harnesspb.StatusCode_STATUS_CODE_OK:
		return otelcodes.Ok
	case harnesspb.StatusCode_STATUS_CODE_ERROR:
		return otelcodes.Error
	default:
		return otelcodes.Unset
	}
}

// protoAttributesToOtel converts proto KeyValue attributes to OpenTelemetry attributes.
func (s *HarnessCallbackService) protoAttributesToOtel(protoAttrs []*harnesspb.KeyValue) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(protoAttrs))
	for _, protoAttr := range protoAttrs {
		if protoAttr.Value == nil {
			continue
		}

		key := attribute.Key(protoAttr.Key)
		// Handle different value types from AnyValue
		switch v := protoAttr.Value.Value.(type) {
		case *harnesspb.AnyValue_StringValue:
			attrs = append(attrs, key.String(v.StringValue))
		case *harnesspb.AnyValue_BoolValue:
			attrs = append(attrs, key.Bool(v.BoolValue))
		case *harnesspb.AnyValue_IntValue:
			attrs = append(attrs, key.Int64(v.IntValue))
		case *harnesspb.AnyValue_DoubleValue:
			attrs = append(attrs, key.Float64(v.DoubleValue))
		}
	}
	return attrs
}

// protoEventsToOtel converts proto SpanEvents to OpenTelemetry Events.
func (s *HarnessCallbackService) protoEventsToOtel(protoEvents []*harnesspb.SpanEvent) []sdktrace.Event {
	events := make([]sdktrace.Event, len(protoEvents))
	for i, protoEvent := range protoEvents {
		events[i] = sdktrace.Event{
			Name:       protoEvent.Name,
			Time:       time.Unix(0, protoEvent.TimeUnixNano),
			Attributes: s.protoAttributesToOtel(protoEvent.Attributes),
		}
	}
	return events
}

// ============================================================================
// Span Data Container
// ============================================================================

// proxySpanData contains the data extracted from a proto span for export.
// Since sdktrace.ReadOnlySpan has an unexported private() method that prevents
// external implementation, we store the span data and export directly to Langfuse.
type proxySpanData struct {
	Name        string
	SpanContext trace.SpanContext
	Parent      trace.SpanContext
	SpanKind    trace.SpanKind
	StartTime   time.Time
	EndTime     time.Time
	Attributes  []attribute.KeyValue
	Events      []sdktrace.Event
	Status      sdktrace.Status
}

// createProxySpanData creates a proxySpanData from the proto span data.
func (s *HarnessCallbackService) createProxySpanData(
	name string,
	spanContext trace.SpanContext,
	parent trace.SpanContext,
	spanKind trace.SpanKind,
	startTime time.Time,
	endTime time.Time,
	attributes []attribute.KeyValue,
	events []sdktrace.Event,
	status sdktrace.Status,
) *proxySpanData {
	return &proxySpanData{
		Name:        name,
		SpanContext: spanContext,
		Parent:      parent,
		SpanKind:    spanKind,
		StartTime:   startTime,
		EndTime:     endTime,
		Attributes:  attributes,
		Events:      events,
		Status:      status,
	}
}

// ============================================================================
// Credential Operations
// ============================================================================

// GetCredential retrieves a credential by name from the credential store.
// The credential is decrypted and returned with its secret value.
func (s *HarnessCallbackService) GetCredential(ctx context.Context, req *harnesspb.GetCredentialRequest) (*harnesspb.GetCredentialResponse, error) {
	// Validate context
	if req.Context == nil {
		return &harnesspb.GetCredentialResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "missing context info in request",
			},
		}, nil
	}

	// Log request
	s.logger.Debug("GetCredential request",
		"name", req.Name,
		"mission_id", req.Context.MissionId,
		"agent_name", req.Context.AgentName,
	)

	// Check if credential store is configured
	if s.credentialStore == nil {
		s.logger.Warn("GetCredential called but credential store not configured")
		return &harnesspb.GetCredentialResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "credential store not available",
			},
		}, nil
	}

	// Retrieve credential. DaemonCredentialStore delegates to secrets.Service
	// which returns gRPC status errors. Map them to the appropriate HarnessError
	// code so callers can distinguish not-found from service-unavailable.
	cred, secret, err := s.credentialStore.GetCredential(ctx, req.Name)
	if err != nil {
		s.logger.Warn("GetCredential failed", "name", req.Name, "error", err)
		errCode := commonpb.ErrorCode_ERROR_CODE_NOT_FOUND
		if st, ok := status.FromError(err); ok {
			switch st.Code() {
			case codes.Unavailable:
				errCode = commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE
			case codes.PermissionDenied:
				errCode = commonpb.ErrorCode_ERROR_CODE_PERMISSION_DENIED
			case codes.InvalidArgument:
				errCode = commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
			case codes.NotFound:
				errCode = commonpb.ErrorCode_ERROR_CODE_NOT_FOUND
			default:
				errCode = commonpb.ErrorCode_ERROR_CODE_INTERNAL
			}
		}
		return &harnesspb.GetCredentialResponse{
			Error: &harnesspb.HarnessError{
				Code:    errCode,
				Message: fmt.Sprintf("credential %q: %v", req.Name, err),
			},
		}, nil
	}

	// Map internal credential type to proto type
	var credType harnesspb.CredentialType
	switch cred.Type {
	case types.CredentialTypeAPIKey:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_API_KEY
	case types.CredentialTypeBearer:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_BEARER
	case types.CredentialTypeBasic:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_BASIC
	case types.CredentialTypeOAuth:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_OAUTH
	case types.CredentialTypeCustom:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_CUSTOM
	default:
		credType = harnesspb.CredentialType_CREDENTIAL_TYPE_API_KEY
	}

	s.logger.Debug("GetCredential succeeded", "name", req.Name)

	// Build credential with oneof secret_data based on type
	pbCred := &harnesspb.Credential{
		Name:     cred.Name,
		Type:     credType,
		Metadata: mapToTypedValueMap(map[string]any{"provider": cred.Provider, "tags": cred.Tags}),
	}

	// Set secret using oneof field based on credential type
	switch credType {
	case harnesspb.CredentialType_CREDENTIAL_TYPE_API_KEY:
		pbCred.SecretData = &harnesspb.Credential_ApiKey{ApiKey: secret}
	case harnesspb.CredentialType_CREDENTIAL_TYPE_BEARER:
		pbCred.SecretData = &harnesspb.Credential_BearerToken{BearerToken: secret}
	case harnesspb.CredentialType_CREDENTIAL_TYPE_CUSTOM:
		pbCred.SecretData = &harnesspb.Credential_CustomSecret{CustomSecret: secret}
	default:
		pbCred.SecretData = &harnesspb.Credential_ApiKey{ApiKey: secret}
	}

	return &harnesspb.GetCredentialResponse{
		Credential: pbCred,
	}, nil
}

// ============================================================================
// Helper Methods for Taxonomy Engine Integration
// ============================================================================

// extractAgentRunID extracts the agent run ID from context.
// Tries multiple sources: trace span ID, mission ID, task ID, or generates a fallback.
func (s *HarnessCallbackService) extractAgentRunID(ctx context.Context, contextInfo *harnesspb.ContextInfo) string {
	// Priority 1: Use trace span ID if available (most specific)
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}

	// Priority 2: Use task ID if available (unique per execution)
	if contextInfo != nil && contextInfo.TaskId != "" {
		return contextInfo.TaskId
	}

	// Priority 3: Use mission ID (less specific but still useful)
	if contextInfo != nil && contextInfo.MissionId != "" {
		return contextInfo.MissionId
	}

	// Fallback: Generate a unique ID
	return uuid.New().String()
}

// publishEvent publishes an event to the event bus if configured.
// This is a helper method that safely publishes events without blocking
// callback responses. Events are published in a goroutine to avoid latency.
func (s *HarnessCallbackService) publishEvent(ctx context.Context, eventType string, data map[string]interface{}) {
	if s.eventBus == nil {
		return // Event bus not configured, skip
	}

	// Extract trace context from OpenTelemetry span
	var traceID, spanID, parentSpanID string
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		spanCtx := span.SpanContext()
		traceID = spanCtx.TraceID().String()
		spanID = spanCtx.SpanID().String()
	}

	// Extract parent_span_id from data if provided (for relationship creation)
	// This is passed explicitly by callers who know their parent span
	if psid, ok := data["parent_span_id"].(string); ok {
		parentSpanID = psid
	}

	// IMPORTANT: Add trace context to data map for taxonomy engine
	// The taxonomy engine reads from data map, not the event struct fields
	// This ensures LLMCall, ToolExecution nodes can create relationships
	timestamp := time.Now()
	data["trace_id"] = traceID
	data["span_id"] = spanID
	data["parent_span_id"] = parentSpanID
	data["timestamp"] = timestamp.Format(time.RFC3339Nano)

	// Create event structure matching daemon.GraphEvent
	event := struct {
		Type         string
		TraceID      string
		SpanID       string
		ParentSpanID string
		Timestamp    time.Time
		Data         map[string]interface{}
	}{
		Type:         eventType,
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		Timestamp:    timestamp,
		Data:         data,
	}

	// Publish in background to avoid blocking the callback response
	// Use timeout context to prevent goroutine leaks while still allowing
	// publish to complete after request context is cancelled
	go func() {
		pubCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.eventBus.Publish(pubCtx, event); err != nil {
			// Don't log context.Canceled - expected when request is cancelled
			if !errors.Is(err, context.Canceled) {
				s.logger.Warn("failed to publish event",
					"event_type", eventType,
					"error", err,
				)
			}
		}
	}()
}

// ============================================================================
// Taxonomy Operations
// ============================================================================

// GetTaxonomySchema returns the full taxonomy schema to agents.
// NOTE: Taxonomy has been removed. This returns an empty response.
func (s *HarnessCallbackService) GetTaxonomySchema(ctx context.Context, req *harnesspb.GetTaxonomySchemaRequest) (*harnesspb.GetTaxonomySchemaResponse, error) {
	s.logger.Debug("GetTaxonomySchema called (taxonomy removed)")
	return &harnesspb.GetTaxonomySchemaResponse{
		Version: "0.0.0",
	}, nil
}

// GenerateNodeID generates a deterministic node ID.
// NOTE: Taxonomy has been removed. Use domain types instead which generate their own IDs.
func (s *HarnessCallbackService) GenerateNodeID(ctx context.Context, req *harnesspb.GenerateNodeIDRequest) (*harnesspb.GenerateNodeIDResponse, error) {
	s.logger.Debug("GenerateNodeID called (taxonomy removed)")
	return &harnesspb.GenerateNodeIDResponse{
		Error: &harnesspb.HarnessError{
			Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
			Message: "taxonomy has been removed; use domain types which generate their own IDs",
		},
	}, nil
}

// ValidateFinding validates a finding.
// NOTE: Taxonomy-based validation has been removed. Basic validation is still performed.
func (s *HarnessCallbackService) ValidateFinding(ctx context.Context, req *harnesspb.ValidateFindingRequest) (*harnesspb.ValidateFindingResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request cannot be nil")
	}

	s.logger.Debug("ValidateFinding called")

	// Convert proto finding to SDK finding
	finding := protoFindingToSDKFinding(req.Finding)
	if finding == nil {
		return &harnesspb.ValidateFindingResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "finding cannot be nil",
			},
		}, nil
	}

	resp := &harnesspb.ValidateFindingResponse{Valid: true}

	// Validate severity
	validSeverities := []string{"critical", "high", "medium", "low", "informational"}
	severityValid := false
	for _, sev := range validSeverities {
		if string(finding.Severity) == sev {
			severityValid = true
			break
		}
	}
	if !severityValid && finding.Severity != "" {
		resp.Valid = false
		resp.Errors = append(resp.Errors, &harnesspb.ValidationError{
			Field:   "severity",
			Message: fmt.Sprintf("invalid severity: %s", finding.Severity),
			Code:    "INVALID_ENUM",
		})
	}

	// Validate required fields
	if finding.Title == "" {
		resp.Valid = false
		resp.Errors = append(resp.Errors, &harnesspb.ValidationError{
			Field:   "title",
			Message: "title is required",
			Code:    "MISSING_REQUIRED",
		})
	}

	s.logger.Debug("ValidateFinding completed", "valid", resp.Valid, "errors", len(resp.Errors))

	return resp, nil
}

// ValidateGraphNode validates a graph node.
// NOTE: Taxonomy-based validation has been removed. Returns success with a warning.
func (s *HarnessCallbackService) ValidateGraphNode(ctx context.Context, req *harnesspb.ValidateGraphNodeRequest) (*harnesspb.ValidateGraphNodeResponse, error) {
	s.logger.Debug("ValidateGraphNode called (taxonomy removed)")
	return &harnesspb.ValidateGraphNodeResponse{
		Valid:    true,
		Warnings: []string{"taxonomy-based validation has been removed; use domain types for type-safe node creation"},
	}, nil
}

// ValidateRelationship validates a relationship.
// NOTE: Taxonomy-based validation has been removed. Returns success with a warning.
func (s *HarnessCallbackService) ValidateRelationship(ctx context.Context, req *harnesspb.ValidateRelationshipRequest) (*harnesspb.ValidateRelationshipResponse, error) {
	s.logger.Debug("ValidateRelationship called (taxonomy removed)")
	return &harnesspb.ValidateRelationshipResponse{
		Valid:    true,
		Warnings: []string{"taxonomy-based validation has been removed; use domain types for type-safe relationship creation"},
	}, nil
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

// typedValueToAny converts a proto TypedValue to a Go any value.
func typedValueToAny(tv *commonpb.TypedValue) any {
	if tv == nil {
		return nil
	}

	switch kind := tv.Kind.(type) {
	case *commonpb.TypedValue_NullValue:
		return nil
	case *commonpb.TypedValue_StringValue:
		return kind.StringValue
	case *commonpb.TypedValue_IntValue:
		return kind.IntValue
	case *commonpb.TypedValue_DoubleValue:
		return kind.DoubleValue
	case *commonpb.TypedValue_BoolValue:
		return kind.BoolValue
	case *commonpb.TypedValue_BytesValue:
		return kind.BytesValue
	case *commonpb.TypedValue_ArrayValue:
		if kind.ArrayValue == nil {
			return []any{}
		}
		result := make([]any, len(kind.ArrayValue.Items))
		for i, item := range kind.ArrayValue.Items {
			result[i] = typedValueToAny(item)
		}
		return result
	case *commonpb.TypedValue_MapValue:
		if kind.MapValue == nil {
			return map[string]any{}
		}
		result := make(map[string]any)
		for k, v := range kind.MapValue.Entries {
			result[k] = typedValueToAny(v)
		}
		return result
	default:
		return nil
	}
}

// ============================================================================
// Proto Conversion Helpers
// ============================================================================

// typedValueMapToMap converts map[string]*TypedValue to map[string]any.
func typedValueMapToMap(m map[string]*commonpb.TypedValue) map[string]any {
	if m == nil {
		return make(map[string]any)
	}

	result := make(map[string]any)
	for k, v := range m {
		result[k] = typedValueToAny(v)
	}
	return result
}

// protoTaskToTask converts a proto Task to an internal agent.Task.
func protoTaskToTask(pt *typespb.Task) agent.Task {
	if pt == nil {
		return agent.Task{}
	}

	task := agent.Task{
		Goal:    pt.Goal,
		Context: typedValueMapToMap(pt.Context),
	}

	// Parse ID if present
	if pt.Id != "" {
		if id, err := uuid.Parse(pt.Id); err == nil {
			task.ID = types.ID(id.String())
		}
	}

	// Extract metadata fields
	if pt.Metadata != nil {
		if nameVal := pt.Metadata["name"]; nameVal != nil {
			if name, ok := typedValueToAny(nameVal).(string); ok {
				task.Name = name
			}
		}
		if descVal := pt.Metadata["description"]; descVal != nil {
			if desc, ok := typedValueToAny(descVal).(string); ok {
				task.Description = desc
			}
		}
		if timeoutVal := pt.Metadata["timeout_ms"]; timeoutVal != nil {
			if timeoutMs, ok := typedValueToAny(timeoutVal).(int64); ok {
				task.Timeout = time.Duration(timeoutMs) * time.Millisecond
			}
		}
		if missionIDVal := pt.Metadata["mission_id"]; missionIDVal != nil {
			if missionIDStr, ok := typedValueToAny(missionIDVal).(string); ok {
				if id, err := uuid.Parse(missionIDStr); err == nil {
					missionID := types.ID(id.String())
					task.MissionID = &missionID
				}
			}
		}
		if parentTaskIDVal := pt.Metadata["parent_task_id"]; parentTaskIDVal != nil {
			if parentTaskIDStr, ok := typedValueToAny(parentTaskIDVal).(string); ok {
				if id, err := uuid.Parse(parentTaskIDStr); err == nil {
					parentTaskID := types.ID(id.String())
					task.ParentTaskID = &parentTaskID
				}
			}
		}
		if targetIDVal := pt.Metadata["target_id"]; targetIDVal != nil {
			if targetIDStr, ok := typedValueToAny(targetIDVal).(string); ok {
				if id, err := uuid.Parse(targetIDStr); err == nil {
					targetID := types.ID(id.String())
					task.TargetID = &targetID
				}
			}
		}
	}

	return task
}

// resultToProtoResult converts an internal agent.Result to a proto Result.
func resultToProtoResult(r agent.Result) *typespb.Result {
	result := &typespb.Result{
		Status: resultStatusToProtoStatus(r.Status),
		Output: mapToTypedValue(r.Output),
	}

	if r.Error != nil {
		// Convert error code string to ErrorCode enum
		errCode := commonpb.ErrorCode_ERROR_CODE_INTERNAL
		if codeVal, ok := commonpb.ErrorCode_value["ERROR_CODE_"+r.Error.Code]; ok {
			errCode = commonpb.ErrorCode(codeVal)
		}
		result.Error = &typespb.ResultError{
			Message:   r.Error.Message,
			Code:      errCode,
			Details:   convertMapStringAnyToMapStringString(r.Error.Details),
			Retryable: r.Error.Recoverable,
		}
	}

	return result
}

// resultStatusToProtoStatus converts an internal ResultStatus to proto ResultStatus.
func resultStatusToProtoStatus(status agent.ResultStatus) typespb.ResultStatus {
	switch status {
	case agent.ResultStatusPending:
		return typespb.ResultStatus_RESULT_STATUS_UNSPECIFIED
	case agent.ResultStatusCompleted:
		return typespb.ResultStatus_RESULT_STATUS_SUCCESS
	case agent.ResultStatusFailed:
		return typespb.ResultStatus_RESULT_STATUS_FAILED
	case agent.ResultStatusCancelled:
		return typespb.ResultStatus_RESULT_STATUS_CANCELLED
	default:
		return typespb.ResultStatus_RESULT_STATUS_FAILED
	}
}

// mapToTypedValue converts a map[string]any to a proto TypedValue containing a TypedMap.
func mapToTypedValue(m map[string]any) *commonpb.TypedValue {
	if m == nil {
		return &commonpb.TypedValue{
			Kind: &commonpb.TypedValue_MapValue{
				MapValue: &commonpb.TypedMap{Entries: make(map[string]*commonpb.TypedValue)},
			},
		}
	}

	entries := make(map[string]*commonpb.TypedValue)
	for k, v := range m {
		entries[k] = anyToTypedValue(v)
	}

	return &commonpb.TypedValue{
		Kind: &commonpb.TypedValue_MapValue{
			MapValue: &commonpb.TypedMap{Entries: entries},
		},
	}
}

// convertMapStringAnyToMapStringString converts map[string]any to map[string]string for Error.Details.
func convertMapStringAnyToMapStringString(m map[string]any) map[string]string {
	if m == nil {
		return nil
	}
	result := make(map[string]string)
	for k, v := range m {
		if str, ok := v.(string); ok {
			result[k] = str
		} else {
			result[k] = fmt.Sprintf("%v", v)
		}
	}
	return result
}

// mapToTypedValueMap converts a map[string]any to a map[string]*commonpb.TypedValue.
func mapToTypedValueMap(m map[string]any) map[string]*commonpb.TypedValue {
	if m == nil {
		return make(map[string]*commonpb.TypedValue)
	}

	result := make(map[string]*commonpb.TypedValue)
	for k, v := range m {
		result[k] = anyToTypedValue(v)
	}
	return result
}

// protoFindingToSDKFinding converts a proto Finding to an SDK finding.Finding.
func protoFindingToSDKFinding(pf *typespb.Finding) *sdkfinding.Finding {
	if pf == nil {
		return nil
	}

	finding := &sdkfinding.Finding{
		ID:          pf.Id,
		MissionID:   pf.MissionId,
		AgentName:   pf.AgentName,
		Title:       pf.Title,
		Description: pf.Description,
		Category:    pf.Category, // Category is now a plain string
		Subcategory: pf.Subcategory,
		Severity:    protoSeverityToSDKSeverity(pf.Severity),
		Confidence:  pf.Confidence,
		TargetID:    pf.TargetId,
		Technique:   pf.Technique,
		Tags:        pf.Tags,
		Remediation: pf.Remediation,
		References:  pf.References,
	}

	// Convert Evidence
	if len(pf.Evidence) > 0 {
		finding.Evidence = make([]sdkfinding.Evidence, len(pf.Evidence))
		for i, ev := range pf.Evidence {
			finding.Evidence[i] = sdkfinding.Evidence{
				Type:    protoEvidenceTypeToSDK(ev.Type),
				Title:   ev.Title,
				Content: ev.Content,
			}
			// Convert metadata if present
			if len(ev.Metadata) > 0 {
				finding.Evidence[i].Metadata = make(map[string]any)
				for k, v := range ev.Metadata {
					finding.Evidence[i].Metadata[k] = v
				}
			}
		}
	}

	// Convert Reproduction steps
	if len(pf.Reproduction) > 0 {
		finding.Reproduction = make([]sdkfinding.ReproStep, len(pf.Reproduction))
		for i, rs := range pf.Reproduction {
			finding.Reproduction[i] = sdkfinding.ReproStep{
				Order:       int(rs.Order),
				Description: rs.Description,
				Input:       rs.Input,
				Output:      rs.Output,
			}
		}
	}

	// Convert CVSS score
	if pf.CvssScore > 0 {
		finding.CVSSScore = &pf.CvssScore
	}

	finding.RiskScore = pf.RiskScore

	// Convert timestamps
	if pf.CreatedAt > 0 {
		finding.CreatedAt = time.Unix(0, pf.CreatedAt*int64(time.Millisecond))
	}
	if pf.UpdatedAt > 0 {
		finding.UpdatedAt = time.Unix(0, pf.UpdatedAt*int64(time.Millisecond))
	}

	return finding
}

// protoSeverityToSDKSeverity converts a proto FindingSeverity to an SDK Severity.
func protoSeverityToSDKSeverity(severity typespb.FindingSeverity) sdkfinding.Severity {
	switch severity {
	case typespb.FindingSeverity_FINDING_SEVERITY_CRITICAL:
		return sdkfinding.SeverityCritical
	case typespb.FindingSeverity_FINDING_SEVERITY_HIGH:
		return sdkfinding.SeverityHigh
	case typespb.FindingSeverity_FINDING_SEVERITY_MEDIUM:
		return sdkfinding.SeverityMedium
	case typespb.FindingSeverity_FINDING_SEVERITY_LOW:
		return sdkfinding.SeverityLow
	case typespb.FindingSeverity_FINDING_SEVERITY_INFO:
		return sdkfinding.SeverityInfo
	default:
		return sdkfinding.SeverityInfo
	}
}

// protoEvidenceTypeToSDK converts a proto EvidenceType to an SDK EvidenceType.
func protoEvidenceTypeToSDK(evidenceType typespb.EvidenceType) sdkfinding.EvidenceType {
	switch evidenceType {
	case typespb.EvidenceType_EVIDENCE_TYPE_REQUEST:
		return sdkfinding.EvidenceHTTPRequest
	case typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE:
		return sdkfinding.EvidenceHTTPResponse
	case typespb.EvidenceType_EVIDENCE_TYPE_SCREENSHOT:
		return sdkfinding.EvidenceScreenshot
	case typespb.EvidenceType_EVIDENCE_TYPE_LOG:
		return sdkfinding.EvidenceLog
	case typespb.EvidenceType_EVIDENCE_TYPE_CODE:
		return sdkfinding.EvidencePayload
	default:
		return sdkfinding.EvidenceLog
	}
}

// protoEvidenceTypeToString converts a proto EvidenceType to a string.
func protoEvidenceTypeToString(evidenceType typespb.EvidenceType) string {
	switch evidenceType {
	case typespb.EvidenceType_EVIDENCE_TYPE_REQUEST:
		return "request"
	case typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE:
		return "response"
	case typespb.EvidenceType_EVIDENCE_TYPE_SCREENSHOT:
		return "screenshot"
	case typespb.EvidenceType_EVIDENCE_TYPE_LOG:
		return "log"
	case typespb.EvidenceType_EVIDENCE_TYPE_CODE:
		return "code"
	case typespb.EvidenceType_EVIDENCE_TYPE_OTHER:
		return "other"
	default:
		return "other"
	}
}

// stringToProtoEvidenceType converts a string to a proto EvidenceType.
func stringToProtoEvidenceType(typeStr string) typespb.EvidenceType {
	switch typeStr {
	case "request":
		return typespb.EvidenceType_EVIDENCE_TYPE_REQUEST
	case "response":
		return typespb.EvidenceType_EVIDENCE_TYPE_RESPONSE
	case "screenshot":
		return typespb.EvidenceType_EVIDENCE_TYPE_SCREENSHOT
	case "log":
		return typespb.EvidenceType_EVIDENCE_TYPE_LOG
	case "code":
		return typespb.EvidenceType_EVIDENCE_TYPE_CODE
	default:
		return typespb.EvidenceType_EVIDENCE_TYPE_OTHER
	}
}

// protoFindingToFinding converts a proto Finding to an internal agent.Finding.
func protoFindingToFinding(pf *typespb.Finding) agent.Finding {
	if pf == nil {
		return agent.Finding{}
	}

	finding := agent.Finding{
		Title:       pf.Title,
		Description: pf.Description,
		Severity:    protoSeverityToAgentSeverity(pf.Severity),
		Confidence:  pf.Confidence,
		Category:    pf.Category,
	}

	// Parse ID if present
	if pf.Id != "" {
		if id, err := uuid.Parse(pf.Id); err == nil {
			finding.ID = types.ID(id.String())
		}
	}

	// Parse TargetID if present
	if pf.TargetId != "" {
		if id, err := uuid.Parse(pf.TargetId); err == nil {
			targetID := types.ID(id.String())
			finding.TargetID = &targetID
		}
	}

	// Convert Evidence
	if len(pf.Evidence) > 0 {
		finding.Evidence = make([]agent.Evidence, len(pf.Evidence))
		for i, ev := range pf.Evidence {
			// Convert proto EvidenceType enum to string
			typeStr := protoEvidenceTypeToString(ev.Type)
			finding.Evidence[i] = agent.Evidence{
				Type:        typeStr,
				Description: ev.Title,
				Data: map[string]any{
					"content": ev.Content,
				},
			}
			// Add metadata to Data if present
			if len(ev.Metadata) > 0 {
				for k, v := range ev.Metadata {
					finding.Evidence[i].Data[k] = v
				}
			}
		}
	}

	// Convert CVSS score if present
	if pf.CvssScore > 0 {
		finding.CVSS = &agent.CVSSScore{
			Score: pf.CvssScore,
			// Vector not available in proto, leave empty
		}
	}

	// Parse timestamp if present
	if pf.CreatedAt > 0 {
		finding.CreatedAt = time.Unix(0, pf.CreatedAt*int64(time.Millisecond))
	} else {
		finding.CreatedAt = time.Now()
	}

	return finding
}

// findingToProtoFinding converts an internal agent.Finding to a proto Finding.
func findingToProtoFinding(f agent.Finding) *typespb.Finding {
	finding := &typespb.Finding{
		Id:          f.ID.String(),
		Title:       f.Title,
		Description: f.Description,
		Severity:    agentSeverityToProtoSeverity(f.Severity),
		Confidence:  f.Confidence,
		Category:    f.Category,
		CreatedAt:   f.CreatedAt.UnixMilli(),
	}

	// Convert CVSS score if present
	if f.CVSS != nil {
		finding.CvssScore = f.CVSS.Score
	}

	if f.TargetID != nil {
		finding.TargetId = f.TargetID.String()
	}

	// Convert Evidence
	if len(f.Evidence) > 0 {
		finding.Evidence = make([]*typespb.Evidence, len(f.Evidence))
		for i, ev := range f.Evidence {
			// Extract content from Data map if present
			content := ""
			if contentVal, ok := ev.Data["content"]; ok {
				if contentStr, ok := contentVal.(string); ok {
					content = contentStr
				}
			}

			// Convert metadata
			metadata := make(map[string]string)
			for k, v := range ev.Data {
				if k != "content" { // Skip content field
					if strVal, ok := v.(string); ok {
						metadata[k] = strVal
					} else {
						metadata[k] = fmt.Sprintf("%v", v)
					}
				}
			}

			finding.Evidence[i] = &typespb.Evidence{
				Type:     stringToProtoEvidenceType(ev.Type),
				Title:    ev.Description,
				Content:  content,
				Metadata: metadata,
			}
		}
	}

	return finding
}

// mapToTypedMap converts map[string]any to *commonpb.TypedMap.
func mapToTypedMap(m map[string]any) *commonpb.TypedMap {
	if m == nil {
		return nil
	}
	entries := make(map[string]*commonpb.TypedValue)
	for k, v := range m {
		entries[k] = anyToTypedValue(v)
	}
	return &commonpb.TypedMap{Entries: entries}
}

// protoSeverityToAgentSeverity converts proto FindingSeverity to agent.FindingSeverity.
func protoSeverityToAgentSeverity(severity typespb.FindingSeverity) agent.FindingSeverity {
	switch severity {
	case typespb.FindingSeverity_FINDING_SEVERITY_CRITICAL:
		return agent.SeverityCritical
	case typespb.FindingSeverity_FINDING_SEVERITY_HIGH:
		return agent.SeverityHigh
	case typespb.FindingSeverity_FINDING_SEVERITY_MEDIUM:
		return agent.SeverityMedium
	case typespb.FindingSeverity_FINDING_SEVERITY_LOW:
		return agent.SeverityLow
	case typespb.FindingSeverity_FINDING_SEVERITY_INFO:
		return agent.SeverityInfo
	default:
		return agent.SeverityInfo
	}
}

// agentSeverityToProtoSeverity converts agent.FindingSeverity to proto FindingSeverity.
func agentSeverityToProtoSeverity(severity agent.FindingSeverity) typespb.FindingSeverity {
	switch severity {
	case agent.SeverityCritical:
		return typespb.FindingSeverity_FINDING_SEVERITY_CRITICAL
	case agent.SeverityHigh:
		return typespb.FindingSeverity_FINDING_SEVERITY_HIGH
	case agent.SeverityMedium:
		return typespb.FindingSeverity_FINDING_SEVERITY_MEDIUM
	case agent.SeverityLow:
		return typespb.FindingSeverity_FINDING_SEVERITY_LOW
	case agent.SeverityInfo:
		return typespb.FindingSeverity_FINDING_SEVERITY_INFO
	default:
		return typespb.FindingSeverity_FINDING_SEVERITY_INFO
	}
}

// protoFilterToFindingFilter converts a proto FindingFilter to internal FindingFilter.
func protoFilterToFindingFilter(pf *harnesspb.FindingFilter) FindingFilter {
	if pf == nil {
		return FindingFilter{}
	}

	filter := FindingFilter{}

	// Convert optional fields that exist in proto
	if pf.Severity != typespb.FindingSeverity_FINDING_SEVERITY_UNSPECIFIED {
		severity := protoSeverityToAgentSeverity(pf.Severity)
		filter.Severity = &severity
	}

	// Note: proto FindingFilter has tags, mission_id, agent_name, status fields
	// but internal FindingFilter may not have all of them

	return filter
}

// protoQueryToSDKQuery converts a proto GraphQuery to SDK Query.
func protoQueryToSDKQuery(pq *typespb.GraphQuery) sdkgraphrag.Query {
	if pq == nil {
		return sdkgraphrag.Query{}
	}

	// Apply default weights if both are zero (proto default values)
	// SDK requires VectorWeight + GraphWeight == 1.0
	vectorWeight := pq.VectorWeight
	graphWeight := pq.GraphWeight
	if vectorWeight == 0.0 && graphWeight == 0.0 {
		// Use SDK default weights: 0.6 vector, 0.4 graph
		vectorWeight = 0.6
		graphWeight = 0.4
	}

	query := sdkgraphrag.Query{
		Text:         pq.Text,
		NodeTypes:    pq.NodeTypes,
		TopK:         int(pq.TopK),
		MinScore:     float64(pq.MinScore),
		VectorWeight: vectorWeight,
		GraphWeight:  graphWeight,
		MissionRunID: pq.MissionRunId,
	}

	// Convert embedding if present (proto uses float32, SDK uses float64)
	if len(pq.Embedding) > 0 {
		embedding := make([]float64, len(pq.Embedding))
		for i, v := range pq.Embedding {
			embedding[i] = float64(v)
		}
		query.Embedding = embedding
	}

	return query
}

// StoreNode implements the proto-canonical StoreNode RPC using graphragpb.GraphNode.
// This is the preferred method for storing graph nodes with full type safety.
func (s *HarnessCallbackService) StoreNode(ctx context.Context, req *harnesspb.StoreNodeRequest) (*harnesspb.StoreNodeResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.StoreNodeResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Inject all context values from proto context into Go context
	var missionRunID, agentRunID string
	if req.Context != nil {
		// Inject MissionID and AgentName for middleware (required by metadataInjector)
		if req.Context.MissionId != "" {
			ctx = middleware.WithMissionContext(ctx, req.Context.MissionId, req.Context.AgentName)
		}
		if req.Context.MissionRunId != "" {
			missionRunID = req.Context.MissionRunId
			ctx = ContextWithMissionRunID(ctx, missionRunID)
		}
		if req.Context.AgentRunId != "" {
			agentRunID = req.Context.AgentRunId
			ctx = ContextWithAgentRunID(ctx, agentRunID)
		}

		s.logger.Info("StoreNode (proto-canonical): injected context IDs",
			"mission_id", req.Context.MissionId,
			"mission_run_id", missionRunID,
			"agent_run_id", agentRunID,
			"node_type", req.Node.Type,
			"agent_name", req.Context.AgentName)
	} else {
		s.logger.Warn("StoreNode (proto-canonical): no context info in request",
			"node_type", req.Node.Type)
	}

	// Convert graphragpb.GraphNode to SDK node
	node := s.graphragpbNodeToSDKNode(req.Node)

	// Inject mission context metadata before storage
	if err := s.metadataInjector.Inject(ctx, &node); err != nil {
		s.logger.Error("metadata injection failed", "error", err, "node_type", req.Node.Type)
		return &harnesspb.StoreNodeResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("metadata injection failed: %v", err),
			},
		}, nil
	}

	// Store node
	nodeID, err := graphRAG.StoreGraphNode(ctx, node)
	if err != nil {
		s.logger.Error("store graph node failed", "error", err)
		return &harnesspb.StoreNodeResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	return &harnesspb.StoreNodeResponse{
		NodeId: nodeID,
	}, nil
}

// QueryNodes implements the proto-canonical QueryNodes RPC using graphragpb.GraphQuery.
// This is the preferred method for querying graph nodes with full type safety.
func (s *HarnessCallbackService) QueryNodes(ctx context.Context, req *harnesspb.QueryNodesRequest) (*harnesspb.QueryNodesResponse, error) {
	graphRAG, err := s.getGraphRAGHarness(ctx, req.Context)
	if err != nil {
		return &harnesspb.QueryNodesResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Inject MissionRunID from proto context into Go context
	if req.Context != nil && req.Context.MissionRunId != "" {
		ctx = ContextWithMissionRunID(ctx, req.Context.MissionRunId)
	}

	// Convert graphragpb.GraphQuery to SDK query
	query := s.graphragpbQueryToSDKQuery(req.Query)

	// Execute query
	results, err := graphRAG.QueryGraphRAG(ctx, query)
	if err != nil {
		s.logger.Error("query graph nodes failed", "error", err)
		return &harnesspb.QueryNodesResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert SDK results to graphragpb.QueryResult
	protoResults := make([]*graphragpb.QueryResult, len(results))
	for i, r := range results {
		protoResults[i] = s.sdkResultToGraphragpbResult(r)
	}

	return &harnesspb.QueryNodesResponse{
		Results: protoResults,
	}, nil
}

// graphragpbNodeToSDKNode converts a graphragpb.GraphNode to an SDK sdkgraphrag.GraphNode.
// It also injects parent relationship information from proto fields into underscore-prefixed
// properties (_parent_id, _parent_type, _parent_relationship) for use by the RelationshipResolver.
func (s *HarnessCallbackService) graphragpbNodeToSDKNode(pn *graphragpb.GraphNode) sdkgraphrag.GraphNode {
	if pn == nil {
		return sdkgraphrag.GraphNode{}
	}

	// Type is now a string field
	nodeType := pn.Type

	// Convert Value properties to map[string]any
	props := make(map[string]any, len(pn.Properties))
	for k, v := range pn.Properties {
		props[k] = s.graphragpbValueToAny(v)
	}

	// Inject parent relationship info from proto fields as underscore-prefixed properties.
	// These are used by the RelationshipResolver to create parent relationships.
	// The underscore prefix indicates these are internal transport properties that
	// should be stripped before Neo4j storage.
	if parentID := pn.GetParentId(); parentID != "" {
		props["_parent_id"] = parentID
	}
	if parentType := pn.GetParentType(); parentType != "" {
		// Normalize to lowercase for consistency with node types
		props["_parent_type"] = strings.ToLower(parentType)
	}
	if parentRel := pn.GetParentRelationship(); parentRel != "" {
		props["_parent_relationship"] = parentRel
	}

	return sdkgraphrag.GraphNode{
		Type:       nodeType,
		Content:    pn.Content,
		Properties: props,
	}
}

// graphragpbValueToAny converts a graphragpb.Value to any.
func (s *HarnessCallbackService) graphragpbValueToAny(v *graphragpb.Value) any {
	if v == nil {
		return nil
	}
	switch k := v.Kind.(type) {
	case *graphragpb.Value_StringValue:
		return k.StringValue
	case *graphragpb.Value_IntValue:
		return k.IntValue
	case *graphragpb.Value_DoubleValue:
		return k.DoubleValue
	case *graphragpb.Value_BoolValue:
		return k.BoolValue
	case *graphragpb.Value_BytesValue:
		return k.BytesValue
	case *graphragpb.Value_TimestampValue:
		return k.TimestampValue
	default:
		return nil
	}
}

// graphragpbQueryToSDKQuery converts a graphragpb.GraphQuery to an SDK sdkgraphrag.Query.
func (s *HarnessCallbackService) graphragpbQueryToSDKQuery(pq *graphragpb.GraphQuery) sdkgraphrag.Query {
	if pq == nil {
		return sdkgraphrag.Query{}
	}

	// NodeTypes is now a repeated string field - just copy directly
	nodeTypes := make([]string, len(pq.NodeTypes))
	copy(nodeTypes, pq.NodeTypes)

	// Note: QueryScope from proto is handled via MissionRunID injection in the context,
	// not through the query struct. The SDK Query struct does not have a Scope field.

	// graphragpb.GraphQuery does not have VectorWeight/GraphWeight fields,
	// so we always use SDK default weights (0.6 vector, 0.4 graph).
	// SDK requires VectorWeight + GraphWeight == 1.0

	return sdkgraphrag.Query{
		Text:         pq.Text,
		NodeTypes:    nodeTypes,
		TopK:         int(pq.TopK),
		MinScore:     pq.MinScore,
		VectorWeight: 0.6,
		GraphWeight:  0.4,
	}
}

// sdkResultToGraphragpbResult converts an SDK sdkgraphrag.Result to a graphragpb.QueryResult.
func (s *HarnessCallbackService) sdkResultToGraphragpbResult(r sdkgraphrag.Result) *graphragpb.QueryResult {
	// Type is now a string field
	nodeType := r.Node.Type

	// Convert properties to Value map
	props := make(map[string]*graphragpb.Value, len(r.Node.Properties))
	for k, v := range r.Node.Properties {
		props[k] = s.anyToGraphragpbValue(v)
	}

	return &graphragpb.QueryResult{
		Node: &graphragpb.GraphNode{
			Id:         r.Node.ID,
			Type:       nodeType,
			Content:    r.Node.Content,
			Properties: props,
		},
		Score: r.Score,
	}
}

// anyToGraphragpbValue converts any to a graphragpb.Value.
func (s *HarnessCallbackService) anyToGraphragpbValue(v any) *graphragpb.Value {
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

// ============================================================================
// Mission Management Operations
// ============================================================================

// CreateMission implements the mission creation RPC.
// This allows agents to autonomously create sub-missions.
func (s *HarnessCallbackService) CreateMission(ctx context.Context, req *harnesspb.CreateMissionRequest) (*harnesspb.CreateMissionResponse, error) {
	s.logger.Debug("CreateMission called",
		"mission_id", req.Context.MissionId,
		"agent_name", req.Context.AgentName,
		"target_id", req.TargetId,
		"name", req.Name,
	)

	// Check if mission manager is available
	if s.missionManager == nil {
		s.logger.Warn("mission creation not available - mission manager not configured")
		return &harnesspb.CreateMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission creation not available - mission manager not configured",
			},
		}, nil
	}

	// Parse parent mission ID
	var parentMissionID *types.ID
	if req.Context != nil && req.Context.MissionId != "" {
		pid, err := types.ParseID(req.Context.MissionId)
		if err != nil {
			s.logger.Error("failed to parse parent mission ID",
				"mission_id", req.Context.MissionId,
				"error", err,
			)
			return &harnesspb.CreateMissionResponse{
				Error: &harnesspb.HarnessError{
					Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
					Message: fmt.Sprintf("invalid parent mission ID: %v", err),
				},
			}, nil
		}
		parentMissionID = &pid
	}

	// Parse target ID
	targetID, err := types.ParseID(req.TargetId)
	if err != nil {
		s.logger.Error("failed to parse target ID",
			"target_id", req.TargetId,
			"error", err,
		)
		return &harnesspb.CreateMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("invalid target ID: %v", err),
			},
		}, nil
	}

	// Convert proto constraints to internal type
	var constraints *MissionConstraints
	if req.Constraints != nil {
		constraints = &MissionConstraints{
			MaxDuration: time.Duration(req.Constraints.MaxDurationMs) * time.Millisecond,
			MaxTokens:   req.Constraints.MaxTokens,
			MaxCost:     req.Constraints.MaxCost,
			MaxFindings: int(req.Constraints.MaxFindings),
		}
	}

	// Convert metadata
	metadata := make(map[string]any)
	for k, v := range req.Metadata {
		if v != nil {
			metadata[k] = protoTypedValueToAny(v)
		}
	}

	// Create mission request
	createReq := &CreateMissionRequest{
		MissionDefinitionJSON: string(req.MissionDefinitionJson),
		TargetID:              targetID,
		ParentMissionID:       parentMissionID,
		Name:                  req.Name,
		Constraints:           constraints,
		Metadata:              metadata,
		Tags:                  req.Tags,
	}

	// Create the mission through the manager
	missionInfo, err := s.missionManager.CreateMission(ctx, createReq)
	if err != nil {
		s.logger.Error("failed to create mission",
			"error", err,
			"parent_mission_id", req.Context.MissionId,
			"target_id", req.TargetId,
		)
		return &harnesspb.CreateMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: fmt.Sprintf("failed to create mission: %v", err),
			},
		}, nil
	}

	s.logger.Info("mission created successfully",
		"mission_id", missionInfo.ID,
		"parent_mission_id", req.Context.MissionId,
		"name", req.Name,
	)

	// Convert mission info to proto response
	pbMission := &harnesspb.MissionInfo{
		Id:       missionInfo.ID.String(),
		Name:     missionInfo.Name,
		Status:   missionStatusToProto(missionInfo.Status),
		TargetId: missionInfo.TargetID.String(),
	}
	if missionInfo.ParentMissionID != nil {
		pbMission.ParentMissionId = missionInfo.ParentMissionID.String()
	}

	return &harnesspb.CreateMissionResponse{
		Mission: pbMission,
	}, nil
}

// protoTypedValueToAny converts a proto TypedValue to a Go any value
func protoTypedValueToAny(tv *commonpb.TypedValue) any {
	if tv == nil {
		return nil
	}

	switch v := tv.Kind.(type) {
	case *commonpb.TypedValue_StringValue:
		return v.StringValue
	case *commonpb.TypedValue_IntValue:
		return v.IntValue
	case *commonpb.TypedValue_DoubleValue:
		return v.DoubleValue
	case *commonpb.TypedValue_BoolValue:
		return v.BoolValue
	case *commonpb.TypedValue_BytesValue:
		return v.BytesValue
	default:
		return nil
	}
}

// missionStatusToProto converts internal MissionStatus to proto format
func missionStatusToProto(status MissionStatus) harnesspb.MissionStatus {
	switch status {
	case MissionStatusPending:
		return harnesspb.MissionStatus_MISSION_STATUS_PENDING
	case MissionStatusRunning:
		return harnesspb.MissionStatus_MISSION_STATUS_RUNNING
	case MissionStatusCompleted:
		return harnesspb.MissionStatus_MISSION_STATUS_COMPLETED
	case MissionStatusFailed:
		return harnesspb.MissionStatus_MISSION_STATUS_FAILED
	case MissionStatusCancelled:
		return harnesspb.MissionStatus_MISSION_STATUS_CANCELLED
	default:
		return harnesspb.MissionStatus_MISSION_STATUS_UNSPECIFIED
	}
}

// RunMission implements the mission execution RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) RunMission(ctx context.Context, req *harnesspb.RunMissionRequest) (*harnesspb.RunMissionResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.RunMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.RunMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	if err := s.missionManager.Run(ctx, req.MissionId); err != nil {
		s.logger.Error("RunMission: failed to run mission", "mission_id", req.MissionId, "error", err)
		return &harnesspb.RunMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	s.logger.Info("RunMission: mission started", "mission_id", req.MissionId)
	return &harnesspb.RunMissionResponse{}, nil
}

// GetMissionStatus implements the mission status query RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) GetMissionStatus(ctx context.Context, req *harnesspb.GetMissionStatusRequest) (*harnesspb.GetMissionStatusResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.GetMissionStatusResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.GetMissionStatusResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	statusInfo, err := s.missionManager.GetStatus(ctx, req.MissionId)
	if err != nil {
		s.logger.Error("GetMissionStatus: failed to get status", "mission_id", req.MissionId, "error", err)
		return &harnesspb.GetMissionStatusResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	// Convert finding counts from map[string]int to map[string]int32.
	findingCounts := make(map[string]int32, len(statusInfo.FindingCounts))
	for k, v := range statusInfo.FindingCounts {
		findingCounts[k] = int32(v)
	}

	return &harnesspb.GetMissionStatusResponse{
		Status: &harnesspb.MissionStatusInfo{
			Status:        missionStatusToProto(statusInfo.Status),
			Progress:      statusInfo.Progress,
			Phase:         statusInfo.Phase,
			FindingCounts: findingCounts,
			TokenUsage:    statusInfo.TokenUsage,
			DurationMs:    statusInfo.Duration.Milliseconds(),
			Error:         statusInfo.Error,
		},
	}, nil
}

// WaitForMission implements the mission wait RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) WaitForMission(ctx context.Context, req *harnesspb.WaitForMissionRequest) (*harnesspb.WaitForMissionResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.WaitForMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.WaitForMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	result, err := s.missionManager.WaitForCompletion(ctx, req.MissionId, timeout)
	if err != nil {
		s.logger.Error("WaitForMission: failed to wait", "mission_id", req.MissionId, "error", err)
		return &harnesspb.WaitForMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	s.logger.Info("WaitForMission: mission completed", "mission_id", req.MissionId, "status", result.Status)
	return &harnesspb.WaitForMissionResponse{
		Result: &harnesspb.MissionResult{
			MissionId:   result.MissionID,
			Status:      missionStatusToProto(result.Status),
			Error:       result.Error,
			CompletedAt: result.CompletedAt.UnixMilli(),
		},
	}, nil
}

// ListMissions implements the mission listing RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) ListMissions(ctx context.Context, req *harnesspb.ListMissionsRequest) (*harnesspb.ListMissionsResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.ListMissionsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	filter := &MissionFilter{}
	if req.Filter != nil {
		filter.Limit = int(req.Filter.Limit)
		filter.Offset = int(req.Filter.Offset)
		if req.Filter.Status != harnesspb.MissionStatus_MISSION_STATUS_UNSPECIFIED {
			// Map proto MissionStatus enum back to internal string representation.
			st := MissionStatus(strings.ToLower(strings.TrimPrefix(req.Filter.Status.String(), "MISSION_STATUS_")))
			filter.Status = &st
		}
	}

	records, err := s.missionManager.List(ctx, filter)
	if err != nil {
		s.logger.Error("ListMissions: failed to list", "error", err)
		return &harnesspb.ListMissionsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	missions := make([]*harnesspb.MissionInfo, 0, len(records))
	for _, rec := range records {
		missions = append(missions, &harnesspb.MissionInfo{
			Id:     rec.ID.String(),
			Status: missionStatusToProto(rec.Status),
		})
	}

	s.logger.Info("ListMissions: listed missions", "count", len(missions))
	return &harnesspb.ListMissionsResponse{Missions: missions}, nil
}

// CancelMission implements the mission cancellation RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) CancelMission(ctx context.Context, req *harnesspb.CancelMissionRequest) (*harnesspb.CancelMissionResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.CancelMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.CancelMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	missionID, err := types.ParseID(req.MissionId)
	if err != nil {
		return &harnesspb.CancelMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("invalid mission_id: %v", err),
			},
		}, nil
	}

	if err := s.missionManager.Cancel(ctx, missionID); err != nil {
		s.logger.Error("CancelMission: failed to cancel", "mission_id", req.MissionId, "error", err)
		return &harnesspb.CancelMissionResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	s.logger.Info("CancelMission: mission cancelled", "mission_id", req.MissionId)
	return &harnesspb.CancelMissionResponse{}, nil
}

// GetMissionResults implements the mission results retrieval RPC by delegating to the MissionOperator.
func (s *HarnessCallbackService) GetMissionResults(ctx context.Context, req *harnesspb.GetMissionResultsRequest) (*harnesspb.GetMissionResultsResponse, error) {
	if s.missionManager == nil {
		return &harnesspb.GetMissionResultsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_UNAVAILABLE,
				Message: "mission management not configured",
			},
		}, nil
	}

	if req.MissionId == "" {
		return &harnesspb.GetMissionResultsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: "mission_id is required",
			},
		}, nil
	}

	missionID, err := types.ParseID(req.MissionId)
	if err != nil {
		return &harnesspb.GetMissionResultsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INVALID_ARGUMENT,
				Message: fmt.Sprintf("invalid mission_id: %v", err),
			},
		}, nil
	}

	result, err := s.missionManager.GetResults(ctx, missionID)
	if err != nil {
		s.logger.Error("GetMissionResults: failed to get results", "mission_id", req.MissionId, "error", err)
		return &harnesspb.GetMissionResultsResponse{
			Error: &harnesspb.HarnessError{
				Code:    commonpb.ErrorCode_ERROR_CODE_INTERNAL,
				Message: err.Error(),
			},
		}, nil
	}

	s.logger.Info("GetMissionResults: results retrieved", "mission_id", req.MissionId, "status", result.Status)
	return &harnesspb.GetMissionResultsResponse{
		Result: &harnesspb.MissionResult{
			MissionId:   result.MissionID,
			Status:      missionStatusToProto(result.Status),
			Error:       result.Error,
			CompletedAt: result.CompletedAt.UnixMilli(),
		},
	}, nil
}
