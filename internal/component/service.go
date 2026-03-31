package component

// service.go implements the ComponentServiceServer gRPC handlers.
//
// This server is the single ingress point that all Gibson components (agents,
// tools, plugins) connect to. It delegates to ComponentRegistry for lifecycle
// tracking and WorkQueue for pull-based work dispatch.
//
// Generated proto code location: github.com/zero-day-ai/gibson/api/gen/componentpb
// TODO: When proto codegen runs, uncomment the componentpb import and the
//       embedded UnimplementedComponentServiceServer field, and replace all
//       placeholder request/response types with their generated counterparts.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ---------------------------------------------------------------------------
// Placeholder proto types
//
// These mirror the message definitions in api/proto/component.proto exactly.
// Replace each type with the corresponding generated componentpb type once
// protoc has been run and core/gibson/api/gen/componentpb/ exists.
// ---------------------------------------------------------------------------

// TODO: replace with componentpb.RegisterComponentRequest
type RegisterComponentRequest struct {
	Kind                string
	Name                string
	Version             string
	Metadata            map[string]string
	Capabilities        []string
	Methods             []string
	InputMessageType    string
	OutputMessageType   string
	FileDescriptorSet   []byte
}

// TODO: replace with componentpb.RegisterComponentResponse
type RegisterComponentResponse struct {
	InstanceID           string
	HeartbeatIntervalMs  int32
	PollIntervalMs       int32
	PollTimeoutMs        int32
	Config               map[string]string
}

// TODO: replace with componentpb.HeartbeatRequest
type HeartbeatRequest struct {
	InstanceID    string
	HealthStatus  string
	HealthMessage string
}

// TODO: replace with componentpb.HeartbeatResponse
type HeartbeatResponse struct {
	Registered    bool
	ConfigUpdates map[string]string
}

// TODO: replace with componentpb.PollWorkRequest
type PollWorkRequest struct {
	InstanceID string
	TimeoutMs  int32
}

// TODO: replace with componentpb.PollWorkResponse
type PollWorkResponse struct {
	WorkID    string
	WorkType  string
	Payload   []byte
	Context   map[string]string
	TimeoutMs int64
}

// TODO: replace with componentpb.SubmitResultRequest
type SubmitResultRequest struct {
	WorkID string
	Result []byte
	Error  *SubmitResultError
}

// SubmitResultError mirrors componentpb.ComponentError for the SubmitResult RPC.
// TODO: replace with componentpb.ComponentError
type SubmitResultError struct {
	Code      string
	Message   string
	Retryable bool
}

// TODO: replace with componentpb.SubmitResultResponse
type SubmitResultResponse struct{}

// ---------------------------------------------------------------------------
// Harness proxy placeholder proto types
//
// These types mirror the message definitions for the harness proxy RPCs in
// api/proto/component.proto. Replace each with the generated componentpb type
// once protoc has been run.
// ---------------------------------------------------------------------------

// MemoryTier identifies which of the three memory tiers an operation targets.
// TODO: replace with componentpb.MemoryTier enum
type MemoryTier string

const (
	// MemoryTierWorking targets ephemeral, in-process working memory.
	MemoryTierWorking MemoryTier = "working"
	// MemoryTierMission targets Redis-backed mission-scoped persistent storage.
	MemoryTierMission MemoryTier = "mission"
	// MemoryTierLongTerm targets the vector-backed long-term semantic memory.
	MemoryTierLongTerm MemoryTier = "longterm"
)

// TODO: replace with componentpb.CompleteRequest
type CompleteRequest struct {
	// WorkId is the ID of the work item on whose behalf the completion is requested.
	// Used to look up the associated mission context for LLM routing.
	WorkId string
	// Slot selects the named model slot (e.g., "primary", "fast", "reasoning").
	Slot string
	// MessagesJson is the JSON-encoded []llm.Message slice to send to the LLM.
	MessagesJson string
	// MaxTokens overrides the slot default when non-zero.
	MaxTokens int32
	// Temperature overrides the slot default when set to a non-negative value.
	Temperature float32
}

// TODO: replace with componentpb.CompleteResponse
type CompleteResponse struct {
	// Content is the assistant's response text.
	Content string
	// FinishReason is the raw finish reason string from the provider.
	FinishReason string
	// PromptTokens is the number of tokens consumed by the prompt.
	PromptTokens int32
	// CompletionTokens is the number of tokens generated.
	CompletionTokens int32
	// TotalTokens is PromptTokens + CompletionTokens.
	TotalTokens int32
	// ModelUsed is the resolved model identifier that served this request.
	ModelUsed string
}

// CompleteStreamResponse carries a single chunk of a streaming completion.
// TODO: replace with componentpb.CompleteStreamResponse
type CompleteStreamResponse struct {
	// Delta is the incremental content for this chunk.
	Delta string
	// FinishReason is non-empty only on the final chunk.
	FinishReason string
	// Error is non-nil when the stream terminated abnormally.
	Error string
}

// TODO: replace with componentpb.CallToolRequest
type CallToolRequest struct {
	// WorkId is the calling work item, used for audit linkage.
	WorkId string
	// ToolName is the registered name of the tool component.
	ToolName string
	// InputJson is the JSON-encoded tool input (matches the tool's declared proto input type).
	InputJson string
	// TimeoutMs is the maximum milliseconds to wait for a result; 0 means 5 minutes.
	TimeoutMs int64
}

// TODO: replace with componentpb.CallToolResponse
type CallToolResponse struct {
	// OutputJson is the JSON-encoded tool output.
	OutputJson string
	// Error is non-empty when the tool returned a structured error.
	Error string
}

// TODO: replace with componentpb.QueryPluginRequest
type QueryPluginRequest struct {
	// WorkId is the calling work item, used for audit linkage.
	WorkId string
	// PluginName is the registered name of the plugin component.
	PluginName string
	// InputJson is the JSON-encoded plugin query input.
	InputJson string
	// TimeoutMs is the maximum milliseconds to wait for a result; 0 means 5 minutes.
	TimeoutMs int64
}

// TODO: replace with componentpb.QueryPluginResponse
type QueryPluginResponse struct {
	// OutputJson is the JSON-encoded plugin query output.
	OutputJson string
	// Error is non-empty when the plugin returned a structured error.
	Error string
}

// TODO: replace with componentpb.SubmitFindingRequest
type SubmitFindingRequest struct {
	// WorkId is the work item that produced this finding.
	WorkId string
	// FindingJson is the JSON-encoded finding payload.
	// This must conform to the agent.Finding schema until proto types are generated.
	FindingJson string
	// Severity is a string representation (e.g., "critical", "high", "medium", "low", "info").
	Severity string
	// Title is a short human-readable description of the finding.
	Title string
}

// TODO: replace with componentpb.SubmitFindingResponse
type SubmitFindingResponse struct {
	// FindingId is the generated unique identifier assigned to the stored finding.
	FindingId string
}

// TODO: replace with componentpb.MemoryGetRequest
type MemoryGetRequest struct {
	// Tier selects the memory tier to read from.
	Tier MemoryTier
	// Key is the memory key to retrieve.
	Key string
}

// TODO: replace with componentpb.MemoryGetResponse
type MemoryGetResponse struct {
	// ValueJson is the JSON-encoded stored value, or empty string if not found.
	ValueJson string
	// Found is false when the key does not exist in the requested tier.
	Found bool
}

// TODO: replace with componentpb.MemorySetRequest
type MemorySetRequest struct {
	// Tier selects the memory tier to write to.
	Tier MemoryTier
	// Key is the memory key to set.
	Key string
	// ValueJson is the JSON-encoded value to store.
	ValueJson string
	// MetadataJson is an optional JSON-encoded map[string]any of metadata.
	MetadataJson string
}

// TODO: replace with componentpb.MemorySetResponse
type MemorySetResponse struct{}

// TODO: replace with componentpb.MemorySearchRequest
type MemorySearchRequest struct {
	// Tier selects the memory tier to search (mission supports FTS; longterm supports vector search).
	Tier MemoryTier
	// Query is the search query string.
	Query string
	// TopK is the maximum number of results to return.
	TopK int32
}

// MemorySearchResult is a single result from a memory search operation.
// TODO: replace with componentpb.MemorySearchResult
type MemorySearchResult struct {
	// Key is the memory key for this result.
	Key string
	// ValueJson is the JSON-encoded stored value.
	ValueJson string
	// Score is the relevance score (0–1 for vector search, BM25 score for FTS).
	Score float32
}

// TODO: replace with componentpb.MemorySearchResponse
type MemorySearchResponse struct {
	Results []MemorySearchResult
}

// ---------------------------------------------------------------------------
// Harness proxy dependency interfaces
//
// These narrow interfaces decouple ComponentServiceServer from the concrete
// LLM and finding pipeline implementations. Wire them at construction time.
// Both interfaces will be replaced by direct harness delegation once the
// mission-context lookup layer (task 5.3+) is in place.
// ---------------------------------------------------------------------------

// LLMCompleter routes a completion request for a given mission slot to the
// appropriate LLM provider. The missionID is used to resolve per-tenant
// slot configuration.
//
// TODO: replace call site with harness.Complete once mission context lookup
// is available (task 5.3). Until then, implementors may use a simple
// provider-registry lookup keyed by tenant + slot.
type LLMCompleter interface {
	// Complete executes a blocking completion using the named slot.
	// messagesJSON is a JSON-encoded []llm.Message.
	// Returns the response content, finish reason, token usage, and resolved model.
	Complete(ctx context.Context, tenant, missionID, slot, messagesJSON string, maxTokens int32, temperature float32) (content, finishReason, modelUsed string, promptTokens, completionTokens int32, err error)

	// Stream executes a streaming completion using the named slot and sends
	// chunks to the provided send function until completion or error.
	// messagesJSON is a JSON-encoded []llm.Message.
	Stream(ctx context.Context, tenant, missionID, slot, messagesJSON string, maxTokens int32, temperature float32, send func(delta, finishReason string) error) error
}

// FindingSubmitter persists a serialized finding produced by a remote agent.
// The JSON payload must conform to the agent.Finding schema.
//
// TODO: wire to the Neo4j/GraphRAG pipeline in task 5.4+. For now, the
// InMemoryFindingSubmitter logs and generates a finding_id.
type FindingSubmitter interface {
	// Submit stores the finding and returns a generated finding_id.
	Submit(ctx context.Context, tenant, workID, findingJSON, severity, title string) (findingID string, err error)
}

// ---------------------------------------------------------------------------
// Connection parameter defaults
//
// These values are returned to every registering component so they know how
// frequently to heartbeat and poll. They are intentionally conservative so
// that a component defaults to safe behaviour before any server-pushed config
// is available.
// ---------------------------------------------------------------------------

const (
	// defaultHeartbeatIntervalMs is the recommended heartbeat cadence sent to
	// components on registration. Must be shorter than the registry TTL (30 s).
	defaultHeartbeatIntervalMs = 10_000 // 10 seconds

	// defaultPollIntervalMs is the recommended back-off between empty polls.
	defaultPollIntervalMs = 1_000 // 1 second

	// defaultPollTimeoutMs is the server-side long-poll window a component
	// should request. Matches the registry TTL so an idle component is never
	// blocking for longer than its registration would be valid.
	defaultPollTimeoutMs = 20_000 // 20 seconds

	// maxPollTimeoutMs caps the client-requested poll timeout to prevent
	// goroutine leaks from extremely long-running blocking claims.
	maxPollTimeoutMs = 30_000 // 30 seconds
)

// ---------------------------------------------------------------------------
// ComponentServiceServer
// ---------------------------------------------------------------------------

// ComponentServiceServer handles the four core lifecycle RPCs that every
// Gibson component calls:
//
//   - RegisterComponent  - announce existence, receive instance_id + config
//   - Heartbeat          - refresh TTL, detect forced deregistration
//   - PollWork           - long-poll for a work item (blocking claim)
//   - SubmitResult       - deliver work outcome back to the orchestrator
//
// All operations are tenant-scoped: the tenant is extracted from the context
// via auth.TenantFromContext and forwarded to both the registry and queue so
// that data from different tenants is never commingled.
//
// TODO: embed componentpb.UnimplementedComponentServiceServer once generated
// code exists so that newly added RPCs in the proto return UNIMPLEMENTED
// rather than panicking:
//
//	type ComponentServiceServer struct {
//	    componentpb.UnimplementedComponentServiceServer
//	    ...
//	}
type ComponentServiceServer struct {
	registry ComponentRegistry
	queue    WorkQueue
	logger   *slog.Logger

	// Harness proxy dependencies.
	//
	// llmCompleter routes LLM completions back to Gibson's provider system.
	// May be nil; Complete and CompleteStream return codes.Unimplemented when nil.
	llmCompleter LLMCompleter

	// memory provides access to all three memory tiers on behalf of remote agents.
	// May be nil; MemoryGet, MemorySet, and MemorySearch return codes.Unimplemented when nil.
	memory memory.MemoryStore

	// findingSubmitter persists findings from remote agents.
	// May be nil; SubmitFinding logs and generates an ID when nil.
	findingSubmitter FindingSubmitter
}

// NewComponentServiceServer constructs a ComponentServiceServer with the core
// lifecycle dependencies. Both registry and queue must be non-nil.
//
// Harness proxy dependencies (llmCompleter, memStore, findingSubmitter) are
// optional at this stage: pass nil to leave the corresponding RPCs returning
// codes.Unimplemented until the subsystems are wired (tasks 5.3–5.5).
func NewComponentServiceServer(
	registry ComponentRegistry,
	queue WorkQueue,
	logger *slog.Logger,
	llmCompleter LLMCompleter,
	memStore memory.MemoryStore,
	findingSubmitter FindingSubmitter,
) *ComponentServiceServer {
	if registry == nil {
		panic("component.NewComponentServiceServer: registry must not be nil")
	}
	if queue == nil {
		panic("component.NewComponentServiceServer: queue must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &ComponentServiceServer{
		registry:         registry,
		queue:            queue,
		logger:           logger,
		llmCompleter:     llmCompleter,
		memory:           memStore,
		findingSubmitter: findingSubmitter,
	}
}

// ---------------------------------------------------------------------------
// RegisterComponent
// ---------------------------------------------------------------------------

// RegisterComponent handles a component announcing itself to Gibson.
//
// Flow:
//  1. Extract tenant from context — unauthenticated callers are rejected.
//  2. Build a ComponentInfo from the request fields.
//  3. Call registry.Register which assigns a unique instance ID and stores
//     the entry with a TTL.
//  4. Return the instance ID and the recommended connection parameters.
func (s *ComponentServiceServer) RegisterComponent(
	ctx context.Context,
	req *RegisterComponentRequest,
) (*RegisterComponentResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.Kind == "" {
		return nil, status.Error(codes.InvalidArgument, "kind is required")
	}
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	info := ComponentInfo{
		Kind:     req.Kind,
		Name:     req.Name,
		Version:  req.Version,
		TenantID: tenant,
		Metadata: req.Metadata,
	}
	if info.Metadata == nil {
		info.Metadata = make(map[string]string)
	}

	// Capabilities, methods, and descriptor set are stored in metadata so that
	// the registry remains agnostic to component type semantics.
	for _, cap := range req.Capabilities {
		info.Metadata["capability:"+cap] = "true"
	}
	for _, method := range req.Methods {
		info.Metadata["method:"+method] = "true"
	}
	if len(req.FileDescriptorSet) > 0 {
		info.Metadata["input_message_type"] = req.InputMessageType
		info.Metadata["output_message_type"] = req.OutputMessageType
		// Binary descriptor sets are not stored in string metadata; callers that
		// need them must re-send on each registration.
	}

	instanceID, err := s.registry.Register(ctx, tenant, req.Kind, req.Name, info)
	if err != nil {
		s.logger.ErrorContext(ctx, "component registration failed",
			slog.String("tenant", tenant),
			slog.String("kind", req.Kind),
			slog.String("name", req.Name),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to register component: %v", err)
	}

	s.logger.InfoContext(ctx, "component registered",
		slog.String("tenant", tenant),
		slog.String("kind", req.Kind),
		slog.String("name", req.Name),
		slog.String("version", req.Version),
		slog.String("instance_id", instanceID),
	)

	return &RegisterComponentResponse{
		InstanceID:          instanceID,
		HeartbeatIntervalMs: defaultHeartbeatIntervalMs,
		PollIntervalMs:      defaultPollIntervalMs,
		PollTimeoutMs:       defaultPollTimeoutMs,
		Config:              map[string]string{},
	}, nil
}

// ---------------------------------------------------------------------------
// Heartbeat
// ---------------------------------------------------------------------------

// Heartbeat handles a periodic liveness pulse from a registered component.
//
// Flow:
//  1. Extract tenant from context.
//  2. Resolve the component kind and name from the instance ID via Discover
//     (the heartbeat request only carries instance_id, not kind/name).
//  3. Call registry.RefreshTTL to reset the expiry clock.
//  4. Return registered=false when the instance is no longer known so the
//     component knows to re-register.
//
// Note: The HeartbeatRequest carries only instance_id, so we must locate the
// component record before refreshing. If the component is unknown we return
// registered=false rather than an error — this is a normal operational signal
// that tells the client to re-register rather than treating it as a fault.
func (s *ComponentServiceServer) Heartbeat(
	ctx context.Context,
	req *HeartbeatRequest,
) (*HeartbeatResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.InstanceID == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_id is required")
	}

	// Discover all tenant components and find the one matching the instance ID.
	// This is intentionally a lightweight scan: the registry keeps a small hot
	// set per tenant and the common case is O(1) Redis GET after SCAN.
	components, err := s.registry.ListTenantComponents(ctx, tenant)
	if err != nil {
		s.logger.ErrorContext(ctx, "heartbeat: failed to list tenant components",
			slog.String("tenant", tenant),
			slog.String("instance_id", req.InstanceID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to lookup component instance: %v", err)
	}

	var target *ComponentInfo
	for i := range components {
		if components[i].InstanceID == req.InstanceID {
			target = &components[i]
			break
		}
	}

	if target == nil {
		// Instance is not registered — caller must re-register.
		s.logger.InfoContext(ctx, "heartbeat: instance not found, signalling re-register",
			slog.String("tenant", tenant),
			slog.String("instance_id", req.InstanceID),
		)
		return &HeartbeatResponse{Registered: false}, nil
	}

	err = s.registry.RefreshTTL(ctx, tenant, target.Kind, target.Name, req.InstanceID)
	if err != nil {
		if errors.Is(err, ErrComponentNotFound) {
			// Key expired between the Discover scan and the RefreshTTL call.
			s.logger.InfoContext(ctx, "heartbeat: instance expired between scan and refresh",
				slog.String("tenant", tenant),
				slog.String("instance_id", req.InstanceID),
			)
			return &HeartbeatResponse{Registered: false}, nil
		}
		s.logger.ErrorContext(ctx, "heartbeat: failed to refresh TTL",
			slog.String("tenant", tenant),
			slog.String("kind", target.Kind),
			slog.String("name", target.Name),
			slog.String("instance_id", req.InstanceID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to refresh component TTL: %v", err)
	}

	s.logger.DebugContext(ctx, "heartbeat: TTL refreshed",
		slog.String("tenant", tenant),
		slog.String("kind", target.Kind),
		slog.String("name", target.Name),
		slog.String("instance_id", req.InstanceID),
		slog.String("health_status", req.HealthStatus),
	)

	return &HeartbeatResponse{
		Registered:    true,
		ConfigUpdates: map[string]string{},
	}, nil
}

// ---------------------------------------------------------------------------
// PollWork
// ---------------------------------------------------------------------------

// PollWork long-polls for the next available work item assigned to this
// component instance.
//
// Flow:
//  1. Extract tenant from context.
//  2. Resolve kind and name from the instance ID.
//  3. Compute the blocking duration: use the client-requested timeout clamped
//     to maxPollTimeoutMs, falling back to defaultPollTimeoutMs.
//  4. Call queue.Claim which blocks until a message arrives or the timeout
//     elapses.
//  5. Return the work item fields, or an empty response if no work arrived.
//
// An empty response (work_id == "") signals that the timeout expired without
// available work. The component should loop back and call PollWork again after
// the recommended poll_interval_ms.
func (s *ComponentServiceServer) PollWork(
	ctx context.Context,
	req *PollWorkRequest,
) (*PollWorkResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.InstanceID == "" {
		return nil, status.Error(codes.InvalidArgument, "instance_id is required")
	}

	// Resolve the component record so we can route the claim to the correct stream.
	components, err := s.registry.ListTenantComponents(ctx, tenant)
	if err != nil {
		s.logger.ErrorContext(ctx, "poll work: failed to list tenant components",
			slog.String("tenant", tenant),
			slog.String("instance_id", req.InstanceID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to lookup component instance: %v", err)
	}

	var target *ComponentInfo
	for i := range components {
		if components[i].InstanceID == req.InstanceID {
			target = &components[i]
			break
		}
	}

	if target == nil {
		// Component is not registered; tell the caller to re-register.
		return nil, status.Errorf(codes.NotFound,
			"component instance %q not found; re-register before polling", req.InstanceID)
	}

	// Clamp the requested block timeout.
	timeoutMs := int32(defaultPollTimeoutMs)
	if req.TimeoutMs > 0 {
		timeoutMs = req.TimeoutMs
	}
	if timeoutMs > maxPollTimeoutMs {
		timeoutMs = maxPollTimeoutMs
	}
	blockTimeout := time.Duration(timeoutMs) * time.Millisecond

	item, err := s.queue.Claim(ctx, tenant, target.Kind, target.Name, req.InstanceID, blockTimeout)
	if err != nil {
		// Distinguish context cancellation from genuine queue errors.
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		s.logger.ErrorContext(ctx, "poll work: claim failed",
			slog.String("tenant", tenant),
			slog.String("kind", target.Kind),
			slog.String("name", target.Name),
			slog.String("instance_id", req.InstanceID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to claim work item: %v", err)
	}

	if item == nil {
		// Timeout elapsed with no work available — empty response is the
		// normal signal for the component to loop.
		return &PollWorkResponse{}, nil
	}

	s.logger.InfoContext(ctx, "poll work: dispatched work item",
		slog.String("tenant", tenant),
		slog.String("kind", target.Kind),
		slog.String("name", target.Name),
		slog.String("instance_id", req.InstanceID),
		slog.String("work_id", item.WorkID),
		slog.String("work_type", item.WorkType),
	)

	return &PollWorkResponse{
		WorkID:    item.WorkID,
		WorkType:  item.WorkType,
		Payload:   item.Payload,
		Context:   item.Context,
		TimeoutMs: item.TimeoutMs,
	}, nil
}

// ---------------------------------------------------------------------------
// SubmitResult
// ---------------------------------------------------------------------------

// SubmitResult accepts the outcome of a completed work item from a component.
//
// Flow:
//  1. Extract tenant from context (for audit logging; DeliverResult is keyed
//     by work_id which is globally unique, so no further tenant routing is
//     needed at the queue layer).
//  2. Convert the optional proto ComponentError to a WorkError.
//  3. Call queue.DeliverResult to persist the result and unblock any caller
//     waiting in WaitForResult.
//  4. Return an empty response.
func (s *ComponentServiceServer) SubmitResult(
	ctx context.Context,
	req *SubmitResultRequest,
) (*SubmitResultResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.WorkID == "" {
		return nil, status.Error(codes.InvalidArgument, "work_id is required")
	}

	result := WorkResult{
		WorkID: req.WorkID,
		Result: req.Result,
	}

	if req.Error != nil && req.Error.Code != "" {
		result.Error = &WorkError{
			Code:      req.Error.Code,
			Message:   req.Error.Message,
			Retryable: req.Error.Retryable,
		}
	}

	if err := s.queue.DeliverResult(ctx, req.WorkID, result); err != nil {
		s.logger.ErrorContext(ctx, "submit result: deliver failed",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to deliver result for work %q: %v", req.WorkID, err)
	}

	s.logger.InfoContext(ctx, "submit result: result delivered",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkID),
		slog.Bool("has_error", result.Error != nil),
	)

	return &SubmitResultResponse{}, nil
}

// ---------------------------------------------------------------------------
// Harness proxy RPCs
//
// The methods below proxy operations that a remote agent needs to perform
// during task execution — LLM completions, tool/plugin dispatch, finding
// submission, and memory access — back to Gibson's internal subsystems.
//
// Each method follows the same tenant-extraction pattern as the lifecycle RPCs
// above. Nil dependencies cause the method to return codes.Unimplemented so
// that operators can incrementally wire subsystems without breaking the server.
// ---------------------------------------------------------------------------

// Complete proxies an LLM completion request from a remote agent to Gibson's
// LLM provider system.
//
// Flow:
//  1. Extract tenant; reject unauthenticated callers.
//  2. Validate required fields (slot, messages_json).
//  3. Delegate to llmCompleter.Complete which resolves the slot to a provider
//     and model, forwards the messages, and returns usage metrics.
//  4. Return the assistant content and token usage to the caller.
//
// TODO (task 5.3): look up the work item's mission context so that slot
// resolution can use per-mission model configuration rather than tenant-level
// defaults.
func (s *ComponentServiceServer) Complete(
	ctx context.Context,
	req *CompleteRequest,
) (*CompleteResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.llmCompleter == nil {
		return nil, status.Error(codes.Unimplemented, "LLM completion not yet wired on this server")
	}

	if req.Slot == "" {
		return nil, status.Error(codes.InvalidArgument, "slot is required")
	}
	if req.MessagesJson == "" {
		return nil, status.Error(codes.InvalidArgument, "messages_json is required")
	}

	s.logger.DebugContext(ctx, "complete: routing LLM request",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("slot", req.Slot),
	)

	// TODO (task 5.3): resolve mission ID from work item context so that
	// per-mission slot overrides can be applied.
	missionID := ""

	content, finishReason, modelUsed, promptTokens, completionTokens, err := s.llmCompleter.Complete(
		ctx,
		tenant,
		missionID,
		req.Slot,
		req.MessagesJson,
		req.MaxTokens,
		req.Temperature,
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "complete: LLM completion failed",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("slot", req.Slot),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "LLM completion failed: %v", err)
	}

	s.logger.InfoContext(ctx, "complete: LLM completion succeeded",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("slot", req.Slot),
		slog.String("model_used", modelUsed),
		slog.Int("prompt_tokens", int(promptTokens)),
		slog.Int("completion_tokens", int(completionTokens)),
	)

	return &CompleteResponse{
		Content:          content,
		FinishReason:     finishReason,
		ModelUsed:        modelUsed,
		PromptTokens:     promptTokens,
		CompletionTokens: completionTokens,
		TotalTokens:      promptTokens + completionTokens,
	}, nil
}

// CompleteStream is the server-streaming variant of Complete. It invokes the
// LLM and sends incremental content deltas to the client as they arrive.
//
// The final chunk carries a non-empty FinishReason and zero Delta to signal
// stream termination. On error mid-stream, a chunk with a non-empty Error
// field is sent before the stream closes.
//
// TODO (task 5.3): same mission-context lookup as Complete.
// TODO: When proto codegen runs, replace the send function signature with the
//
//	generated grpc.ServerStream.Send method.
func (s *ComponentServiceServer) CompleteStream(
	ctx context.Context,
	req *CompleteRequest,
	send func(*CompleteStreamResponse) error,
) error {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.llmCompleter == nil {
		return status.Error(codes.Unimplemented, "LLM streaming not yet wired on this server")
	}

	if req.Slot == "" {
		return status.Error(codes.InvalidArgument, "slot is required")
	}
	if req.MessagesJson == "" {
		return status.Error(codes.InvalidArgument, "messages_json is required")
	}

	s.logger.DebugContext(ctx, "complete stream: starting streaming LLM request",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("slot", req.Slot),
	)

	// TODO (task 5.3): resolve mission ID from work item context.
	missionID := ""

	err := s.llmCompleter.Stream(
		ctx,
		tenant,
		missionID,
		req.Slot,
		req.MessagesJson,
		req.MaxTokens,
		req.Temperature,
		func(delta, finishReason string) error {
			return send(&CompleteStreamResponse{
				Delta:        delta,
				FinishReason: finishReason,
			})
		},
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "complete stream: streaming LLM request failed",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("slot", req.Slot),
			slog.String("error", err.Error()),
		)
		// Best-effort: send an error chunk before returning the gRPC error so
		// that clients that do not inspect the trailing status still see the
		// failure reason.
		_ = send(&CompleteStreamResponse{Error: err.Error()})
		return status.Errorf(codes.Internal, "LLM streaming failed: %v", err)
	}

	return nil
}

// CallTool dispatches a tool invocation on behalf of a remote agent.
//
// Flow:
//  1. Extract tenant; reject unauthenticated callers.
//  2. Validate required fields.
//  3. Discover tool instances via registry (tenant namespace first, then _system).
//  4. Enqueue a work item on the tool's work stream via WorkQueue.Enqueue.
//  5. Block on WorkQueue.WaitForResult until the tool responds or the timeout
//     elapses.
//  6. Return the tool output or surface the tool's structured error.
//
// The direct in-cluster gRPC call path (for tools that have a gRPC endpoint in
// their ComponentInfo.Metadata) is deferred: all dispatch goes through the
// work queue for now, keeping the flow uniform and observable.
func (s *ComponentServiceServer) CallTool(
	ctx context.Context,
	req *CallToolRequest,
) (*CallToolResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.ToolName == "" {
		return nil, status.Error(codes.InvalidArgument, "tool_name is required")
	}
	if req.InputJson == "" {
		return nil, status.Error(codes.InvalidArgument, "input_json is required")
	}

	// Discover tool: tenant-scoped first, then _system fallback (handled by Discover).
	instances, err := s.registry.Discover(ctx, tenant, "tool", req.ToolName)
	if err != nil {
		s.logger.ErrorContext(ctx, "call tool: discovery failed",
			slog.String("tenant", tenant),
			slog.String("tool_name", req.ToolName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "tool discovery failed: %v", err)
	}
	if len(instances) == 0 {
		s.logger.WarnContext(ctx, "call tool: tool not found",
			slog.String("tenant", tenant),
			slog.String("tool_name", req.ToolName),
		)
		return nil, status.Errorf(codes.NotFound, "tool %q not available for tenant %q", req.ToolName, tenant)
	}

	// Build the work item targeting the tool component.
	workItem := WorkItem{
		WorkType:  "execute_proto",
		Payload:   []byte(req.InputJson),
		TimeoutMs: req.TimeoutMs,
		Context: map[string]string{
			"source_work_id": req.WorkId,
			"caller_tenant":  tenant,
		},
	}

	workID, err := s.queue.Enqueue(ctx, tenant, "tool", req.ToolName, workItem)
	if err != nil {
		s.logger.ErrorContext(ctx, "call tool: enqueue failed",
			slog.String("tenant", tenant),
			slog.String("tool_name", req.ToolName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to enqueue tool work: %v", err)
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	s.logger.DebugContext(ctx, "call tool: waiting for result",
		slog.String("tenant", tenant),
		slog.String("tool_name", req.ToolName),
		slog.String("work_id", workID),
		slog.Duration("timeout", timeout),
	)

	result, err := s.queue.WaitForResult(ctx, workID, timeout)
	if err != nil {
		s.logger.ErrorContext(ctx, "call tool: wait for result failed",
			slog.String("tenant", tenant),
			slog.String("tool_name", req.ToolName),
			slog.String("work_id", workID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.DeadlineExceeded, "tool execution timed out or failed: %v", err)
	}

	resp := &CallToolResponse{OutputJson: string(result.Result)}
	if result.Error != nil && result.Error.Code != "" {
		resp.Error = fmt.Sprintf("[%s] %s", result.Error.Code, result.Error.Message)
	}

	s.logger.InfoContext(ctx, "call tool: result received",
		slog.String("tenant", tenant),
		slog.String("tool_name", req.ToolName),
		slog.String("work_id", workID),
		slog.Bool("has_error", resp.Error != ""),
	)

	return resp, nil
}

// QueryPlugin dispatches a plugin query on behalf of a remote agent.
//
// The dispatch pattern is identical to CallTool — discover via registry,
// enqueue on the plugin's work stream, wait for result — with the component
// kind set to "plugin" instead of "tool".
func (s *ComponentServiceServer) QueryPlugin(
	ctx context.Context,
	req *QueryPluginRequest,
) (*QueryPluginResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.PluginName == "" {
		return nil, status.Error(codes.InvalidArgument, "plugin_name is required")
	}
	if req.InputJson == "" {
		return nil, status.Error(codes.InvalidArgument, "input_json is required")
	}

	// Discover plugin: tenant-scoped first, then _system fallback.
	instances, err := s.registry.Discover(ctx, tenant, "plugin", req.PluginName)
	if err != nil {
		s.logger.ErrorContext(ctx, "query plugin: discovery failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "plugin discovery failed: %v", err)
	}
	if len(instances) == 0 {
		s.logger.WarnContext(ctx, "query plugin: plugin not found",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
		)
		return nil, status.Errorf(codes.NotFound, "plugin %q not available for tenant %q", req.PluginName, tenant)
	}

	workItem := WorkItem{
		WorkType:  "execute_proto",
		Payload:   []byte(req.InputJson),
		TimeoutMs: req.TimeoutMs,
		Context: map[string]string{
			"source_work_id": req.WorkId,
			"caller_tenant":  tenant,
		},
	}

	workID, err := s.queue.Enqueue(ctx, tenant, "plugin", req.PluginName, workItem)
	if err != nil {
		s.logger.ErrorContext(ctx, "query plugin: enqueue failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.Internal, "failed to enqueue plugin work: %v", err)
	}

	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	s.logger.DebugContext(ctx, "query plugin: waiting for result",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
		slog.String("work_id", workID),
		slog.Duration("timeout", timeout),
	)

	result, err := s.queue.WaitForResult(ctx, workID, timeout)
	if err != nil {
		s.logger.ErrorContext(ctx, "query plugin: wait for result failed",
			slog.String("tenant", tenant),
			slog.String("plugin_name", req.PluginName),
			slog.String("work_id", workID),
			slog.String("error", err.Error()),
		)
		return nil, status.Errorf(codes.DeadlineExceeded, "plugin execution timed out or failed: %v", err)
	}

	resp := &QueryPluginResponse{OutputJson: string(result.Result)}
	if result.Error != nil && result.Error.Code != "" {
		resp.Error = fmt.Sprintf("[%s] %s", result.Error.Code, result.Error.Message)
	}

	s.logger.InfoContext(ctx, "query plugin: result received",
		slog.String("tenant", tenant),
		slog.String("plugin_name", req.PluginName),
		slog.String("work_id", workID),
		slog.Bool("has_error", resp.Error != ""),
	)

	return resp, nil
}

// SubmitFinding accepts a serialized finding from a remote agent and persists it.
//
// Flow:
//  1. Extract tenant; reject unauthenticated callers.
//  2. Validate that finding_json is present.
//  3. Delegate to findingSubmitter if wired; otherwise generate a finding_id
//     and log the payload so that no findings are silently dropped during
//     the development phase.
//
// TODO (task 5.4): wire findingSubmitter to the Neo4j/GraphRAG pipeline.
func (s *ComponentServiceServer) SubmitFinding(
	ctx context.Context,
	req *SubmitFindingRequest,
) (*SubmitFindingResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if req.FindingJson == "" {
		return nil, status.Error(codes.InvalidArgument, "finding_json is required")
	}

	if s.findingSubmitter != nil {
		findingID, err := s.findingSubmitter.Submit(
			ctx,
			tenant,
			req.WorkId,
			req.FindingJson,
			req.Severity,
			req.Title,
		)
		if err != nil {
			s.logger.ErrorContext(ctx, "submit finding: storage failed",
				slog.String("tenant", tenant),
				slog.String("work_id", req.WorkId),
				slog.String("severity", req.Severity),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to store finding: %v", err)
		}

		s.logger.InfoContext(ctx, "submit finding: finding stored",
			slog.String("tenant", tenant),
			slog.String("work_id", req.WorkId),
			slog.String("finding_id", findingID),
			slog.String("severity", req.Severity),
		)

		return &SubmitFindingResponse{FindingId: findingID}, nil
	}

	// findingSubmitter not yet wired — generate an ID and log the payload so
	// that findings are traceable during development without being silently lost.
	findingID := uuid.New().String()

	s.logger.WarnContext(ctx, "submit finding: no finding submitter wired; logging payload only",
		slog.String("tenant", tenant),
		slog.String("work_id", req.WorkId),
		slog.String("finding_id", findingID),
		slog.String("severity", req.Severity),
		slog.String("title", req.Title),
		slog.String("finding_json", req.FindingJson),
	)

	return &SubmitFindingResponse{FindingId: findingID}, nil
}

// MemoryGet retrieves a value from the requested memory tier by key.
//
// Tier routing:
//   - working  — in-process ephemeral map; returns not-found when key absent.
//   - mission  — Redis-backed persistent store; returns not-found when absent.
//   - longterm — not suitable for point lookups; returns codes.InvalidArgument.
//
// TODO (task 5.5): wire per-agent memory manager lookup so that each remote
// agent reads from its own mission-scoped memory namespace.
func (s *ComponentServiceServer) MemoryGet(
	ctx context.Context,
	req *MemoryGetRequest,
) (*MemoryGetResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.memory == nil {
		// TODO (task 5.5): return codes.Unimplemented until memory is wired.
		return nil, status.Error(codes.Unimplemented, "memory store not yet wired on this server")
	}

	if req.Key == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}

	switch req.Tier {
	case MemoryTierWorking:
		val, ok := s.memory.Working().Get(req.Key)
		if !ok {
			return &MemoryGetResponse{Found: false}, nil
		}
		// Serialize the retrieved value to JSON for the wire format.
		// Working memory stores arbitrary any values; JSON is the lowest common
		// denominator for cross-language clients.
		//
		// TODO (task 5.5): use a shared codec so that types round-trip correctly.
		item := memory.NewMemoryItem(req.Key, val, nil)
		data, err := item.MarshalValue()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to serialize working memory value: %v", err)
		}
		return &MemoryGetResponse{Found: true, ValueJson: string(data)}, nil

	case MemoryTierMission:
		item, err := s.memory.Mission().Retrieve(ctx, req.Key)
		if err != nil {
			// Translate not-found into a Found=false response instead of an error
			// to keep the client contract simple. Mission memory signals not-found
			// via *types.GibsonError with code ErrCodeMissionMemoryNotFound.
			var gibsonErr *types.GibsonError
			if errors.As(err, &gibsonErr) && gibsonErr.Code == memory.ErrCodeMissionMemoryNotFound {
				return &MemoryGetResponse{Found: false}, nil
			}
			s.logger.ErrorContext(ctx, "memory get: mission retrieve failed",
				slog.String("tenant", tenant),
				slog.String("key", req.Key),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to retrieve mission memory key %q: %v", req.Key, err)
		}
		data, err := item.MarshalValue()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to serialize mission memory value: %v", err)
		}
		return &MemoryGetResponse{Found: true, ValueJson: string(data)}, nil

	case MemoryTierLongTerm:
		// Long-term memory is a semantic vector store; it does not support
		// direct key lookups. Use MemorySearch with a precise query instead.
		return nil, status.Error(codes.InvalidArgument,
			"long-term memory does not support key-based Get; use MemorySearch instead")

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown memory tier %q", req.Tier)
	}
}

// MemorySet writes a value to the requested memory tier.
//
// Tier routing:
//   - working  — in-process ephemeral map; value_json is deserialized into any.
//   - mission  — Redis-backed persistent store; value_json is stored as-is.
//   - longterm — use the Store call (ID + content + metadata); metadata_json is
//     treated as the content and key as the ID.
//
// TODO (task 5.5): wire per-agent memory manager lookup.
func (s *ComponentServiceServer) MemorySet(
	ctx context.Context,
	req *MemorySetRequest,
) (*MemorySetResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.memory == nil {
		// TODO (task 5.5): return codes.Unimplemented until memory is wired.
		return nil, status.Error(codes.Unimplemented, "memory store not yet wired on this server")
	}

	if req.Key == "" {
		return nil, status.Error(codes.InvalidArgument, "key is required")
	}
	if req.ValueJson == "" {
		return nil, status.Error(codes.InvalidArgument, "value_json is required")
	}

	switch req.Tier {
	case MemoryTierWorking:
		// Store the raw JSON string in working memory. The agent is responsible
		// for deserializing on retrieval; this keeps working memory agnostic to
		// schema.
		if err := s.memory.Working().Set(req.Key, req.ValueJson); err != nil {
			s.logger.ErrorContext(ctx, "memory set: working memory set failed",
				slog.String("tenant", tenant),
				slog.String("key", req.Key),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to set working memory key %q: %v", req.Key, err)
		}

	case MemoryTierMission:
		// Mission memory accepts any value; store the JSON string directly.
		// metadata_json is ignored for now — agents can embed metadata in value_json.
		//
		// TODO (task 5.5): parse MetadataJson and forward as map[string]any.
		if err := s.memory.Mission().Store(ctx, req.Key, req.ValueJson, nil); err != nil {
			s.logger.ErrorContext(ctx, "memory set: mission memory store failed",
				slog.String("tenant", tenant),
				slog.String("key", req.Key),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to store mission memory key %q: %v", req.Key, err)
		}

	case MemoryTierLongTerm:
		// Long-term memory requires content as a plain string for embedding.
		// value_json is treated as that content; key becomes the vector entry ID.
		//
		// TODO (task 5.5): parse MetadataJson and forward as map[string]any.
		if err := s.memory.LongTerm().Store(ctx, req.Key, req.ValueJson, nil); err != nil {
			s.logger.ErrorContext(ctx, "memory set: long-term memory store failed",
				slog.String("tenant", tenant),
				slog.String("key", req.Key),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "failed to store long-term memory entry %q: %v", req.Key, err)
		}

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown memory tier %q", req.Tier)
	}

	s.logger.DebugContext(ctx, "memory set: value stored",
		slog.String("tenant", tenant),
		slog.String("tier", string(req.Tier)),
		slog.String("key", req.Key),
	)

	return &MemorySetResponse{}, nil
}

// MemorySearch performs a semantic or full-text search over a memory tier.
//
// Tier routing:
//   - working  — not suitable for search; returns codes.InvalidArgument.
//   - mission  — full-text search over stored key-value pairs.
//   - longterm — vector-similarity search using the configured embedder.
//
// TODO (task 5.5): wire per-agent memory manager lookup so each remote agent
// searches within its own mission namespace.
func (s *ComponentServiceServer) MemorySearch(
	ctx context.Context,
	req *MemorySearchRequest,
) (*MemorySearchResponse, error) {
	tenant := auth.TenantFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.Unauthenticated, "missing tenant in context")
	}

	if s.memory == nil {
		// TODO (task 5.5): return codes.Unimplemented until memory is wired.
		return nil, status.Error(codes.Unimplemented, "memory store not yet wired on this server")
	}

	if req.Query == "" {
		return nil, status.Error(codes.InvalidArgument, "query is required")
	}

	topK := int(req.TopK)
	if topK <= 0 {
		topK = 10
	}

	switch req.Tier {
	case MemoryTierWorking:
		// Working memory is an in-process key-value map with no search index.
		// Callers should iterate keys via MemoryGet or restructure data for
		// mission/longterm tiers.
		return nil, status.Error(codes.InvalidArgument,
			"working memory does not support search; use mission or longterm tier")

	case MemoryTierMission:
		// TODO (task 5.5): call mission memory Search once the interface exposes it.
		// For now, return Unimplemented so callers know to use longterm search.
		//
		// Placeholder: mission memory FTS is exposed via MissionMemory.Search in
		// the mission_redis.go implementation; wire it here once the interface is
		// stable.
		_ = topK
		s.logger.WarnContext(ctx, "memory search: mission FTS not yet wired",
			slog.String("tenant", tenant),
			slog.String("query", req.Query),
		)
		return nil, status.Error(codes.Unimplemented,
			"mission memory search not yet wired; use longterm tier for semantic search")

	case MemoryTierLongTerm:
		rawResults, err := s.memory.LongTerm().Search(ctx, req.Query, topK, nil)
		if err != nil {
			s.logger.ErrorContext(ctx, "memory search: long-term search failed",
				slog.String("tenant", tenant),
				slog.String("query", req.Query),
				slog.String("error", err.Error()),
			)
			return nil, status.Errorf(codes.Internal, "long-term memory search failed: %v", err)
		}

		results := make([]MemorySearchResult, 0, len(rawResults))
		for _, r := range rawResults {
			data, err := r.Item.MarshalValue()
			if err != nil {
				// Skip results that cannot be serialized rather than failing the
				// entire response — partial results are more useful than none.
				s.logger.WarnContext(ctx, "memory search: failed to serialize result; skipping",
					slog.String("tenant", tenant),
					slog.String("key", r.Item.Key),
					slog.String("error", err.Error()),
				)
				continue
			}
			results = append(results, MemorySearchResult{
				Key:       r.Item.Key,
				ValueJson: string(data),
				Score:     float32(r.Score),
			})
		}

		s.logger.DebugContext(ctx, "memory search: long-term search completed",
			slog.String("tenant", tenant),
			slog.String("query", req.Query),
			slog.Int("result_count", len(results)),
		)

		return &MemorySearchResponse{Results: results}, nil

	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown memory tier %q", req.Tier)
	}
}
