package harness

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/harness/middleware"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/codegen/workspace"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

// MiddlewareHarness wraps an AgentHarness and routes operations through middleware.
type MiddlewareHarness struct {
	inner      AgentHarness
	middleware middleware.Middleware
}

// NewMiddlewareHarness creates a new MiddlewareHarness.
func NewMiddlewareHarness(inner AgentHarness, mw middleware.Middleware) *MiddlewareHarness {
	return &MiddlewareHarness{inner: inner, middleware: mw}
}

func (h *MiddlewareHarness) wrapOperation(op middleware.Operation) middleware.Operation {
	if h.middleware == nil {
		return op
	}
	return h.middleware(op)
}

func (h *MiddlewareHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	ctx = middleware.WithOperationType(ctx, middleware.OpComplete)
	ctx = middleware.WithSlotName(ctx, slot)
	ctx = middleware.WithMissionContext(ctx, h.inner.Mission().ID.String(), h.inner.Mission().CurrentAgent)
	ctx = middleware.WithMessages(ctx, toMiddlewareMessages(messages))

	innerOp := func(ctx context.Context, req any) (any, error) {
		return h.inner.Complete(ctx, slot, messages, opts...)
	}

	result, err := h.wrapOperation(innerOp)(ctx, nil)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*llm.CompletionResponse), nil
}

func (h *MiddlewareHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	ctx = middleware.WithOperationType(ctx, middleware.OpCompleteWithTools)
	ctx = middleware.WithSlotName(ctx, slot)
	ctx = middleware.WithMissionContext(ctx, h.inner.Mission().ID.String(), h.inner.Mission().CurrentAgent)
	ctx = middleware.WithMessages(ctx, toMiddlewareMessages(messages))

	innerOp := func(ctx context.Context, req any) (any, error) {
		return h.inner.CompleteWithTools(ctx, slot, messages, tools, opts...)
	}

	result, err := h.wrapOperation(innerOp)(ctx, nil)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*llm.CompletionResponse), nil
}

func (h *MiddlewareHarness) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (<-chan llm.StreamChunk, error) {
	ctx = middleware.WithOperationType(ctx, middleware.OpStream)
	ctx = middleware.WithSlotName(ctx, slot)
	ctx = middleware.WithMissionContext(ctx, h.inner.Mission().ID.String(), h.inner.Mission().CurrentAgent)
	ctx = middleware.WithMessages(ctx, toMiddlewareMessages(messages))

	innerOp := func(ctx context.Context, req any) (any, error) {
		return h.inner.Stream(ctx, slot, messages, opts...)
	}

	result, err := h.wrapOperation(innerOp)(ctx, nil)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(<-chan llm.StreamChunk), nil
}

func (h *MiddlewareHarness) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
	ctx = middleware.WithOperationType(ctx, middleware.OpCompleteWithTools) // Reuse tools op type since structured uses tool_use
	ctx = middleware.WithSlotName(ctx, slot)
	ctx = middleware.WithMissionContext(ctx, h.inner.Mission().ID.String(), h.inner.Mission().CurrentAgent)
	ctx = middleware.WithMessages(ctx, toMiddlewareMessages(messages))

	innerOp := func(ctx context.Context, req any) (any, error) {
		return h.inner.CompleteStructuredAny(ctx, slot, messages, schemaType, opts...)
	}

	return h.wrapOperation(innerOp)(ctx, nil)
}

func (h *MiddlewareHarness) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
	ctx = middleware.WithOperationType(ctx, middleware.OpCompleteWithTools) // Reuse tools op type since structured uses tool_use
	ctx = middleware.WithSlotName(ctx, slot)
	ctx = middleware.WithMissionContext(ctx, h.inner.Mission().ID.String(), h.inner.Mission().CurrentAgent)
	ctx = middleware.WithMessages(ctx, toMiddlewareMessages(messages))

	innerOp := func(ctx context.Context, req any) (any, error) {
		return h.inner.CompleteStructuredAnyWithUsage(ctx, slot, messages, schemaType, opts...)
	}

	result, err := h.wrapOperation(innerOp)(ctx, nil)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.(*StructuredCompletionResult), nil
}

// CallToolProto delegates to the inner harness's CallToolProto.
// Middleware can be applied in the future if needed.
func (h *MiddlewareHarness) CallToolProto(ctx context.Context, name string, request, response proto.Message) error {
	return h.inner.CallToolProto(ctx, name, request, response)
}

func (h *MiddlewareHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	ctx = middleware.WithOperationType(ctx, middleware.OpQueryPlugin)
	ctx = middleware.WithPluginInfo(ctx, name, method)
	ctx = middleware.WithMissionContext(ctx, h.inner.Mission().ID.String(), h.inner.Mission().CurrentAgent)

	innerOp := func(ctx context.Context, req any) (any, error) {
		return h.inner.QueryPlugin(ctx, name, method, params)
	}

	return h.wrapOperation(innerOp)(ctx, params)
}

func (h *MiddlewareHarness) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	ctx = middleware.WithOperationType(ctx, middleware.OpDelegateToAgent)
	ctx = middleware.WithAgentTargetName(ctx, name)
	ctx = middleware.WithMissionContext(ctx, h.inner.Mission().ID.String(), h.inner.Mission().CurrentAgent)

	innerOp := func(ctx context.Context, req any) (any, error) {
		return h.inner.DelegateToAgent(ctx, name, task)
	}

	result, err := h.wrapOperation(innerOp)(ctx, task)
	if err != nil {
		return agent.Result{}, err
	}
	return result.(agent.Result), nil
}

func (h *MiddlewareHarness) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	ctx = middleware.WithOperationType(ctx, middleware.OpSubmitFinding)
	ctx = middleware.WithMissionContext(ctx, h.inner.Mission().ID.String(), h.inner.Mission().CurrentAgent)

	innerOp := func(ctx context.Context, req any) (any, error) {
		return nil, h.inner.SubmitFinding(ctx, finding)
	}

	_, err := h.wrapOperation(innerOp)(ctx, finding)
	return err
}

// Pass-through methods
func (h *MiddlewareHarness) GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return h.inner.GetFindings(ctx, filter)
}
func (h *MiddlewareHarness) Memory() memory.MemoryStore  { return h.inner.Memory() }
func (h *MiddlewareHarness) Mission() MissionContext     { return h.inner.Mission() }
func (h *MiddlewareHarness) MissionID() types.ID         { return h.inner.MissionID() }
func (h *MiddlewareHarness) Target() TargetInfo          { return h.inner.Target() }
func (h *MiddlewareHarness) ListTools() []ToolDescriptor { return h.inner.ListTools() }
func (h *MiddlewareHarness) GetToolDescriptor(ctx context.Context, name string) (*ToolDescriptor, error) {
	return h.inner.GetToolDescriptor(ctx, name)
}
func (h *MiddlewareHarness) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	return h.inner.GetToolCapabilities(ctx, toolName)
}
func (h *MiddlewareHarness) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	return h.inner.GetAllToolCapabilities(ctx)
}
func (h *MiddlewareHarness) ListPlugins() []PluginDescriptor { return h.inner.ListPlugins() }
func (h *MiddlewareHarness) ListAgents() []AgentDescriptor   { return h.inner.ListAgents() }
func (h *MiddlewareHarness) Tracer() trace.Tracer            { return h.inner.Tracer() }
func (h *MiddlewareHarness) Logger() *slog.Logger            { return h.inner.Logger() }
func (h *MiddlewareHarness) Metrics() MetricsRecorder        { return h.inner.Metrics() }
func (h *MiddlewareHarness) TokenUsage() *llm.TokenTracker   { return h.inner.TokenUsage() }
func (h *MiddlewareHarness) MissionExecutionContext() MissionExecutionContextSDK {
	return h.inner.MissionExecutionContext()
}
func (h *MiddlewareHarness) GetMissionRunHistory(ctx context.Context) ([]MissionRunSummarySDK, error) {
	return h.inner.GetMissionRunHistory(ctx)
}
func (h *MiddlewareHarness) GetPreviousRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return h.inner.GetPreviousRunFindings(ctx, filter)
}
func (h *MiddlewareHarness) GetAllRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return h.inner.GetAllRunFindings(ctx, filter)
}

// agent.AgentHarness interface
func (h *MiddlewareHarness) Log(level, message string, fields map[string]any) {
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, slog.Any(k, v))
	}
	logger := h.Logger()
	switch level {
	case "debug":
		logger.Debug(message, attrs...)
	case "info":
		logger.Info(message, attrs...)
	case "warn":
		logger.Warn(message, attrs...)
	case "error":
		logger.Error(message, attrs...)
	default:
		logger.Info(message, attrs...)
	}
}

var _ AgentHarness = (*MiddlewareHarness)(nil)

// TODO: Re-enable SDK Harness interface check once CallToolProtoStream is implemented
// The SDK agent.Harness interface now requires CallToolProtoStream which needs to be
// implemented in MiddlewareHarness as a pass-through to the inner harness.
// var _ sdkagent.Harness = (*MiddlewareHarness)(nil)

// GraphRAGSupport interface implementation - pass through to inner harness
// These methods enable GraphRAG operations for external agents using callback RPCs.

func (h *MiddlewareHarness) QueryGraphRAG(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error) {
	if inner, ok := h.inner.(interface {
		QueryGraphRAG(context.Context, sdkgraphrag.Query) ([]sdkgraphrag.Result, error)
	}); ok {
		return inner.QueryGraphRAG(ctx, query)
	}
	return nil, fmt.Errorf("QueryGraphRAG not supported by inner harness")
}

func (h *MiddlewareHarness) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]sdkgraphrag.AttackPattern, error) {
	if inner, ok := h.inner.(interface {
		FindSimilarAttacks(context.Context, string, int) ([]sdkgraphrag.AttackPattern, error)
	}); ok {
		return inner.FindSimilarAttacks(ctx, content, topK)
	}
	return nil, fmt.Errorf("FindSimilarAttacks not supported by inner harness")
}

func (h *MiddlewareHarness) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]sdkgraphrag.FindingNode, error) {
	if inner, ok := h.inner.(interface {
		FindSimilarFindings(context.Context, string, int) ([]sdkgraphrag.FindingNode, error)
	}); ok {
		return inner.FindSimilarFindings(ctx, findingID, topK)
	}
	return nil, fmt.Errorf("FindSimilarFindings not supported by inner harness")
}

func (h *MiddlewareHarness) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]sdkgraphrag.AttackChain, error) {
	if inner, ok := h.inner.(interface {
		GetAttackChains(context.Context, string, int) ([]sdkgraphrag.AttackChain, error)
	}); ok {
		return inner.GetAttackChains(ctx, techniqueID, maxDepth)
	}
	return nil, fmt.Errorf("GetAttackChains not supported by inner harness")
}

func (h *MiddlewareHarness) GetRelatedFindings(ctx context.Context, findingID string) ([]sdkgraphrag.FindingNode, error) {
	if inner, ok := h.inner.(interface {
		GetRelatedFindings(context.Context, string) ([]sdkgraphrag.FindingNode, error)
	}); ok {
		return inner.GetRelatedFindings(ctx, findingID)
	}
	return nil, fmt.Errorf("GetRelatedFindings not supported by inner harness")
}

func (h *MiddlewareHarness) StoreGraphNode(ctx context.Context, node sdkgraphrag.GraphNode) (string, error) {
	if inner, ok := h.inner.(interface {
		StoreGraphNode(context.Context, sdkgraphrag.GraphNode) (string, error)
	}); ok {
		return inner.StoreGraphNode(ctx, node)
	}
	return "", fmt.Errorf("StoreGraphNode not supported by inner harness")
}

func (h *MiddlewareHarness) CreateGraphRelationship(ctx context.Context, rel sdkgraphrag.Relationship) error {
	if inner, ok := h.inner.(interface {
		CreateGraphRelationship(context.Context, sdkgraphrag.Relationship) error
	}); ok {
		return inner.CreateGraphRelationship(ctx, rel)
	}
	return fmt.Errorf("CreateGraphRelationship not supported by inner harness")
}

func (h *MiddlewareHarness) StoreGraphBatch(ctx context.Context, batch sdkgraphrag.Batch) ([]string, error) {
	if inner, ok := h.inner.(interface {
		StoreGraphBatch(context.Context, sdkgraphrag.Batch) ([]string, error)
	}); ok {
		return inner.StoreGraphBatch(ctx, batch)
	}
	return nil, fmt.Errorf("StoreGraphBatch not supported by inner harness")
}

func (h *MiddlewareHarness) TraverseGraph(ctx context.Context, startNodeID string, opts sdkgraphrag.TraversalOptions) ([]sdkgraphrag.TraversalResult, error) {
	if inner, ok := h.inner.(interface {
		TraverseGraph(context.Context, string, sdkgraphrag.TraversalOptions) ([]sdkgraphrag.TraversalResult, error)
	}); ok {
		return inner.TraverseGraph(ctx, startNodeID, opts)
	}
	return nil, fmt.Errorf("TraverseGraph not supported by inner harness")
}

func (h *MiddlewareHarness) GraphRAGHealth(ctx context.Context) types.HealthStatus {
	if inner, ok := h.inner.(interface {
		GraphRAGHealth(context.Context) types.HealthStatus
	}); ok {
		return inner.GraphRAGHealth(ctx)
	}
	return types.Unhealthy("GraphRAGHealth not supported by inner harness")
}

// Checkpoint returns the checkpoint access interface from the inner harness.
func (h *MiddlewareHarness) Checkpoint() CheckpointAccess {
	if inner, ok := h.inner.(interface {
		Checkpoint() CheckpointAccess
	}); ok {
		return inner.Checkpoint()
	}
	// Return a disabled checkpoint implementation
	return NewHarnessCheckpointMethods(nil, "", "", 0)
}

// Workspace returns the primary workspace from the inner harness.
// Returns nil if workspaces are not configured.
func (h *MiddlewareHarness) Workspace() workspace.Workspace {
	if inner, ok := h.inner.(interface {
		Workspace() workspace.Workspace
	}); ok {
		return inner.Workspace()
	}
	return nil
}

// Workspaces returns all workspaces from the inner harness.
// Returns an empty map if workspaces are not configured.
func (h *MiddlewareHarness) Workspaces() map[string]workspace.Workspace {
	if inner, ok := h.inner.(interface {
		Workspaces() map[string]workspace.Workspace
	}); ok {
		return inner.Workspaces()
	}
	return make(map[string]workspace.Workspace)
}

// toMiddlewareMessages converts llm.Message slice to middleware.Message slice
// for passing through context to tracing middleware.
func toMiddlewareMessages(messages []llm.Message) []middleware.Message {
	result := make([]middleware.Message, len(messages))
	for i, m := range messages {
		result[i] = middleware.Message{
			Role:    string(m.Role),
			Content: m.Content,
		}
	}
	return result
}
