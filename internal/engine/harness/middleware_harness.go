// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"fmt"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/middleware"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	sdkagent "github.com/zeroroot-ai/sdk/agent"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	sdktypes "github.com/zeroroot-ai/sdk/types"
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

// CallToolProtoStream delegates to the inner harness's streaming dispatch.
// Mirrors the operation-type / mission-context capture pattern used by
// CallToolProto so middleware sees both call shapes consistently.
//
// Spec: headline-feature-completion R1.3.
func (h *MiddlewareHarness) CallToolProtoStream(ctx context.Context, name string, request, response proto.Message, callback sdkagent.ToolStreamCallback) error {
	return h.inner.CallToolProtoStream(ctx, name, request, response, callback)
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

// GetRunFindings forwards to the wrapped harness.
func (h *MiddlewareHarness) GetRunFindings(ctx context.Context, scope harnesspb.RunScope, filter FindingFilter) ([]agent.Finding, error) {
	findings, err := h.inner.GetRunFindings(ctx, scope, filter)
	if err != nil {
		return nil, fmt.Errorf("middleware: get run findings: %w", err)
	}
	return findings, nil
}

// Graph reads below are pure forwarders: this decorator wraps behaviour, and a
// read that only leaves the process has none to wrap.

// QueryNodes forwards to the wrapped harness.
func (h *MiddlewareHarness) QueryNodes(ctx context.Context, q *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error) {
	results, err := h.inner.QueryNodes(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("middleware: query nodes: %w", err)
	}
	return results, nil
}

// FindSimilarAttacks forwards to the wrapped harness.
func (h *MiddlewareHarness) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]*graphragpb.AttackPattern, error) {
	results, err := h.inner.FindSimilarAttacks(ctx, content, topK)
	if err != nil {
		return nil, fmt.Errorf("middleware: find similar attacks: %w", err)
	}
	return results, nil
}

// GetAttackChains forwards to the wrapped harness.
func (h *MiddlewareHarness) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]*graphragpb.AttackChain, error) {
	results, err := h.inner.GetAttackChains(ctx, techniqueID, maxDepth)
	if err != nil {
		return nil, fmt.Errorf("middleware: get attack chains: %w", err)
	}
	return results, nil
}

// FindSimilarFindings forwards to the wrapped harness.
func (h *MiddlewareHarness) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]*graphragpb.FindingNode, error) {
	results, err := h.inner.FindSimilarFindings(ctx, findingID, topK)
	if err != nil {
		return nil, fmt.Errorf("middleware: find similar findings: %w", err)
	}
	return results, nil
}

// GetRelatedFindings forwards to the wrapped harness.
func (h *MiddlewareHarness) GetRelatedFindings(ctx context.Context, findingID string) ([]*graphragpb.FindingNode, error) {
	results, err := h.inner.GetRelatedFindings(ctx, findingID)
	if err != nil {
		return nil, fmt.Errorf("middleware: get related findings: %w", err)
	}
	return results, nil
}

// ApplicationFindings forwards to the wrapped harness.
func (h *MiddlewareHarness) ApplicationFindings(ctx context.Context, application string, statuses []string, limit int) ([]byte, error) {
	results, err := h.inner.ApplicationFindings(ctx, application, statuses, limit)
	if err != nil {
		return nil, fmt.Errorf("middleware: application findings: %w", err)
	}
	return results, nil
}

// agent.AgentHarness interface
func (h *MiddlewareHarness) Log(level, message string, fields map[string]any) {
	// One slog.Attr per field — so the capacity is len(fields), not
	// len(fields)*2. The old *2 over-allocated by 100% and read as a
	// potential integer overflow to static analysis (gibson#1444).
	attrs := make([]any, 0, len(fields))
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

// SDK Harness interface check.
//
// MiddlewareHarness now provides CallToolProtoStream (Week 4 task 49), so
// the streaming-tool side of the SDK contract is satisfied. The full
// sdkagent.Harness interface, however, is a sibling surface with
// deliberately different ID types (string vs types.ID) and a different
// Memory shape; that contract is enforced on the SDK-facing
// PlatformHarness / CallbackHarness in core/sdk/serve/, not on this
// internal middleware wrapper. Re-enabling the assertion below would
// require MiddlewareHarness to grow SDK-specific surface area unrelated
// to its purpose.
//
// var _ sdkagent.Harness = (*MiddlewareHarness)(nil)

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
