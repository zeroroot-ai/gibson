// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"fmt"
	"log/slog"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/middleware"
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

// Pass-through methods. Each reads state the middleware has no reason to
// intercept, so it answers from the inner harness unchanged.

// GetFindings returns the inner harness's findings.
func (h *MiddlewareHarness) GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	return h.inner.GetFindings(ctx, filter)
}

// Mission returns the inner harness's mission context.
func (h *MiddlewareHarness) Mission() MissionContext { return h.inner.Mission() }

// MissionID returns the inner harness's mission id.
func (h *MiddlewareHarness) MissionID() types.ID { return h.inner.MissionID() }

// Target returns the inner harness's target.
func (h *MiddlewareHarness) Target() TargetInfo { return h.inner.Target() }

// ForTarget scopes THIS harness, not its inner one. A view built around the
// inner harness would answer every call from the inner harness and silently drop
// whatever middleware this one adds — for exactly the dispatches that most need
// it, since a fan-out instance is still subject to the same policy as the
// mission's primary.
func (h *MiddlewareHarness) ForTarget(targetID string) AgentHarness {
	return scopeToTarget(h, h.Target(), targetID)
}
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

// ResolveSlotModel resolves a slot with no call, so no middleware wraps it. An
// inner harness that cannot resolve a slot gives an error.
func (h *MiddlewareHarness) ResolveSlotModel(ctx context.Context, slot string) (SlotModel, error) {
	r, ok := h.inner.(SlotModelResolver)
	if !ok {
		return SlotModel{}, fmt.Errorf("the harness %T cannot resolve a slot to a model", h.inner)
	}
	//nolint:wrapcheck // a decorator returns the inner error, which callers match by code
	return r.ResolveSlotModel(ctx, slot)
}

var (
	_ SlotModelResolver = (*MiddlewareHarness)(nil)
	_ SlotModelResolver = (*DefaultAgentHarness)(nil)
)
