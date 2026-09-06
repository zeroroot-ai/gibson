// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	sdkagent "github.com/zeroroot-ai/sdk/agent"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	sdktypes "github.com/zeroroot-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

// noopInnerHarness is a minimal stub of AgentHarness for tests that need a
// complete implementor of the interface but exercise none of its behaviour.
// Every method returns zero values.
//
// It lived in compliance_middleware_test.go until the compliance-signal
// pipeline was deleted (gibson#1299, ADR-0013); it is a generic test fake and
// has nothing to do with compliance, so it moved here rather than going with
// that deletion.
type noopInnerHarness struct {
	UnimplementedKnowledgeReader // knowledge reads report unavailable; explicit methods below still win.
}

var _ AgentHarness = (*noopInnerHarness)(nil)

func (*noopInnerHarness) Complete(context.Context, string, []llm.Message, ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, nil
}
func (*noopInnerHarness) CompleteWithTools(context.Context, string, []llm.Message, []llm.ToolDef, ...CompletionOption) (*llm.CompletionResponse, error) {
	return nil, nil
}
func (*noopInnerHarness) Stream(context.Context, string, []llm.Message, ...CompletionOption) (<-chan llm.StreamChunk, error) {
	return nil, nil
}
func (*noopInnerHarness) CompleteStructuredAny(context.Context, string, []llm.Message, any, ...CompletionOption) (any, error) {
	return nil, nil
}
func (*noopInnerHarness) CompleteStructuredAnyWithUsage(context.Context, string, []llm.Message, any, ...CompletionOption) (*StructuredCompletionResult, error) {
	return nil, nil
}
func (*noopInnerHarness) CallToolProto(context.Context, string, proto.Message, proto.Message) error {
	return nil
}
func (*noopInnerHarness) CallToolProtoStream(context.Context, string, proto.Message, proto.Message, sdkagent.ToolStreamCallback) error {
	return nil
}
func (*noopInnerHarness) ListTools() []ToolDescriptor { return nil }
func (*noopInnerHarness) GetToolDescriptor(context.Context, string) (*ToolDescriptor, error) {
	return nil, nil
}
func (*noopInnerHarness) GetToolCapabilities(context.Context, string) (*sdktypes.Capabilities, error) {
	return nil, nil
}
func (*noopInnerHarness) GetAllToolCapabilities(context.Context) (map[string]*sdktypes.Capabilities, error) {
	return nil, nil
}
func (*noopInnerHarness) QueryPlugin(context.Context, string, string, map[string]any) (any, error) {
	return nil, nil
}
func (*noopInnerHarness) ListPlugins() []PluginDescriptor { return nil }
func (*noopInnerHarness) DelegateToAgent(context.Context, string, agent.Task) (agent.Result, error) {
	return agent.Result{}, nil
}
func (*noopInnerHarness) ListAgents() []AgentDescriptor { return nil }
func (*noopInnerHarness) SubmitFinding(context.Context, agent.Finding) error {
	return nil
}
func (*noopInnerHarness) GetFindings(context.Context, FindingFilter) ([]agent.Finding, error) {
	return nil, nil
}
func (*noopInnerHarness) MissionID() types.ID     { return "" }
func (*noopInnerHarness) Mission() MissionContext { return MissionContext{} }
func (*noopInnerHarness) MissionExecutionContext() MissionExecutionContextSDK {
	return MissionExecutionContextSDK{}
}
func (*noopInnerHarness) GetMissionRunHistory(context.Context) ([]MissionRunSummarySDK, error) {
	return nil, nil
}
func (*noopInnerHarness) GetPreviousRunFindings(context.Context, FindingFilter) ([]agent.Finding, error) {
	return nil, nil
}
func (*noopInnerHarness) GetAllRunFindings(context.Context, FindingFilter) ([]agent.Finding, error) {
	return nil, nil
}
func (*noopInnerHarness) Target() TargetInfo       { return TargetInfo{} }
func (*noopInnerHarness) Tracer() trace.Tracer     { return nil }
func (*noopInnerHarness) Logger() *slog.Logger     { return slog.Default() }
func (*noopInnerHarness) Metrics() MetricsRecorder { return nil }

// The pointer return is dictated by the Harness interface
// (harness.go: TokenUsage() *llm.TokenTracker), so gocritic's suggestion to
// take a non-pointer type cannot be applied without breaking the contract
// this stub exists to satisfy.
//
//nolint:gocritic // ptrToRefParam: signature is fixed by the Harness interface.
func (*noopInnerHarness) TokenUsage() *llm.TokenTracker { return nil }
func (*noopInnerHarness) Workspace() workspace.Workspace {
	return nil
}
func (*noopInnerHarness) Workspaces() map[string]workspace.Workspace {
	return map[string]workspace.Workspace{}
}
