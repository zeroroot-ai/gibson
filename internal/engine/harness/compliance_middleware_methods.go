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

// This file implements the AgentHarness interface on ComplianceMiddleware.
// Every method either:
//   - Intercepts the call, emits a compliance signal around it (Emit=true
//     methods in the action table), or
//   - Passes through directly (Emit=false getters).
//
// The shape is deliberately uniform:
//
//   sip := m.beginSignal(ctx, method, request)
//   <inner call>
//   m.completeSignal(ctx, sip, err)
//   m.emit(ctx, sip)
//   return <inner result>
//
// Byte/token stamping and per-call tag merging happen inside beginSignal and
// completeSignal — this file just drives the shape.

// ────────────────────────────────────────────────────────────────────────────
// LLM methods (action = llm_call, effect = read)
// ────────────────────────────────────────────────────────────────────────────

func (m *ComplianceMiddleware) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: slot})
	resp, err := m.inner.Complete(ctx, slot, messages, opts...)
	m.stampLLMResponse(sip, resp)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return resp, err
}

func (m *ComplianceMiddleware) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	sip := m.beginSignal(ctx, MethodCompleteWithTools, LLMTarget{Slot: slot})
	resp, err := m.inner.CompleteWithTools(ctx, slot, messages, tools, opts...)
	m.stampLLMResponse(sip, resp)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return resp, err
}

func (m *ComplianceMiddleware) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (<-chan llm.StreamChunk, error) {
	sip := m.beginSignal(ctx, MethodStream, LLMTarget{Slot: slot})
	ch, err := m.inner.Stream(ctx, slot, messages, opts...)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return ch, err
}

func (m *ComplianceMiddleware) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
	sip := m.beginSignal(ctx, MethodCompleteStructuredAny, LLMTarget{Slot: slot})
	result, err := m.inner.CompleteStructuredAny(ctx, slot, messages, schemaType, opts...)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return result, err
}

func (m *ComplianceMiddleware) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
	sip := m.beginSignal(ctx, MethodCompleteStructuredAnyWithUsage, LLMTarget{Slot: slot})
	result, err := m.inner.CompleteStructuredAnyWithUsage(ctx, slot, messages, schemaType, opts...)
	if result != nil {
		// Refine resource_type / uri with the actual model that was chosen.
		if result.Model != "" {
			rt := "llm:" + result.Model
			sip.signal.ResourceType = rt
			uri := result.Model
			sip.signal.ResourceUri = &uri
		}
		if result.PromptTokens > 0 {
			tp := int32(result.PromptTokens)
			sip.signal.TokensPrompt = &tp
		}
		if result.CompletionTokens > 0 {
			tc := int32(result.CompletionTokens)
			sip.signal.TokensCompletion = &tc
		}
	}
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return result, err
}

// stampLLMResponse refines the in-progress signal with model id and token
// usage from the completion response. Called from Complete / CompleteWithTools.
func (m *ComplianceMiddleware) stampLLMResponse(sip *signalInProgress, resp *llm.CompletionResponse) {
	if resp == nil {
		return
	}
	if resp.Model != "" {
		sip.signal.ResourceType = "llm:" + resp.Model
		uri := resp.Model
		sip.signal.ResourceUri = &uri
	}
	if resp.Usage.PromptTokens > 0 {
		tp := int32(resp.Usage.PromptTokens)
		sip.signal.TokensPrompt = &tp
	}
	if resp.Usage.CompletionTokens > 0 {
		tc := int32(resp.Usage.CompletionTokens)
		sip.signal.TokensCompletion = &tc
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Tool methods
// ────────────────────────────────────────────────────────────────────────────

func (m *ComplianceMiddleware) CallToolProto(ctx context.Context, name string, request, response proto.Message) error {
	target := ToolCallTarget{
		Name:    name,
		Request: request,
	}
	sip := m.beginSignal(ctx, MethodCallToolProto, target)

	// Byte in/out measurement per Requirement 8.3/8.4.
	if request != nil {
		size := int64(proto.Size(request))
		sip.signal.BytesIn = &size
	}

	err := m.inner.CallToolProto(ctx, name, request, response)

	if response != nil {
		size := int64(proto.Size(response))
		sip.signal.BytesOut = &size
	}

	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return err
}

// CallToolProtoStream emits the same compliance signal envelope as
// CallToolProto and forwards every streaming event verbatim through the
// caller-supplied callback. Spec: headline-feature-completion R1.3.
func (m *ComplianceMiddleware) CallToolProtoStream(ctx context.Context, name string, request, response proto.Message, callback sdkagent.ToolStreamCallback) error {
	target := ToolCallTarget{
		Name:    name,
		Request: request,
	}
	sip := m.beginSignal(ctx, MethodCallToolProto, target)

	if request != nil {
		size := int64(proto.Size(request))
		sip.signal.BytesIn = &size
	}

	err := m.inner.CallToolProtoStream(ctx, name, request, response, callback)

	if response != nil {
		size := int64(proto.Size(response))
		sip.signal.BytesOut = &size
	}

	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return err
}

func (m *ComplianceMiddleware) ListTools() []ToolDescriptor {
	return m.inner.ListTools()
}

func (m *ComplianceMiddleware) GetToolDescriptor(ctx context.Context, name string) (*ToolDescriptor, error) {
	return m.inner.GetToolDescriptor(ctx, name)
}

func (m *ComplianceMiddleware) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	return m.inner.GetToolCapabilities(ctx, toolName)
}

func (m *ComplianceMiddleware) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	return m.inner.GetAllToolCapabilities(ctx)
}

// ────────────────────────────────────────────────────────────────────────────
// Memory access
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// Context / identity getters (pure pass-through)
// ────────────────────────────────────────────────────────────────────────────

func (m *ComplianceMiddleware) MissionID() types.ID {
	return m.inner.MissionID()
}

func (m *ComplianceMiddleware) Mission() MissionContext {
	return m.inner.Mission()
}

// Workspace returns the primary workspace from the inner harness.
// Spec: callback-harness-workspace-rpcs.
func (m *ComplianceMiddleware) Workspace() workspace.Workspace {
	return m.inner.Workspace()
}

// Workspaces returns all workspaces from the inner harness.
// Spec: callback-harness-workspace-rpcs.
func (m *ComplianceMiddleware) Workspaces() map[string]workspace.Workspace {
	return m.inner.Workspaces()
}

func (m *ComplianceMiddleware) MissionExecutionContext() MissionExecutionContextSDK {
	return m.inner.MissionExecutionContext()
}

func (m *ComplianceMiddleware) GetMissionRunHistory(ctx context.Context) ([]MissionRunSummarySDK, error) {
	return m.inner.GetMissionRunHistory(ctx)
}

func (m *ComplianceMiddleware) Target() TargetInfo {
	return m.inner.Target()
}

// ────────────────────────────────────────────────────────────────────────────
// Observability getters
// ────────────────────────────────────────────────────────────────────────────

func (m *ComplianceMiddleware) Tracer() trace.Tracer {
	return m.inner.Tracer()
}

func (m *ComplianceMiddleware) Logger() *slog.Logger {
	return m.inner.Logger()
}

func (m *ComplianceMiddleware) Metrics() MetricsRecorder {
	return m.inner.Metrics()
}

func (m *ComplianceMiddleware) TokenUsage() *llm.TokenTracker {
	return m.inner.TokenUsage()
}

// ────────────────────────────────────────────────────────────────────────────
// Findings management
// ────────────────────────────────────────────────────────────────────────────

func (m *ComplianceMiddleware) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	sip := m.beginSignal(ctx, MethodSubmitFinding, nil)
	err := m.inner.SubmitFinding(ctx, finding)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return err
}

func (m *ComplianceMiddleware) GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	sip := m.beginSignal(ctx, MethodGetFindings, GraphReadTarget{NodeType: "finding"})
	findings, err := m.inner.GetFindings(ctx, filter)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return findings, err
}

func (m *ComplianceMiddleware) GetPreviousRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	sip := m.beginSignal(ctx, MethodGetPreviousRunFindings, GraphReadTarget{NodeType: "finding"})
	findings, err := m.inner.GetPreviousRunFindings(ctx, filter)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return findings, err
}

func (m *ComplianceMiddleware) GetAllRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	sip := m.beginSignal(ctx, MethodGetAllRunFindings, GraphReadTarget{NodeType: "finding"})
	findings, err := m.inner.GetAllRunFindings(ctx, filter)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return findings, err
}

// ────────────────────────────────────────────────────────────────────────────
// Plugin access (task 8)
// ────────────────────────────────────────────────────────────────────────────

func (m *ComplianceMiddleware) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	sip := m.beginSignal(ctx, MethodQueryPlugin, PluginTarget{Name: name, Method: method})
	result, err := m.inner.QueryPlugin(ctx, name, method, params)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return result, err
}

func (m *ComplianceMiddleware) ListPlugins() []PluginDescriptor {
	return m.inner.ListPlugins()
}

// ────────────────────────────────────────────────────────────────────────────
// Sub-agent delegation (task 8)
// ────────────────────────────────────────────────────────────────────────────

// DelegateToAgent intercepts sub-agent delegation. Per the design doc,
// this emits a signal for the DELEGATION EVENT ITSELF (action=delegate),
// not for the child agent's signals — those emit independently when the
// child runs through its own harness chain.
func (m *ComplianceMiddleware) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	sip := m.beginSignal(ctx, MethodDelegateToAgent, name)
	result, err := m.inner.DelegateToAgent(ctx, name, task)
	m.completeSignal(ctx, sip, err)
	m.emit(ctx, sip)
	return result, err
}

func (m *ComplianceMiddleware) ListAgents() []AgentDescriptor {
	return m.inner.ListAgents()
}

// Compile-time assertion that ComplianceMiddleware implements AgentHarness.
var _ AgentHarness = (*ComplianceMiddleware)(nil)
