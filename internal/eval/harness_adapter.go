package eval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/sdk/agent"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	"github.com/zeroroot-ai/sdk/finding"
	"github.com/zeroroot-ai/sdk/llm"
	"github.com/zeroroot-ai/sdk/mission"
	"github.com/zeroroot-ai/sdk/planning"
	"github.com/zeroroot-ai/sdk/plugin"
	"github.com/zeroroot-ai/sdk/tool"
	"github.com/zeroroot-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	gibsonAgent "github.com/zeroroot-ai/gibson/internal/agent"
	gibsonHarness "github.com/zeroroot-ai/gibson/internal/harness"
	gibsonLLM "github.com/zeroroot-ai/gibson/internal/llm"
	gibsonTypes "github.com/zeroroot-ai/gibson/internal/types"
	gibsonSchema "github.com/zeroroot-ai/sdk/schema"
)

var (
	// ErrNotSupported is returned for operations not supported in the eval context.
	// Mission management operations (CreateMission, RunMission, etc.) are intentionally
	// unsupported during eval runs — use daemon missions for orchestration.
	// Callers can check with errors.Is(err, eval.ErrNotSupported).
	ErrNotSupported = errors.New("not supported in eval context")
)

// GibsonHarnessAdapter adapts Gibson's internal AgentHarness to the SDK's agent.Harness interface.
type GibsonHarnessAdapter struct {
	inner gibsonHarness.AgentHarness
}

// NewGibsonHarnessAdapter creates a new adapter that wraps a Gibson AgentHarness.
func NewGibsonHarnessAdapter(inner gibsonHarness.AgentHarness) *GibsonHarnessAdapter {
	return &GibsonHarnessAdapter{inner: inner}
}

// Complete performs a single LLM completion request.
func (a *GibsonHarnessAdapter) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...llm.CompletionOption) (*llm.CompletionResponse, error) {
	gibsonMessages := convertMessagesToGibson(messages)
	gibsonOpts := convertCompletionOptionsToGibson(opts)
	gibsonResp, err := a.inner.Complete(ctx, slot, gibsonMessages, gibsonOpts...)
	if err != nil {
		return nil, err
	}
	return convertCompletionResponseToSDK(gibsonResp), nil
}

// CompleteWithTools performs a completion with tool calling enabled.
func (a *GibsonHarnessAdapter) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	gibsonMessages := convertMessagesToGibson(messages)
	gibsonTools := convertToolDefsToGibson(tools)
	gibsonResp, err := a.inner.CompleteWithTools(ctx, slot, gibsonMessages, gibsonTools)
	if err != nil {
		return nil, err
	}
	return convertCompletionResponseToSDK(gibsonResp), nil
}

// Stream performs a streaming completion request.
func (a *GibsonHarnessAdapter) Stream(ctx context.Context, slot string, messages []llm.Message) (<-chan llm.StreamChunk, error) {
	gibsonMessages := convertMessagesToGibson(messages)
	gibsonChunks, err := a.inner.Stream(ctx, slot, gibsonMessages)
	if err != nil {
		return nil, err
	}
	sdkChunks := make(chan llm.StreamChunk, 10)
	go func() {
		defer close(sdkChunks)
		for chunk := range gibsonChunks {
			sdkChunk := convertStreamChunkToSDK(chunk)
			select {
			case sdkChunks <- sdkChunk:
			case <-ctx.Done():
				return
			}
		}
	}()
	return sdkChunks, nil
}

// CallToolProto invokes a tool by name with proto request/response messages.
// This delegates to the inner Gibson harness.
func (a *GibsonHarnessAdapter) CallToolProto(ctx context.Context, name string, request, response proto.Message) error {
	return a.inner.CallToolProto(ctx, name, request, response)
}

// CallToolProtoStream invokes a tool with streaming support.
// This is a placeholder implementation that falls back to non-streaming execution.
func (a *GibsonHarnessAdapter) CallToolProtoStream(ctx context.Context, name string, request, response proto.Message, callback agent.ToolStreamCallback) error {
	// For now, delegate to non-streaming CallToolProto
	// Future: implement actual streaming through the harness
	return a.inner.CallToolProto(ctx, name, request, response)
}

// ListTools returns descriptors for all available tools.
func (a *GibsonHarnessAdapter) ListTools(ctx context.Context) ([]tool.Descriptor, error) {
	gibsonTools := a.inner.ListTools()
	sdkTools := make([]tool.Descriptor, len(gibsonTools))
	for i, t := range gibsonTools {
		sdkTools[i] = tool.Descriptor{
			Name:              t.Name,
			Version:           t.Version,
			Description:       t.Description,
			Tags:              t.Tags,
			InputMessageType:  t.InputProtoType,
			OutputMessageType: t.OutputProtoType,
		}
	}
	return sdkTools, nil
}

// QueryPlugin sends a query to a plugin and returns the result.
func (a *GibsonHarnessAdapter) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	return a.inner.QueryPlugin(ctx, name, method, params)
}

// ListPlugins returns descriptors for all available plugins.
func (a *GibsonHarnessAdapter) ListPlugins(ctx context.Context) ([]plugin.Descriptor, error) {
	gibsonPlugins := a.inner.ListPlugins()
	sdkPlugins := make([]plugin.Descriptor, len(gibsonPlugins))
	for i, p := range gibsonPlugins {
		methods := make([]plugin.MethodDescriptor, len(p.Methods))
		for j, m := range p.Methods {
			methods[j] = plugin.MethodDescriptor{
				Name:        m.Name,
				Description: m.Description,
				// InputSchema / OutputSchema removed in plugin-runtime Spec 2 Phase 1.
				// The new manifest-driven MethodDescriptor carries Name+Description only.
				// Typed schema dispatch is handled via the plugin's proto FileDescriptorSet
				// uploaded at registration (plugin_install.proto_descriptor_set).
			}
		}
		sdkPlugins[i] = plugin.Descriptor{
			Name:        p.Name,
			Version:     p.Version,
			Description: "",
			Methods:     methods,
		}
	}
	return sdkPlugins, nil
}

// DelegateToAgent assigns a task to another agent for execution.
func (a *GibsonHarnessAdapter) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	gibsonTask := convertTaskToGibson(task)
	gibsonResult, err := a.inner.DelegateToAgent(ctx, name, gibsonTask)
	if err != nil {
		return agent.Result{}, err
	}
	return convertResultToSDK(gibsonResult), nil
}

// ListAgents returns descriptors for all available agents.
func (a *GibsonHarnessAdapter) ListAgents(ctx context.Context) ([]agent.Descriptor, error) {
	gibsonAgents := a.inner.ListAgents()
	sdkAgents := make([]agent.Descriptor, len(gibsonAgents))
	for i, agentDesc := range gibsonAgents {
		sdkAgents[i] = agent.Descriptor{
			Name:         agentDesc.Name,
			Version:      agentDesc.Version,
			Description:  agentDesc.Description,
			Capabilities: agentDesc.Capabilities, // Already []string
		}
	}
	return sdkAgents, nil
}

// SubmitFinding records a new security finding.
func (a *GibsonHarnessAdapter) SubmitFinding(ctx context.Context, f *finding.Finding) error {
	gibsonFinding := convertFindingToGibson(f)
	return a.inner.SubmitFinding(ctx, gibsonFinding)
}

// Mission returns the current mission context.
func (a *GibsonHarnessAdapter) Mission() types.MissionContext {
	gibsonMission := a.inner.Mission()
	return types.MissionContext{
		ID:           string(gibsonMission.ID),
		Name:         gibsonMission.Name,
		CurrentAgent: gibsonMission.CurrentAgent,
		Phase:        gibsonMission.Phase,
		Metadata:     gibsonMission.Metadata,
	}
}

// Target returns information about the target being tested.
func (a *GibsonHarnessAdapter) Target() types.TargetInfo {
	gibsonTarget := a.inner.Target()

	// Build connection map from URL and Headers fields
	// This provides compatibility as we migrate to schema-based targets
	connection := make(map[string]any)
	if gibsonTarget.URL != "" {
		connection["url"] = gibsonTarget.URL
	}
	if len(gibsonTarget.Headers) > 0 {
		connection["headers"] = gibsonTarget.Headers
	}

	return types.TargetInfo{
		ID:         string(gibsonTarget.ID),
		Name:       gibsonTarget.Name,
		Type:       gibsonTarget.Type, // Type is now string, not enum
		Provider:   gibsonTarget.Provider,
		Connection: connection,
		Metadata:   gibsonTarget.Metadata,
	}
}

// Tracer returns an OpenTelemetry tracer for distributed tracing.
func (a *GibsonHarnessAdapter) Tracer() trace.Tracer {
	return a.inner.Tracer()
}

// Logger returns a structured logger for the agent.
func (a *GibsonHarnessAdapter) Logger() *slog.Logger {
	return a.inner.Logger()
}

// TokenUsage returns the token usage tracker for this execution.
func (a *GibsonHarnessAdapter) TokenUsage() llm.TokenTracker {
	return &tokenTrackerAdapter{slotTracker: make(map[string]llm.TokenUsage)}
}

type tokenTrackerAdapter struct {
	slotTracker map[string]llm.TokenUsage
}

func (t *tokenTrackerAdapter) Add(slot string, usage llm.TokenUsage) {
	current := t.slotTracker[slot]
	current.InputTokens += usage.InputTokens
	current.OutputTokens += usage.OutputTokens
	current.TotalTokens += usage.TotalTokens
	t.slotTracker[slot] = current
}

func (t *tokenTrackerAdapter) Total() llm.TokenUsage {
	var total llm.TokenUsage
	for _, usage := range t.slotTracker {
		total.InputTokens += usage.InputTokens
		total.OutputTokens += usage.OutputTokens
		total.TotalTokens += usage.TotalTokens
	}
	return total
}

func (t *tokenTrackerAdapter) BySlot(slot string) llm.TokenUsage {
	return t.slotTracker[slot]
}

func (t *tokenTrackerAdapter) Reset() {
	t.slotTracker = make(map[string]llm.TokenUsage)
}

func (t *tokenTrackerAdapter) Slots() []string {
	slots := make([]string, 0, len(t.slotTracker))
	for slot := range t.slotTracker {
		slots = append(slots, slot)
	}
	return slots
}

// PlanContext returns the planning context for the current execution.
func (a *GibsonHarnessAdapter) PlanContext() planning.PlanningContext {
	return nil
}

// ReportStepHints allows agents to provide feedback to the planning system.
func (a *GibsonHarnessAdapter) ReportStepHints(ctx context.Context, hints *planning.StepHints) error {
	return nil
}

// Type conversion helpers

func convertMessagesToGibson(messages []llm.Message) []gibsonLLM.Message {
	gibsonMessages := make([]gibsonLLM.Message, len(messages))
	for i, msg := range messages {
		gibsonMessages[i] = gibsonLLM.Message{
			Role:    gibsonLLM.Role(msg.Role),
			Content: msg.Content,
			Name:    msg.Name,
		}
		if len(msg.ToolCalls) > 0 {
			gibsonMessages[i].ToolCalls = make([]gibsonLLM.ToolCall, len(msg.ToolCalls))
			for j, tc := range msg.ToolCalls {
				gibsonMessages[i].ToolCalls[j] = gibsonLLM.ToolCall{
					ID:        tc.ID,
					Name:      tc.Name,
					Arguments: tc.Arguments,
				}
			}
		}
		if len(msg.ToolResults) > 0 {
			gibsonMessages[i].ToolCallID = msg.ToolResults[0].ToolCallID
		}
	}
	return gibsonMessages
}

func convertCompletionOptionsToGibson(opts []llm.CompletionOption) []gibsonHarness.CompletionOption {
	req := &llm.CompletionRequest{}
	for _, opt := range opts {
		opt(req)
	}
	var gibsonOpts []gibsonHarness.CompletionOption
	if req.Temperature != nil {
		gibsonOpts = append(gibsonOpts, gibsonHarness.WithTemperature(*req.Temperature))
	}
	if req.MaxTokens != nil {
		gibsonOpts = append(gibsonOpts, gibsonHarness.WithMaxTokens(*req.MaxTokens))
	}
	if req.TopP != nil {
		gibsonOpts = append(gibsonOpts, gibsonHarness.WithTopP(*req.TopP))
	}
	if len(req.Stop) > 0 {
		gibsonOpts = append(gibsonOpts, gibsonHarness.WithStopSequences(req.Stop...))
	}
	return gibsonOpts
}

func convertToolDefsToGibson(tools []llm.ToolDef) []gibsonLLM.ToolDef {
	gibsonTools := make([]gibsonLLM.ToolDef, len(tools))
	for i, t := range tools {
		gibsonTools[i] = gibsonLLM.ToolDef{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  convertMapToJSONSchema(t.Parameters),
		}
	}
	return gibsonTools
}

func convertMapToJSONSchema(m map[string]any) gibsonSchema.JSON {
	var s gibsonSchema.JSON
	data, err := json.Marshal(m)
	if err != nil {
		return gibsonSchema.JSON{Type: "object"}
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return gibsonSchema.JSON{Type: "object"}
	}
	return s
}

func convertCompletionResponseToSDK(gibsonResp *gibsonLLM.CompletionResponse) *llm.CompletionResponse {
	resp := &llm.CompletionResponse{
		Content:      gibsonResp.Message.Content,
		FinishReason: string(gibsonResp.FinishReason),
		Usage: llm.TokenUsage{
			InputTokens:  gibsonResp.Usage.PromptTokens,
			OutputTokens: gibsonResp.Usage.CompletionTokens,
			TotalTokens:  gibsonResp.Usage.TotalTokens,
		},
	}
	if len(gibsonResp.Message.ToolCalls) > 0 {
		resp.ToolCalls = make([]llm.ToolCall, len(gibsonResp.Message.ToolCalls))
		for i, tc := range gibsonResp.Message.ToolCalls {
			resp.ToolCalls[i] = llm.ToolCall{
				ID:        tc.ID,
				Name:      tc.Name,
				Arguments: tc.Arguments,
			}
		}
	}
	return resp
}

func convertStreamChunkToSDK(gibsonChunk gibsonLLM.StreamChunk) llm.StreamChunk {
	return llm.StreamChunk{
		Delta:        gibsonChunk.Delta.Content,
		FinishReason: string(gibsonChunk.FinishReason),
	}
}

func convertFindingToGibson(f *finding.Finding) gibsonAgent.Finding {
	return gibsonAgent.Finding{
		ID:          gibsonTypes.ID(f.ID),
		Title:       f.Title,
		Description: f.Description,
		Category:    string(f.Category),
		Severity:    convertSeverityToGibson(f.Severity),
		Confidence:  f.Confidence,
	}
}

func convertFindingFromGibson(gf gibsonAgent.Finding) *finding.Finding {
	return &finding.Finding{
		ID:          string(gf.ID),
		Title:       gf.Title,
		Description: gf.Description,
		Category:    gf.Category, // Category is now a string type
		Severity:    convertSeverityFromGibson(gf.Severity),
		Confidence:  gf.Confidence,
	}
}

func convertSeverityToGibson(s finding.Severity) gibsonAgent.FindingSeverity {
	switch s {
	case finding.SeverityCritical:
		return gibsonAgent.SeverityCritical
	case finding.SeverityHigh:
		return gibsonAgent.SeverityHigh
	case finding.SeverityMedium:
		return gibsonAgent.SeverityMedium
	case finding.SeverityLow:
		return gibsonAgent.SeverityLow
	case finding.SeverityInfo:
		return gibsonAgent.SeverityInfo
	default:
		return gibsonAgent.SeverityInfo
	}
}

func convertSeverityFromGibson(s gibsonAgent.FindingSeverity) finding.Severity {
	switch s {
	case gibsonAgent.SeverityCritical:
		return finding.SeverityCritical
	case gibsonAgent.SeverityHigh:
		return finding.SeverityHigh
	case gibsonAgent.SeverityMedium:
		return finding.SeverityMedium
	case gibsonAgent.SeverityLow:
		return finding.SeverityLow
	case gibsonAgent.SeverityInfo:
		return finding.SeverityInfo
	default:
		return finding.SeverityInfo
	}
}

// convertTaskToGibson converts an SDK agent.Task to a Gibson internal agent.Task.
func convertTaskToGibson(t agent.Task) gibsonAgent.Task {
	return gibsonAgent.Task{
		ID:          gibsonTypes.NewID(),
		Name:        t.Goal,
		Description: t.Goal,
		Goal:        t.Goal,
		Context:     t.Context,
		Input:       t.Context,
	}
}

// convertResultToSDK converts a Gibson internal agent.Result to an SDK agent.Result.
func convertResultToSDK(r gibsonAgent.Result) agent.Result {
	sdkResult := agent.Result{
		Status: agent.ResultStatus(r.Status),
		Output: r.Output,
	}
	if r.Error != nil {
		sdkResult.Error = fmt.Errorf("%s", r.Error.Message)
		sdkResult.ErrorInfo = &agent.ResultError{
			Message: r.Error.Message,
			Code:    r.Error.Code,
		}
	}
	// Copy finding IDs from findings slice
	sdkResult.Findings = make([]string, len(r.Findings))
	for i, f := range r.Findings {
		sdkResult.Findings[i] = string(f.ID)
	}
	return sdkResult
}

// convertFilterToGibson converts SDK finding.Filter to Gibson FindingFilter.
func convertFilterToGibson(filter finding.Filter) gibsonHarness.FindingFilter {
	gibsonFilter := gibsonHarness.FindingFilter{}
	if len(filter.Severities) > 0 {
		sev := convertSeverityToGibson(filter.Severities[0])
		gibsonFilter.Severity = &sev
	}
	if len(filter.Categories) > 0 {
		cat := string(filter.Categories[0])
		gibsonFilter.Category = &cat
	}
	return gibsonFilter
}

// CallToolsParallel executes multiple tool calls concurrently.
func (a *GibsonHarnessAdapter) CallToolsParallel(ctx context.Context, calls []agent.ToolCall, maxConcurrency int) ([]agent.ToolResult, error) {
	return nil, fmt.Errorf("%w: CallToolsParallel not available in eval context", ErrNotSupported)
}

// CompleteStructured performs a completion with provider-native structured output.
func (a *GibsonHarnessAdapter) CompleteStructured(ctx context.Context, slot string, messages []llm.Message, schema any) (any, error) {
	return nil, fmt.Errorf("%w: CompleteStructured not available in eval context", ErrNotSupported)
}

// CompleteStructuredAny is an alias for CompleteStructured for compatibility.
func (a *GibsonHarnessAdapter) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schema any) (any, error) {
	return a.CompleteStructured(ctx, slot, messages, schema)
}

// ============================================================================
// Mission Management Methods (Not Supported in Eval Adapter)
// ============================================================================

// CreateMission creates a new mission from a mission definition.
func (a *GibsonHarnessAdapter) CreateMission(ctx context.Context, mission any, targetID string, opts *mission.CreateMissionOpts) (*mission.MissionInfo, error) {
	return nil, fmt.Errorf("%w: CreateMission not available in eval context", ErrNotSupported)
}

// RunMission queues a mission for execution.
func (a *GibsonHarnessAdapter) RunMission(ctx context.Context, missionID string, opts *mission.RunMissionOpts) error {
	return fmt.Errorf("%w: RunMission not available in eval context", ErrNotSupported)
}

// GetMissionStatus returns the current state of a mission.
func (a *GibsonHarnessAdapter) GetMissionStatus(ctx context.Context, missionID string) (*mission.MissionStatusInfo, error) {
	return nil, fmt.Errorf("%w: GetMissionStatus not available in eval context", ErrNotSupported)
}

// WaitForMission blocks until a mission completes or the timeout expires.
func (a *GibsonHarnessAdapter) WaitForMission(ctx context.Context, missionID string, timeout time.Duration) (*mission.MissionResult, error) {
	return nil, fmt.Errorf("%w: WaitForMission not available in eval context", ErrNotSupported)
}

// ListMissions returns missions matching the provided filter criteria.
func (a *GibsonHarnessAdapter) ListMissions(ctx context.Context, filter *mission.MissionFilter) ([]*mission.MissionInfo, error) {
	return nil, fmt.Errorf("%w: ListMissions not available in eval context", ErrNotSupported)
}

// CancelMission requests cancellation of a running mission.
func (a *GibsonHarnessAdapter) CancelMission(ctx context.Context, missionID string) error {
	return fmt.Errorf("%w: CancelMission not available in eval context", ErrNotSupported)
}

// GetMissionResults returns the final results of a completed mission.
func (a *GibsonHarnessAdapter) GetMissionResults(ctx context.Context, missionID string) (*mission.MissionResult, error) {
	return nil, fmt.Errorf("%w: GetMissionResults not available in eval context", ErrNotSupported)
}

// ============================================================================
// Credential Operations (Not Supported in Eval Adapter)
// ============================================================================

// GetCredential retrieves a credential by name from the credential store.
func (a *GibsonHarnessAdapter) GetCredential(ctx context.Context, name string) (*types.Credential, error) {
	return nil, fmt.Errorf("%w: GetCredential not available in eval context", ErrNotSupported)
}

// ============================================================================
// Proto-Based GraphRAG Operations (Not Supported in Eval Adapter)
// ============================================================================

// StoreNode stores a graph node using proto message.
func (a *GibsonHarnessAdapter) StoreNode(ctx context.Context, node *graphragpb.GraphNode) (string, error) {
	return "", fmt.Errorf("%w: StoreNode not available in eval context", ErrNotSupported)
}

// Observe is a no-op in the eval adapter: evaluation trajectories capture LLM,
// tool, and finding activity, not World observations (ADR-0007).
func (a *GibsonHarnessAdapter) Observe(_ context.Context, _ agent.Observation) error {
	return nil
}

// QueueToolWork queues multiple tool executions for parallel processing.
// Not supported in eval adapter.
func (a *GibsonHarnessAdapter) QueueToolWork(ctx context.Context, toolName string, inputs []proto.Message) (string, error) {
	return "", fmt.Errorf("%w: QueueToolWork not available in eval context", ErrNotSupported)
}

// ToolResults returns a channel for receiving results from a queued tool job.
// Not implemented in eval adapter.
func (a *GibsonHarnessAdapter) ToolResults(ctx context.Context, jobID string) <-chan agent.QueuedToolResult {
	ch := make(chan agent.QueuedToolResult)
	close(ch)
	return ch
}

// Workspace returns the primary workspace for single-repository missions.
// Not implemented in eval harness - returns nil.
func (a *GibsonHarnessAdapter) Workspace() workspace.Workspace {
	return nil
}

// Workspaces returns all workspaces keyed by repository name.
// Not implemented in eval harness - returns empty map.
func (a *GibsonHarnessAdapter) Workspaces() map[string]workspace.Workspace {
	return make(map[string]workspace.Workspace)
}

// Authorize is a no-op in the eval harness adapter — eval runs bypass
// component authz enforcement because they run under direct evaluation
// context, not via the daemon callback channel.
func (a *GibsonHarnessAdapter) Authorize(_ context.Context, _, _ string) error {
	return nil
}

var _ agent.Harness = (*GibsonHarnessAdapter)(nil)
