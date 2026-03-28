package eval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/api/gen/graphragpb"
	"github.com/zero-day-ai/sdk/codegen/workspace"
	"github.com/zero-day-ai/sdk/finding"
	"github.com/zero-day-ai/sdk/graphrag"
	"github.com/zero-day-ai/sdk/llm"
	"github.com/zero-day-ai/sdk/memory"
	"github.com/zero-day-ai/sdk/mission"
	"github.com/zero-day-ai/sdk/planning"
	"github.com/zero-day-ai/sdk/plugin"
	"github.com/zero-day-ai/sdk/schema"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	gibsonAgent "github.com/zero-day-ai/gibson/internal/agent"
	gibsonHarness "github.com/zero-day-ai/gibson/internal/harness"
	gibsonLLM "github.com/zero-day-ai/gibson/internal/llm"
	gibsonMemory "github.com/zero-day-ai/gibson/internal/memory"
	gibsonTypes "github.com/zero-day-ai/gibson/internal/types"
	gibsonSchema "github.com/zero-day-ai/sdk/schema"
)

var (
	// ErrNotImplemented is returned for features not yet implemented in the adapter
	ErrNotImplemented = errors.New("feature not yet implemented in Gibson harness adapter")
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
				Name:         m.Name,
				Description:  m.Description,
				InputSchema:  schema.Any(),
				OutputSchema: schema.Any(),
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
	return agent.Result{}, fmt.Errorf("agent delegation not yet implemented in harness adapter")
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

// GetFindings retrieves findings matching the given filter criteria.
func (a *GibsonHarnessAdapter) GetFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error) {
	gibsonFilter := gibsonHarness.NewFindingFilter()
	if len(filter.Severities) > 0 {
		severity := convertSeverityToGibson(filter.Severities[0])
		gibsonFilter = gibsonFilter.WithSeverity(severity)
	}
	if len(filter.Categories) > 0 {
		gibsonFilter = gibsonFilter.WithCategory(string(filter.Categories[0]))
	}
	gibsonFindings, err := a.inner.GetFindings(ctx, *gibsonFilter)
	if err != nil {
		return nil, err
	}
	sdkFindings := make([]*finding.Finding, len(gibsonFindings))
	for i, gf := range gibsonFindings {
		sdkFindings[i] = convertFindingFromGibson(gf)
	}
	return sdkFindings, nil
}

// Memory returns the memory store for this agent.
func (a *GibsonHarnessAdapter) Memory() memory.Store {
	return &memoryStoreAdapter{inner: a.inner.Memory()}
}

type memoryStoreAdapter struct {
	inner gibsonMemory.MemoryStore
}

func (m *memoryStoreAdapter) Working() memory.WorkingMemory {
	return &workingMemoryAdapter{inner: m.inner.Working()}
}

func (m *memoryStoreAdapter) Mission() memory.MissionMemory {
	return nil
}

func (m *memoryStoreAdapter) LongTerm() memory.LongTermMemory {
	return nil
}

type workingMemoryAdapter struct {
	inner interface {
		Get(key string) (any, bool)
		Set(key string, value any) error
		Delete(key string) bool
		List() []string
	}
}

func (m *workingMemoryAdapter) Get(ctx context.Context, key string) (any, error) {
	val, ok := m.inner.Get(key)
	if !ok {
		return nil, memory.ErrNotFound
	}
	return val, nil
}

func (m *workingMemoryAdapter) Set(ctx context.Context, key string, value any) error {
	return m.inner.Set(key, value)
}

func (m *workingMemoryAdapter) Delete(ctx context.Context, key string) error {
	m.inner.Delete(key)
	return nil
}

func (m *workingMemoryAdapter) Clear(ctx context.Context) error {
	for _, key := range m.inner.List() {
		m.inner.Delete(key)
	}
	return nil
}

func (m *workingMemoryAdapter) Keys(ctx context.Context) ([]string, error) {
	return m.inner.List(), nil
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

// QueryGraphRAG performs a semantic or hybrid query against the knowledge graph.
func (a *GibsonHarnessAdapter) QueryGraphRAG(ctx context.Context, query graphrag.Query) ([]graphrag.Result, error) {
	return nil, ErrNotImplemented
}

// FindSimilarAttacks searches for attack patterns semantically similar to the given content.
func (a *GibsonHarnessAdapter) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]graphrag.AttackPattern, error) {
	return nil, ErrNotImplemented
}

// FindSimilarFindings searches for findings semantically similar to the referenced finding.
func (a *GibsonHarnessAdapter) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]graphrag.FindingNode, error) {
	return nil, ErrNotImplemented
}

// GetAttackChains discovers multi-step attack paths starting from a technique.
func (a *GibsonHarnessAdapter) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]graphrag.AttackChain, error) {
	return nil, ErrNotImplemented
}

// GetRelatedFindings retrieves findings connected via SIMILAR_TO or RELATED_TO relationships.
func (a *GibsonHarnessAdapter) GetRelatedFindings(ctx context.Context, findingID string) ([]graphrag.FindingNode, error) {
	return nil, ErrNotImplemented
}

// StoreGraphNode stores an arbitrary node in the knowledge graph.
func (a *GibsonHarnessAdapter) StoreGraphNode(ctx context.Context, node graphrag.GraphNode) (string, error) {
	return "", ErrNotImplemented
}

// CreateGraphRelationship creates a relationship between two existing nodes.
func (a *GibsonHarnessAdapter) CreateGraphRelationship(ctx context.Context, rel graphrag.Relationship) error {
	return ErrNotImplemented
}

// StoreGraphBatch stores multiple nodes and relationships atomically.
func (a *GibsonHarnessAdapter) StoreGraphBatch(ctx context.Context, batch graphrag.Batch) ([]string, error) {
	return nil, ErrNotImplemented
}

// TraverseGraph walks the graph from a starting node following relationships.
func (a *GibsonHarnessAdapter) TraverseGraph(ctx context.Context, startNodeID string, opts graphrag.TraversalOptions) ([]graphrag.TraversalResult, error) {
	return nil, ErrNotImplemented
}

// GraphRAGHealth returns the health status of the GraphRAG subsystem.
func (a *GibsonHarnessAdapter) GraphRAGHealth(ctx context.Context) types.HealthStatus {
	return types.HealthStatus{
		Status:  "unavailable",
		Message: "GraphRAG not yet integrated with Gibson harness",
	}
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

// MissionExecutionContext returns the full execution context for the current run.
func (a *GibsonHarnessAdapter) MissionExecutionContext() types.MissionExecutionContext {
	gibsonCtx := a.inner.MissionExecutionContext()
	return types.MissionExecutionContext{
		MissionID:            gibsonCtx.MissionID,
		MissionName:          gibsonCtx.MissionName,
		RunNumber:            gibsonCtx.RunNumber,
		IsResumed:            gibsonCtx.IsResumed,
		PreviousRunID:        gibsonCtx.PreviousRunID,
		PreviousRunStatus:    gibsonCtx.PreviousRunStatus,
		TotalFindingsAllRuns: gibsonCtx.TotalFindingsAllRuns,
		MemoryContinuity:     gibsonCtx.MemoryContinuity,
	}
}

// GetMissionRunHistory returns all runs for this mission name.
func (a *GibsonHarnessAdapter) GetMissionRunHistory(ctx context.Context) ([]types.MissionRunSummary, error) {
	gibsonRuns, err := a.inner.GetMissionRunHistory(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]types.MissionRunSummary, len(gibsonRuns))
	for i, r := range gibsonRuns {
		result[i] = types.MissionRunSummary{
			MissionID:     r.MissionID,
			RunNumber:     r.RunNumber,
			Status:        r.Status,
			FindingsCount: r.FindingsCount,
			CreatedAt:     r.CreatedAt,
			CompletedAt:   r.CompletedAt,
		}
	}
	return result, nil
}

// GetPreviousRunFindings returns findings from the immediate prior run.
func (a *GibsonHarnessAdapter) GetPreviousRunFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error) {
	// Convert SDK filter to Gibson filter
	gibsonFilter := convertFilterToGibson(filter)
	gibsonFindings, err := a.inner.GetPreviousRunFindings(ctx, gibsonFilter)
	if err != nil {
		return nil, err
	}
	result := make([]*finding.Finding, len(gibsonFindings))
	for i, f := range gibsonFindings {
		result[i] = convertFindingFromGibson(f)
	}
	return result, nil
}

// GetAllRunFindings returns findings from all runs of this mission.
func (a *GibsonHarnessAdapter) GetAllRunFindings(ctx context.Context, filter finding.Filter) ([]*finding.Finding, error) {
	// Convert SDK filter to Gibson filter
	gibsonFilter := convertFilterToGibson(filter)
	gibsonFindings, err := a.inner.GetAllRunFindings(ctx, gibsonFilter)
	if err != nil {
		return nil, err
	}
	result := make([]*finding.Finding, len(gibsonFindings))
	for i, f := range gibsonFindings {
		result[i] = convertFindingFromGibson(f)
	}
	return result, nil
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

// StoreSemantic stores a node with semantic search capabilities (requires Content).
func (a *GibsonHarnessAdapter) StoreSemantic(ctx context.Context, node graphrag.GraphNode) (string, error) {
	return "", ErrNotImplemented
}

// StoreStructured stores a node without semantic search (no embedding required).
func (a *GibsonHarnessAdapter) StoreStructured(ctx context.Context, node graphrag.GraphNode) (string, error) {
	return "", ErrNotImplemented
}

// QuerySemantic performs a semantic-only query (no structured fallback).
func (a *GibsonHarnessAdapter) QuerySemantic(ctx context.Context, query graphrag.Query) ([]graphrag.Result, error) {
	return nil, ErrNotImplemented
}

// QueryStructured performs a structured-only query (no vector search).
func (a *GibsonHarnessAdapter) QueryStructured(ctx context.Context, query graphrag.Query) ([]graphrag.Result, error) {
	return nil, ErrNotImplemented
}

// CallToolsParallel executes multiple tool calls concurrently.
func (a *GibsonHarnessAdapter) CallToolsParallel(ctx context.Context, calls []agent.ToolCall, maxConcurrency int) ([]agent.ToolResult, error) {
	// Not yet implemented - requires parallel execution support
	return nil, ErrNotImplemented
}

// CompleteStructured performs a completion with provider-native structured output.
func (a *GibsonHarnessAdapter) CompleteStructured(ctx context.Context, slot string, messages []llm.Message, schema any) (any, error) {
	// Not yet implemented - requires structured output support
	return nil, ErrNotImplemented
}

// CompleteStructuredAny is an alias for CompleteStructured for compatibility.
func (a *GibsonHarnessAdapter) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schema any) (any, error) {
	return a.CompleteStructured(ctx, slot, messages, schema)
}

// ============================================================================
// Mission Management Methods (Not Implemented in Eval Adapter)
// ============================================================================

// CreateMission creates a new mission from a workflow definition.
func (a *GibsonHarnessAdapter) CreateMission(ctx context.Context, workflow any, targetID string, opts *mission.CreateMissionOpts) (*mission.MissionInfo, error) {
	return nil, ErrNotImplemented
}

// RunMission queues a mission for execution.
func (a *GibsonHarnessAdapter) RunMission(ctx context.Context, missionID string, opts *mission.RunMissionOpts) error {
	return ErrNotImplemented
}

// GetMissionStatus returns the current state of a mission.
func (a *GibsonHarnessAdapter) GetMissionStatus(ctx context.Context, missionID string) (*mission.MissionStatusInfo, error) {
	return nil, ErrNotImplemented
}

// WaitForMission blocks until a mission completes or the timeout expires.
func (a *GibsonHarnessAdapter) WaitForMission(ctx context.Context, missionID string, timeout time.Duration) (*mission.MissionResult, error) {
	return nil, ErrNotImplemented
}

// ListMissions returns missions matching the provided filter criteria.
func (a *GibsonHarnessAdapter) ListMissions(ctx context.Context, filter *mission.MissionFilter) ([]*mission.MissionInfo, error) {
	return nil, ErrNotImplemented
}

// CancelMission requests cancellation of a running mission.
func (a *GibsonHarnessAdapter) CancelMission(ctx context.Context, missionID string) error {
	return ErrNotImplemented
}

// GetMissionResults returns the final results of a completed mission.
func (a *GibsonHarnessAdapter) GetMissionResults(ctx context.Context, missionID string) (*mission.MissionResult, error) {
	return nil, ErrNotImplemented
}

// ============================================================================
// Credential Operations (Not Implemented in Eval Adapter)
// ============================================================================

// GetCredential retrieves a credential by name from the credential store.
func (a *GibsonHarnessAdapter) GetCredential(ctx context.Context, name string) (*types.Credential, error) {
	return nil, ErrNotImplemented
}

// ============================================================================
// Proto-Based GraphRAG Operations (Not Implemented in Eval Adapter)
// ============================================================================

// QueryNodes queries the knowledge graph using proto messages.
func (a *GibsonHarnessAdapter) QueryNodes(ctx context.Context, query *graphragpb.GraphQuery) ([]*graphragpb.QueryResult, error) {
	return nil, ErrNotImplemented
}

// StoreNode stores a graph node using proto message.
func (a *GibsonHarnessAdapter) StoreNode(ctx context.Context, node *graphragpb.GraphNode) (string, error) {
	return "", ErrNotImplemented
}

// QueueToolWork queues multiple tool executions for parallel processing.
// Not implemented in eval adapter.
func (a *GibsonHarnessAdapter) QueueToolWork(ctx context.Context, toolName string, inputs []proto.Message) (string, error) {
	return "", ErrNotImplemented
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

// TaxonomyRegistry returns the taxonomy introspector for querying available
// node types and relationships in the knowledge graph.
// Delegates to the inner Gibson harness's TaxonomyRegistry implementation.
func (a *GibsonHarnessAdapter) TaxonomyRegistry() graphrag.TaxonomyIntrospector {
	// Type assert to access TaxonomyRegistry method from DefaultAgentHarness
	if h, ok := a.inner.(interface{ TaxonomyRegistry() graphrag.TaxonomyIntrospector }); ok {
		return h.TaxonomyRegistry()
	}
	// Return nil if inner harness doesn't implement TaxonomyRegistry
	return nil
}

// Intelligence returns the intelligence queries interface.
// This adapter returns a no-op implementation since eval harness doesn't have
// access to the full knowledge graph intelligence queries.
func (g *GibsonHarnessAdapter) Intelligence() graphrag.IntelligenceQueries {
	return &graphrag.NoOpIntelligenceQueries{}
}

var _ agent.Harness = (*GibsonHarnessAdapter)(nil)
