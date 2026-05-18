package harness

import (
	"context"
	"testing"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
	"go.opentelemetry.io/otel/trace/noop"
)

func ptr32(v int32) *int32 { return &v }

func agentNode(cap *int32) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Type: missionv1.NodeType_NODE_TYPE_AGENT,
		Config: &missionv1.MissionNode_AgentConfig{
			AgentConfig: &missionv1.AgentNodeConfig{
				AgentName:        "a",
				MaxTokensPerCall: cap,
			},
		},
	}
}

func toolNode(cap *int32) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Type: missionv1.NodeType_NODE_TYPE_TOOL,
		Config: &missionv1.MissionNode_ToolConfig{
			ToolConfig: &missionv1.ToolNodeConfig{
				ToolName:         "t",
				MaxTokensPerCall: cap,
			},
		},
	}
}

func pluginNode(cap *int32) *missionv1.MissionNode {
	return &missionv1.MissionNode{
		Type: missionv1.NodeType_NODE_TYPE_PLUGIN,
		Config: &missionv1.MissionNode_PluginConfig{
			PluginConfig: &missionv1.PluginNodeConfig{
				PluginName:       "p",
				Method:           "do",
				MaxTokensPerCall: cap,
			},
		},
	}
}

func TestEffectivePerCallCap_node_override_wins(t *testing.T) {
	cs := &missionv1.MissionConstraints{MaxTokensPerCall: 1000}
	got := EffectivePerCallCap(agentNode(ptr32(2048)), cs)
	if got != 2048 {
		t.Errorf("got=%d want=2048 (per-node override)", got)
	}
}

func TestEffectivePerCallCap_zero_node_override_disables_cap(t *testing.T) {
	cs := &missionv1.MissionConstraints{MaxTokensPerCall: 1000}
	got := EffectivePerCallCap(agentNode(ptr32(0)), cs)
	if got != 0 {
		t.Errorf("got=%d want=0 (explicit 0 shadows mission cap)", got)
	}
}

func TestEffectivePerCallCap_unset_node_falls_back_to_mission(t *testing.T) {
	cs := &missionv1.MissionConstraints{MaxTokensPerCall: 1000}
	got := EffectivePerCallCap(agentNode(nil), cs)
	if got != 1000 {
		t.Errorf("got=%d want=1000 (mission default)", got)
	}
}

func TestEffectivePerCallCap_no_constraints_no_node(t *testing.T) {
	got := EffectivePerCallCap(agentNode(nil), nil)
	if got != 0 {
		t.Errorf("got=%d want=0", got)
	}
}

func TestEffectivePerCallCap_tool_override(t *testing.T) {
	cs := &missionv1.MissionConstraints{MaxTokensPerCall: 100}
	got := EffectivePerCallCap(toolNode(ptr32(500)), cs)
	if got != 500 {
		t.Errorf("got=%d want=500", got)
	}
}

func TestEffectivePerCallCap_plugin_override(t *testing.T) {
	cs := &missionv1.MissionConstraints{MaxTokensPerCall: 100}
	got := EffectivePerCallCap(pluginNode(ptr32(300)), cs)
	if got != 300 {
		t.Errorf("got=%d want=300", got)
	}
}

func TestEffectivePerCallCap_nil_node(t *testing.T) {
	cs := &missionv1.MissionConstraints{MaxTokensPerCall: 750}
	got := EffectivePerCallCap(nil, cs)
	if got != 750 {
		t.Errorf("got=%d want=750", got)
	}
}

func TestEffectivePerCallCap_zero_mission_no_cap(t *testing.T) {
	cs := &missionv1.MissionConstraints{MaxTokensPerCall: 0}
	got := EffectivePerCallCap(agentNode(nil), cs)
	if got != 0 {
		t.Errorf("got=%d want=0", got)
	}
}

func TestEffectivePerCallCap_condition_node_no_overhead(t *testing.T) {
	// CONDITION nodes don't carry max_tokens_per_call; should
	// always fall through to mission-level.
	node := &missionv1.MissionNode{
		Type: missionv1.NodeType_NODE_TYPE_CONDITION,
		Config: &missionv1.MissionNode_ConditionConfig{
			ConditionConfig: &missionv1.ConditionNodeConfig{Expression: "true"},
		},
	}
	cs := &missionv1.MissionConstraints{MaxTokensPerCall: 600}
	got := EffectivePerCallCap(node, cs)
	if got != 600 {
		t.Errorf("got=%d want=600 (CONDITION → mission cap)", got)
	}
}

// ---------------------------------------------------------------------------
// Integration: applyPerCallCap wired through DefaultAgentHarness.Complete
// ---------------------------------------------------------------------------

// capturingProvider is a minimal llm.LLMProvider that records the CompletionRequest
// it receives. Used to verify that the harness correctly clamps MaxTokens before
// handing off to the provider.
type capturingProvider struct {
	captured llm.CompletionRequest
}

func (p *capturingProvider) Name() string { return "capturing" }
func (p *capturingProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	return []llm.ModelInfo{{Name: "test-model"}}, nil
}
func (p *capturingProvider) Complete(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	p.captured = req
	return &llm.CompletionResponse{
		Message: llm.Message{Role: llm.RoleAssistant, Content: "ok"},
	}, nil
}
func (p *capturingProvider) CompleteWithTools(_ context.Context, req llm.CompletionRequest, _ []llm.ToolDef) (*llm.CompletionResponse, error) {
	p.captured = req
	return &llm.CompletionResponse{
		Message: llm.Message{Role: llm.RoleAssistant, Content: "ok"},
	}, nil
}
func (p *capturingProvider) Stream(_ context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	p.captured = req
	ch := make(chan llm.StreamChunk, 1)
	ch <- llm.StreamChunk{FinishReason: llm.FinishReasonStop}
	close(ch)
	return ch, nil
}
func (p *capturingProvider) Health(_ context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "ok")
}

// fixedSlotManager is a SlotManager that always resolves to a fixed provider/model.
// Used to bypass the registry lookup in unit tests.
type fixedSlotManager struct {
	prov  llm.LLMProvider
	model llm.ModelInfo
}

func (m *fixedSlotManager) ResolveSlot(_ context.Context, _ agent.SlotDefinition, _ *agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	return m.prov, m.model, nil
}

func (m *fixedSlotManager) ValidateSlot(_ context.Context, _ agent.SlotDefinition) error {
	return nil
}

// newTestHarnessWithProvider creates a minimal DefaultAgentHarness wired to
// the given provider. The slot manager always resolves any slot to that
// provider, avoiding the need for a real registry configuration.
func newTestHarnessWithProvider(prov llm.LLMProvider) *DefaultAgentHarness {
	return &DefaultAgentHarness{
		slotManager: &fixedSlotManager{
			prov:  prov,
			model: llm.ModelInfo{Name: "test-model", ContextWindow: 8192},
		},
		llmRegistry: llm.NewLLMRegistry(),
		tracer:      noop.NewTracerProvider().Tracer("test"),
		logger:      discardLogger(),
		metrics:     NewNoOpMetricsRecorder(),
		tokenUsage:  llm.NewTokenTracker(nil),
		missionCtx: MissionContext{
			ID:   types.ID("test-mission"),
			Name: "test-mission",
		},
	}
}

// TestApplyPerCallCap_node_override_clamps_Complete verifies that when the
// per-node cap (100) is lower than the caller-requested max_tokens (4096),
// the cap wins and the provider sees MaxTokens == 100.
// This is the primary dispatch assertion for M4 (gibson#133).
func TestApplyPerCallCap_node_override_clamps_Complete(t *testing.T) {
	prov := &capturingProvider{}
	h := newTestHarnessWithProvider(prov)
	h.WithPerCallCapContext(agentNode(ptr32(100)), nil)

	msgs := []llm.Message{{Role: llm.RoleUser, Content: "hello"}}
	_, err := h.Complete(context.Background(), "primary", msgs, WithMaxTokens(4096))
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if prov.captured.MaxTokens != 100 {
		t.Errorf("provider saw MaxTokens=%d, want 100 (per-node cap)", prov.captured.MaxTokens)
	}
}

// TestApplyPerCallCap_mission_level_clamps_Complete verifies that when no
// per-node cap is set, the mission-level constraint applies.
func TestApplyPerCallCap_mission_level_clamps_Complete(t *testing.T) {
	prov := &capturingProvider{}
	h := newTestHarnessWithProvider(prov)
	h.WithPerCallCapContext(nil, &missionv1.MissionConstraints{MaxTokensPerCall: 512})

	msgs := []llm.Message{{Role: llm.RoleUser, Content: "hello"}}
	_, err := h.Complete(context.Background(), "primary", msgs, WithMaxTokens(4096))
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if prov.captured.MaxTokens != 512 {
		t.Errorf("provider saw MaxTokens=%d, want 512 (mission-level cap)", prov.captured.MaxTokens)
	}
}

// TestApplyPerCallCap_node_beats_mission_Complete verifies the cascade:
// per-node cap (200) wins over mission-level cap (1000) even though node < mission.
func TestApplyPerCallCap_node_beats_mission_Complete(t *testing.T) {
	prov := &capturingProvider{}
	h := newTestHarnessWithProvider(prov)
	h.WithPerCallCapContext(agentNode(ptr32(200)), &missionv1.MissionConstraints{MaxTokensPerCall: 1000})

	msgs := []llm.Message{{Role: llm.RoleUser, Content: "hello"}}
	_, err := h.Complete(context.Background(), "primary", msgs, WithMaxTokens(4096))
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if prov.captured.MaxTokens != 200 {
		t.Errorf("provider saw MaxTokens=%d, want 200 (per-node beats mission)", prov.captured.MaxTokens)
	}
}

// TestApplyPerCallCap_lower_caller_value_preserved verifies that the cap is a
// ceiling, not a floor: if the caller already set MaxTokens below the cap,
// the lower value is preserved.
func TestApplyPerCallCap_lower_caller_value_preserved(t *testing.T) {
	prov := &capturingProvider{}
	h := newTestHarnessWithProvider(prov)
	h.WithPerCallCapContext(agentNode(ptr32(500)), nil)

	msgs := []llm.Message{{Role: llm.RoleUser, Content: "hello"}}
	_, err := h.Complete(context.Background(), "primary", msgs, WithMaxTokens(50)) // 50 < 500
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if prov.captured.MaxTokens != 50 {
		t.Errorf("provider saw MaxTokens=%d, want 50 (caller's lower value preserved)", prov.captured.MaxTokens)
	}
}

// TestApplyPerCallCap_no_cap_no_change verifies that when neither node nor
// constraints supply a cap, MaxTokens is left exactly as the caller set it.
func TestApplyPerCallCap_no_cap_no_change(t *testing.T) {
	prov := &capturingProvider{}
	h := newTestHarnessWithProvider(prov)
	// No cap wired.

	msgs := []llm.Message{{Role: llm.RoleUser, Content: "hello"}}
	_, err := h.Complete(context.Background(), "primary", msgs, WithMaxTokens(4096))
	if err != nil {
		t.Fatalf("Complete returned error: %v", err)
	}
	if prov.captured.MaxTokens != 4096 {
		t.Errorf("provider saw MaxTokens=%d, want 4096 (no cap)", prov.captured.MaxTokens)
	}
}

// TestApplyPerCallCap_CompleteWithTools verifies the cap applies on the tools
// dispatch path as well.
func TestApplyPerCallCap_CompleteWithTools(t *testing.T) {
	prov := &capturingProvider{}
	h := newTestHarnessWithProvider(prov)
	h.WithPerCallCapContext(agentNode(ptr32(100)), nil)

	msgs := []llm.Message{{Role: llm.RoleUser, Content: "hello"}}
	_, err := h.CompleteWithTools(context.Background(), "primary", msgs, nil, WithMaxTokens(4096))
	if err != nil {
		t.Fatalf("CompleteWithTools returned error: %v", err)
	}
	if prov.captured.MaxTokens != 100 {
		t.Errorf("provider saw MaxTokens=%d, want 100 (per-node cap via CompleteWithTools)", prov.captured.MaxTokens)
	}
}

// TestApplyPerCallCap_Stream verifies the cap applies on the streaming path.
func TestApplyPerCallCap_Stream(t *testing.T) {
	prov := &capturingProvider{}
	h := newTestHarnessWithProvider(prov)
	h.WithPerCallCapContext(agentNode(ptr32(100)), nil)

	msgs := []llm.Message{{Role: llm.RoleUser, Content: "hello"}}
	ch, err := h.Stream(context.Background(), "primary", msgs, WithMaxTokens(4096))
	if err != nil {
		t.Fatalf("Stream returned error: %v", err)
	}
	// Drain the channel.
	for range ch {
	}
	if prov.captured.MaxTokens != 100 {
		t.Errorf("provider saw MaxTokens=%d, want 100 (per-node cap via Stream)", prov.captured.MaxTokens)
	}
}
