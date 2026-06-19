package harness

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/contextkeys"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/tool"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
	"go.opentelemetry.io/otel/trace/noop"
)

// discardLogger returns a slog.Logger that discards all output.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ────────────────────────────────────────────────────────────────────────────
// Helpers — minimal harness construction for delegation tests
// ────────────────────────────────────────────────────────────────────────────

// recordingGraphRAGQueryBridge captures CreateRelationship calls for assertion.
type recordingGraphRAGQueryBridge struct {
	mu            sync.Mutex
	relationships []sdkgraphrag.Relationship
}

func (r *recordingGraphRAGQueryBridge) StoreNode(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	return "", nil
}
func (r *recordingGraphRAGQueryBridge) CreateRelationship(ctx context.Context, rel sdkgraphrag.Relationship) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.relationships = append(r.relationships, rel)
	return nil
}
func (r *recordingGraphRAGQueryBridge) StoreBatch(ctx context.Context, batch sdkgraphrag.Batch, missionID, agentName string) ([]string, error) {
	return nil, nil
}
func (r *recordingGraphRAGQueryBridge) StoreSemantic(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	return "", nil
}
func (r *recordingGraphRAGQueryBridge) StoreStructured(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	return "", nil
}
func (r *recordingGraphRAGQueryBridge) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("ok")
}

// captureAgent is a minimal agent.Agent implementation that records context
// state (CallerChain, DelegationDepth) on Execute and returns a simple result.
type captureAgent struct {
	name string

	// captured on Execute
	mu             sync.Mutex
	capturedChain  []string
	capturedDepth  int
	capturedParent string
}

func (a *captureAgent) Name() string                                                { return a.name }
func (a *captureAgent) Version() string                                             { return "0.0.1" }
func (a *captureAgent) Description() string                                         { return "capture agent for delegation tests" }
func (a *captureAgent) Capabilities() []string                                      { return nil }
func (a *captureAgent) TargetTypes() []component.TargetType                         { return nil }
func (a *captureAgent) TechniqueTypes() []component.TechniqueType                   { return nil }
func (a *captureAgent) LLMSlots() []agent.SlotDefinition                            { return nil }
func (a *captureAgent) Initialize(ctx context.Context, cfg agent.AgentConfig) error { return nil }
func (a *captureAgent) Shutdown(ctx context.Context) error                          { return nil }
func (a *captureAgent) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("ok")
}

func (a *captureAgent) Execute(ctx context.Context, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	chain, _ := contextkeys.GetCallerChain(ctx)
	parent, _ := contextkeys.GetParentAgentRunID(ctx)

	// Recover the delegation depth from the harness mission context if available.
	var depth int
	if dh, ok := harness.(*DefaultAgentHarness); ok {
		depth = dh.missionCtx.DelegationDepth
	}

	a.mu.Lock()
	a.capturedChain = chain
	a.capturedDepth = depth
	a.capturedParent = parent
	a.mu.Unlock()

	result := agent.NewResult(task.ID)
	result.Complete(map[string]any{"agent": a.name})
	return result, nil
}

// delegationRegistryAdapter is a component.ComponentDiscovery backed by a map
// of registered captureAgents.
type delegationRegistryAdapter struct {
	agents map[string]*captureAgent
}

func (d *delegationRegistryAdapter) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	a, ok := d.agents[name]
	if !ok {
		return nil, fmt.Errorf("agent %q not found", name)
	}
	return a, nil
}
func (d *delegationRegistryAdapter) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	return nil, fmt.Errorf("tools not supported in delegation test adapter")
}

// DiscoverPlugin was removed from component.ComponentDiscovery in plugin-runtime
// Spec 2 Phase 7; plugin invocation now goes through PluginInvokeService.

func (d *delegationRegistryAdapter) ListAgents(ctx context.Context) ([]component.AgentInfo, error) {
	return nil, nil
}
func (d *delegationRegistryAdapter) ListTools(ctx context.Context) ([]component.ToolInfo, error) {
	return nil, nil
}
func (d *delegationRegistryAdapter) ListPlugins(ctx context.Context) ([]component.PluginInfo, error) {
	return nil, nil
}
func (d *delegationRegistryAdapter) DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	a, err := d.DiscoverAgent(ctx, name)
	if err != nil {
		return agent.Result{}, err
	}
	return a.Execute(ctx, task, harness)
}

// buildTestHarness creates a minimal *DefaultAgentHarness for delegation tests.
// The missionCtx.AgentRunID is set to agentRunID so the parent-push logic has
// a run ID to propagate.
func buildTestHarness(t *testing.T, agentRunID string, depth int, maxDepth int, registry *delegationRegistryAdapter, graphBridge GraphRAGQueryBridge) *DefaultAgentHarness {
	t.Helper()

	llmRegistry := llm.NewLLMRegistry()
	slotManager := llm.NewSlotManager(llmRegistry)

	missionCtx := MissionContext{
		ID:              types.NewID(),
		Name:            "test-mission",
		CurrentAgent:    "test-agent",
		AgentRunID:      agentRunID,
		DelegationDepth: depth,
	}
	targetInfo := TargetInfo{ID: "test-target", Type: "http_api"}

	var selfRef *DefaultAgentHarness

	logger := discardLogger()

	// HarnessFactory that returns a new DefaultAgentHarness with the same
	// registry and graphRAG bridge — mirrors what the real factory does for
	// child harness creation in DelegateToAgent.
	factory := HarnessFactory(func(ctx context.Context, mc MissionContext, ti TargetInfo) (AgentHarness, error) {
		child := &DefaultAgentHarness{
			slotManager:         slotManager,
			llmRegistry:         llmRegistry,
			missionCtx:          mc,
			targetInfo:          ti,
			tracer:              noop.NewTracerProvider().Tracer("test"),
			logger:              logger,
			metrics:             &NoOpMetricsRecorder{},
			registryAdapter:     registry,
			findingStore:        NewInMemoryFindingStore(),
			graphRAGQueryBridge: graphBridge,
			maxDelegationDepth:  selfRef.maxDelegationDepth,
		}
		// Provide a recursive self-referencing factory so nested delegation works.
		var childRef *DefaultAgentHarness
		childRef = child
		child.factory = HarnessFactory(func(ctx2 context.Context, mc2 MissionContext, ti2 TargetInfo) (AgentHarness, error) {
			return buildTestHarness(t, mc2.AgentRunID, mc2.DelegationDepth, selfRef.maxDelegationDepth, registry, graphBridge), nil
		})
		_ = childRef
		return child, nil
	})

	h := &DefaultAgentHarness{
		slotManager:         slotManager,
		llmRegistry:         llmRegistry,
		missionCtx:          missionCtx,
		targetInfo:          targetInfo,
		tracer:              noop.NewTracerProvider().Tracer("test"),
		logger:              logger,
		metrics:             &NoOpMetricsRecorder{},
		registryAdapter:     registry,
		findingStore:        NewInMemoryFindingStore(),
		factory:             factory,
		graphRAGQueryBridge: graphBridge,
		maxDelegationDepth:  maxDepth,
	}
	selfRef = h
	return h
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

// TestDelegateToAgent_CallerChainPropagation verifies that A → B → C
// delegation produces caller_chain = [A_run_id, B_run_id] on C's context.
func TestDelegateToAgent_CallerChainPropagation(t *testing.T) {
	// Agents B and C are captureAgents so we can inspect what context they see.
	agentB := &captureAgent{name: "agent_b"}
	agentC := &captureAgent{name: "agent_c"}

	registry := &delegationRegistryAdapter{
		agents: map[string]*captureAgent{
			"agent_b": agentB,
			"agent_c": agentC,
		},
	}

	graphBridge := &recordingGraphRAGQueryBridge{}

	// Harness A: top-level agent with run ID "run-a".
	// When A delegates to B, the chain on B's context must be ["run-a"].
	// When B delegates to C (via its own harness), the chain on C must be ["run-a", "run-b"].

	// Build A's harness. B needs its own harness (simulated by a recursive
	// captureAgent that itself calls DelegateToAgent).  For simplicity in this
	// unit test, we exercise A→B directly and then independently verify A→B→C
	// by building a second level.

	harnessA := buildTestHarness(t, "run-a", 0, defaultMaxDelegationDepth, registry, graphBridge)

	task := agent.NewTask("test", "test task", nil)

	// A delegates to B. B's Execute will see caller_chain=["run-a"].
	_, err := harnessA.DelegateToAgent(context.Background(), "agent_b", task)
	require.NoError(t, err)

	agentB.mu.Lock()
	chainOnB := agentB.capturedChain
	parentOnB := agentB.capturedParent
	depthOnB := agentB.capturedDepth
	agentB.mu.Unlock()

	assert.Equal(t, []string{"run-a"}, chainOnB, "chain on B should contain A's run ID")
	assert.Equal(t, "run-a", parentOnB, "B's parent run ID should be A")
	assert.Equal(t, 1, depthOnB, "B's delegation depth should be 1")

	// Now simulate B (depth=1, run_id="run-b") delegating to C.
	// Provide a context that already carries A→B chain (as DelegateToAgent would set it).
	ctxWithChain := contextkeys.WithCallerChain(context.Background(), []string{"run-a"})
	ctxWithChain = contextkeys.WithParentAgentRunID(ctxWithChain, "run-a")

	harnessB := buildTestHarness(t, "run-b", 1, defaultMaxDelegationDepth, registry, graphBridge)
	_, err = harnessB.DelegateToAgent(ctxWithChain, "agent_c", task)
	require.NoError(t, err)

	agentC.mu.Lock()
	chainOnC := agentC.capturedChain
	parentOnC := agentC.capturedParent
	depthOnC := agentC.capturedDepth
	agentC.mu.Unlock()

	assert.Equal(t, []string{"run-a", "run-b"}, chainOnC, "chain on C should contain A then B")
	assert.Equal(t, "run-b", parentOnC, "C's parent run ID should be B")
	assert.Equal(t, 2, depthOnC, "C's delegation depth should be 2")
}

// TestDelegateToAgent_DepthCapReturnsError verifies that delegating when the
// current DelegationDepth equals or exceeds maxDelegationDepth returns an error
// whose message contains "delegation_depth_exceeded".
func TestDelegateToAgent_DepthCapReturnsError(t *testing.T) {
	agentX := &captureAgent{name: "agent_x"}
	registry := &delegationRegistryAdapter{
		agents: map[string]*captureAgent{"agent_x": agentX},
	}
	graphBridge := &recordingGraphRAGQueryBridge{}

	// Build a harness that is already at the cap (depth == maxDepth).
	// maxDepth=8, currentDepth=8 → next hop (depth=9) must be rejected.
	const maxDepth = 8
	harnessAtCap := buildTestHarness(t, "run-x", maxDepth, maxDepth, registry, graphBridge)

	task := agent.NewTask("test", "test task", nil)
	_, err := harnessAtCap.DelegateToAgent(context.Background(), "agent_x", task)

	require.Error(t, err, "expected delegation_depth_exceeded error")
	assert.True(t,
		strings.Contains(err.Error(), "delegation_depth_exceeded"),
		"error message should contain delegation_depth_exceeded, got: %s", err.Error(),
	)

	// The agent should NOT have been executed.
	agentX.mu.Lock()
	wasCalled := agentX.capturedChain != nil || agentX.capturedParent != ""
	agentX.mu.Unlock()
	assert.False(t, wasCalled, "agent_x should not have been called when depth cap is exceeded")
}

// TestDelegateToAgent_DepthCapDefault verifies that a harness with maxDepth=0
// uses defaultMaxDelegationDepth (8) so that depth=8 is still rejected.
func TestDelegateToAgent_DepthCapDefault(t *testing.T) {
	agentX := &captureAgent{name: "agent_x"}
	registry := &delegationRegistryAdapter{
		agents: map[string]*captureAgent{"agent_x": agentX},
	}
	graphBridge := &recordingGraphRAGQueryBridge{}

	// maxDepth=0 means "use default=8". depth=defaultMaxDelegationDepth should fail.
	harnessAtDefaultCap := buildTestHarness(t, "run-x", defaultMaxDelegationDepth, 0 /*maxDepth=use default*/, registry, graphBridge)

	task := agent.NewTask("test", "test task", nil)
	_, err := harnessAtDefaultCap.DelegateToAgent(context.Background(), "agent_x", task)

	require.Error(t, err, "expected depth-exceeded error with default cap")
	assert.Contains(t, err.Error(), "delegation_depth_exceeded")
}

// TestDelegateToAgent_DepthBelowCap verifies that delegation at depth < maxDepth
// succeeds and does not return the depth-exceeded error.
func TestDelegateToAgent_DepthBelowCap(t *testing.T) {
	agentX := &captureAgent{name: "agent_x"}
	registry := &delegationRegistryAdapter{
		agents: map[string]*captureAgent{"agent_x": agentX},
	}
	graphBridge := &recordingGraphRAGQueryBridge{}

	// depth=7, maxDepth=8 → should succeed.
	harnessNearCap := buildTestHarness(t, "run-near", 7, 8, registry, graphBridge)

	task := agent.NewTask("test", "test task", nil)
	_, err := harnessNearCap.DelegateToAgent(context.Background(), "agent_x", task)

	require.NoError(t, err, "delegation at depth 7 (max=8) should succeed")
}

// TestDelegateToAgent_DELEGATEDTORelationship verifies that a DELEGATED_TO
// relationship is written from the parent agent_run to the child agent_run
// when both run IDs are non-empty.
func TestDelegateToAgent_DELEGATEDTORelationship(t *testing.T) {
	// delegatingAgent delegates to a child and sets child's AgentRunID via a
	// custom captureAgent that sets its run ID into the harness.
	childRunID := "run-child-42"

	// Use a captureAgent whose Execute sets the childRunID onto the mission
	// context. Since the child harness's missionCtx.AgentRunID is set at
	// factory time, we pre-seed the child's AgentRunID via the factory used
	// inside buildTestHarness (the recursive factory).  The simplest approach:
	// directly construct a harness with childRunID set and call DelegateToAgent.

	// We'll use a custom registry adapter that directly returns a result
	// without going through a captureAgent, so we can set the child run ID
	// predictably in the test.
	type childResult struct{}

	agentWithKnownRunID := &captureAgent{name: "child_agent"}
	registry := &delegationRegistryAdapter{
		agents: map[string]*captureAgent{"child_agent": agentWithKnownRunID},
	}

	graphBridge := &recordingGraphRAGQueryBridge{}

	// Parent harness: run_id="run-parent"
	parentRunID := "run-parent"
	harnessParent := buildTestHarness(t, parentRunID, 0, 8, registry, graphBridge)

	// Override the factory so the child harness gets childRunID pre-set.
	harnessParent.factory = HarnessFactory(func(ctx context.Context, mc MissionContext, ti TargetInfo) (AgentHarness, error) {
		mc.AgentRunID = childRunID
		llmReg := llm.NewLLMRegistry()
		child := &DefaultAgentHarness{
			slotManager:         llm.NewSlotManager(llmReg),
			llmRegistry:         llmReg,
			missionCtx:          mc,
			targetInfo:          ti,
			tracer:              noop.NewTracerProvider().Tracer("test"),
			logger:              discardLogger(),
			metrics:             &NoOpMetricsRecorder{},
			registryAdapter:     registry,
			findingStore:        NewInMemoryFindingStore(),
			graphRAGQueryBridge: graphBridge,
			maxDelegationDepth:  8,
			factory: HarnessFactory(func(ctx2 context.Context, mc2 MissionContext, ti2 TargetInfo) (AgentHarness, error) {
				return nil, fmt.Errorf("nested delegation not expected in this test")
			}),
		}
		return child, nil
	})

	task := agent.NewTask("test", "test task", nil)
	_, err := harnessParent.DelegateToAgent(context.Background(), "child_agent", task)
	require.NoError(t, err)

	// Verify the DELEGATED_TO relationship was recorded.
	graphBridge.mu.Lock()
	rels := graphBridge.relationships
	graphBridge.mu.Unlock()

	require.Len(t, rels, 1, "expected exactly one DELEGATED_TO relationship")
	assert.Equal(t, parentRunID, rels[0].FromID)
	assert.Equal(t, childRunID, rels[0].ToID)
	assert.Equal(t, "DELEGATED_TO", rels[0].Type)
}

// TestDelegateToAgent_ExistingDelegationTestsUnbroken is a smoke test to
// ensure the existing delegation path (found agents, no chain stamping on
// empty run IDs) still works correctly after the changes.
func TestDelegateToAgent_ExistingDelegationTestsUnbroken(t *testing.T) {
	reconAgent := &captureAgent{name: "recon_agent"}
	exploitAgent := &captureAgent{name: "exploit_agent"}

	registry := &delegationRegistryAdapter{
		agents: map[string]*captureAgent{
			"recon_agent":   reconAgent,
			"exploit_agent": exploitAgent,
		},
	}

	// No AgentRunID — mirrors harnesses created without a run ID stamp.
	h := buildTestHarness(t, "", 0, defaultMaxDelegationDepth, registry, nil)

	task := agent.NewTask("recon", "recon task", nil)

	_, err := h.DelegateToAgent(context.Background(), "recon_agent", task)
	require.NoError(t, err, "delegation to recon_agent should succeed")

	_, err = h.DelegateToAgent(context.Background(), "exploit_agent", task)
	require.NoError(t, err, "delegation to exploit_agent should succeed")
}
