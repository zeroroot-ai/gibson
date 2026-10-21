// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// node_slot_pin_chain_test.go follows the LLM slot pin of a mission AGENT node
// from the mission definition to the provider that serves the completion of an
// agent served with sdk.ServeAgent (gibson#1203):
//
//	MissionNode.llm_slots → mission projection → brain scheduler → dispatch →
//	brainExecutor.Dispatch → agent.Task.SlotOverrides → harness.WorkSlotPins
//	(the work item of delegateToAgentViaWorkQueue) → WorkQueue.Enqueue →
//	ComponentService.Complete → LLMRegistryAdapter → DaemonSlotManager.
//
// The harness hop from the task to the enqueued work item is covered in the
// harness package (TestDelegateToAgent_PutsTheNodeSlotPinsOnTheWorkItem). Here
// the same production function, harness.WorkSlotPins, makes the work item.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/modelgate"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const chainTenant = "acme"

// servingProvider is an LLM provider that records the model of each
// completion it serves.
type servingProvider struct {
	name   string
	models []string
	// noSavedModel makes the provider report no saved default model.
	noSavedModel bool

	mu     sync.Mutex
	served []string
}

func (p *servingProvider) Name() string { return p.name }

// DefaultModel is the saved default model of the provider: its first model.
func (p *servingProvider) DefaultModel() string {
	if p.noSavedModel {
		return ""
	}
	return p.models[0]
}

func (p *servingProvider) Models(context.Context) ([]llm.ModelInfo, error) {
	out := make([]llm.ModelInfo, 0, len(p.models))
	for _, m := range p.models {
		out = append(out, llm.ModelInfo{Name: m, ContextWindow: 200000, MaxOutput: 4096, Features: []string{"chat"}})
	}
	return out, nil
}

func (p *servingProvider) Complete(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	p.mu.Lock()
	p.served = append(p.served, req.Model)
	p.mu.Unlock()
	return &llm.CompletionResponse{Model: req.Model, Message: llm.Message{Role: llm.RoleAssistant, Content: "ok"}}, nil
}

func (p *servingProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, _ []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req)
}

func (p *servingProvider) Stream(context.Context, llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	return nil, types.NewError("NOT_IMPLEMENTED", "no stream")
}

func (p *servingProvider) Health(context.Context) types.HealthStatus { return types.Healthy("ok") }

func (p *servingProvider) servedModels() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.served...)
}

// delegateRecorder is the mission harness of the binding. Dispatch calls only
// DelegateToAgent on it, which records the task.
type delegateRecorder struct {
	gibsonharness.AgentHarness
	tasks chan agent.Task
}

func (d *delegateRecorder) DelegateToAgent(_ context.Context, _ string, task agent.Task) (agent.Result, error) {
	d.tasks <- task
	return agent.Result{Status: agent.ResultStatusCompleted}, nil
}

// chainEnv is the tenant's provider set behind a real DaemonSlotManager, and a
// ComponentService over a real Redis work queue.
type chainEnv struct {
	svc     *component.ComponentServiceServer
	queue   component.WorkQueue
	def     *servingProvider
	pinned  *servingProvider
	manager *DaemonSlotManager
	claims  *component.RedisWorkContextRegistry
}

// chainClaimant is the principal that claims the work items of these tests.
const chainClaimant = "agent_principal:chain"

func newChainEnv(t *testing.T, filter modelgate.Filter) *chainEnv {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sc.Close() })

	def := &servingProvider{name: "default-p", models: []string{"d-1"}}
	pinned := &servingProvider{name: "fast-p", models: []string{"f-small", "f-large"}}
	unsaved := &servingProvider{name: "unsaved-p", models: []string{"u-1"}, noSavedModel: true}
	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(def))
	require.NoError(t, registry.RegisterProvider(pinned))
	require.NoError(t, registry.RegisterProvider(unsaved))
	logger := slog.New(slog.DiscardHandler)
	manager := NewDaemonSlotManager(registry, logger).WithDefaultProvider("default-p")
	if filter != nil {
		manager.WithModelFilter(filter)
	}

	adapter := component.NewLLMRegistryAdapter(nil, nil, logger).
		WithTenantResolver(func(_ context.Context, tenant string) (llm.SlotManager, llm.LLMRegistry, error) {
			require.Equal(t, chainTenant, tenant)
			return manager, registry, nil
		})
	queue := component.NewRedisWorkQueue(client)
	claims := component.NewRedisWorkContextRegistry(sc)
	svc := component.NewComponentServiceServer(component.NewRedisComponentRegistry(client, time.Minute), queue, logger, adapter, nil, nil, nil).
		WithWorkContextRegistry(claims)
	return &chainEnv{svc: svc, queue: queue, def: def, pinned: pinned, manager: manager, claims: claims}
}

// dispatchNode runs one mission with one AGENT node that has the given slot
// pins through the projection, the scheduler and brainExecutor.Dispatch, and
// enqueues the agent work item the way delegateToAgentViaWorkQueue does. It
// returns the work id.
func (e *chainEnv) dispatchNode(t *testing.T, slots []*missionpb.LLMSlotConfig) string {
	t.Helper()
	def := &missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"recon": {
				Type: missionpb.NodeType_NODE_TYPE_AGENT,
				Config: &missionpb.MissionNode_AgentConfig{AgentConfig: &missionpb.AgentNodeConfig{
					AgentName: "recon",
					LlmSlots:  slots,
				}},
			},
		},
	}
	proj, _, err := missionDefinitionToProjected(def, "", nil)
	require.NoError(t, err)

	rec := &delegateRecorder{tasks: make(chan agent.Task, 1)}
	exec := newBrainExecutor(nil, slog.New(slog.DiscardHandler))
	eng := brain.NewEngine(chainTenant, braintest.NewMemTimelineStore())
	eng.AddSystem(brain.SchedulerSystem)
	handler := brain.NewDispatchHandler(exec)
	eng.Subscribe(handler.Tap)
	exec.register(proj.ID, &missionBinding{ctx: context.Background(), tenant: chainTenant, eng: eng, harness: rec})

	eng.Submit(proj)
	eng.Tick()
	require.Equal(t, 1, handler.Drain(), "the agent node is dispatched")

	var task agent.Task
	select {
	case task = <-rec.tasks:
	case <-time.After(5 * time.Second):
		t.Fatal("the agent node never reached DelegateToAgent")
	}

	workID := "agent-recon-chain"
	_, err = e.queue.Enqueue(context.Background(), chainTenant, "agent", "recon", component.WorkItem{
		WorkID:   workID,
		WorkType: component.WorkTypeAgentExecute,
		SlotPins: gibsonharness.WorkSlotPins(task.SlotOverrides),
	})
	require.NoError(t, err)
	// The served agent claimed its work item, as PollWork records.
	require.NoError(t, e.claims.BindWorkClaim(context.Background(), workID, chainClaimant))
	return workID
}

func (e *chainEnv) complete(workID, slot string) error {
	tid, tidErr := auth.NewTenantID(chainTenant)
	if tidErr != nil {
		return fmt.Errorf("tenant: %w", tidErr)
	}
	ctx := auth.WithIdentity(auth.ContextWithTenantString(context.Background(), chainTenant),
		auth.Identity{Subject: chainClaimant, Tenant: tid})
	if _, err := e.svc.Complete(ctx, &componentpb.CompleteRequest{
		WorkId:   workID,
		Slot:     slot,
		Messages: []*componentpb.LLMMessage{{Role: "user", Content: "hello"}},
	}); err != nil {
		return fmt.Errorf("complete %s: %w", slot, err)
	}
	return nil
}

// A node that pins a provider and a model gets that provider and model on the
// completion of its served agent. The tenant default serves nothing.
func TestNodeSlotPin_ReachesTheProviderOfTheServedAgent(t *testing.T) {
	env := newChainEnv(t, nil)
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "fast-p", Model: "f-large"}})

	require.NoError(t, env.complete(workID, "fast"))

	assert.Equal(t, []string{"f-large"}, env.pinned.servedModels())
	assert.Empty(t, env.def.servedModels())
}

// A slot that the node does not pin keeps the tenant default.
func TestNodeSlotPin_AnUnpinnedSlotKeepsTheTenantDefault(t *testing.T) {
	env := newChainEnv(t, nil)
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "fast-p", Model: "f-large"}})

	require.NoError(t, env.complete(workID, "primary"))

	assert.Equal(t, []string{"d-1"}, env.def.servedModels())
	assert.Empty(t, env.pinned.servedModels())
}

// A pin with a provider and no model gets the saved default model of that
// provider.
func TestNodeSlotPin_AProviderOnlyPinUsesThatProvider(t *testing.T) {
	env := newChainEnv(t, nil)
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "fast-p"}})

	require.NoError(t, env.complete(workID, "fast"))

	assert.Equal(t, []string{"f-small"}, env.pinned.servedModels())
	assert.Empty(t, env.def.servedModels())
}

// A pin of a provider and a model that the tenant does not have fails the
// completion with no silent fallback to another provider.
func TestNodeSlotPin_APinOfAMissingProviderFailsTheCompletion(t *testing.T) {
	env := newChainEnv(t, nil)
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "absent-p", Model: "a-1"}})

	require.Error(t, env.complete(workID, "fast"))

	assert.Empty(t, env.def.servedModels())
	assert.Empty(t, env.pinned.servedModels())
}

// The model gate decides on the pinned provider too. A pin never bypasses it.
func TestNodeSlotPin_TheModelGateDecidesOnThePin(t *testing.T) {
	env := newChainEnv(t, newAllowProviderFilter("default-p"))
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "fast-p", Model: "f-large"}})

	err := env.complete(workID, "fast")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model_access_denied")
	assert.Empty(t, env.pinned.servedModels())
}

// A provider-only pin never falls back to another provider in silence. Each
// case fails the completion, and no provider serves it.
func TestNodeSlotPin_AProviderOnlyPinNeverFallsBack(t *testing.T) {
	cases := []struct {
		name   string
		pin    *missionpb.LLMSlotConfig
		filter modelgate.Filter
	}{
		{name: "the tenant has no such provider", pin: &missionpb.LLMSlotConfig{Slot: "fast", Provider: "absent-p"}},
		{name: "the provider has no saved default model", pin: &missionpb.LLMSlotConfig{Slot: "fast", Provider: "unsaved-p"}},
		{
			name:   "the model gate denies the saved model of the provider",
			pin:    &missionpb.LLMSlotConfig{Slot: "fast", Provider: "fast-p"},
			filter: newAllowProviderFilter("default-p"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newChainEnv(t, tc.filter)
			workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{tc.pin})

			err := env.complete(workID, "fast")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "pinned to provider")
			assert.Empty(t, env.def.servedModels(), "the tenant default must not serve a pinned slot")
			assert.Empty(t, env.pinned.servedModels())
		})
	}
}
