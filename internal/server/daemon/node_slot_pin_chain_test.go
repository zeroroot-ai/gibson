// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// node_slot_pin_chain_test.go follows the LLM slot pin of a mission AGENT node
// from the mission definition to the provider that serves the completion of an
// agent served with sdk.ServeAgent (gibson#1203):
//
//	MissionNode.llm_slots → mission projection → brain scheduler → dispatch →
//	brainExecutor.Dispatch → agent.Task.SlotOverrides → harness.WorkSlotPins
//	(the work item of delegateToAgentViaWorkQueue) → WorkQueue.Enqueue →
//	ComponentService.ResolveModel → componentSlotModels → DaemonSlotManager.
//
// The harness hop from the task to the enqueued work item is covered in the
// harness package (TestDelegateToAgent_PutsTheNodeSlotPinsOnTheWorkItem). Here
// the same production function, harness.WorkSlotPins, makes the work item.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const chainTenant = "acme"

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

	providers := []SlotProvider{
		{Name: "default-p", DefaultModel: "d-1"},
		{Name: "fast-p", DefaultModel: "f-small"},
		{Name: "unsaved-p"},
	}
	logger := slog.New(slog.DiscardHandler)
	manager := NewDaemonSlotManager(providers, logger).WithDefaultProvider("default-p")
	if filter != nil {
		manager.WithModelFilter(filter)
	}
	models := &componentSlotModels{forTenant: func(_ context.Context, tenant string) (gibsonharness.SlotManager, error) {
		require.Equal(t, chainTenant, tenant)
		return manager, nil
	}}
	queue := component.NewRedisWorkQueue(client)
	claims := component.NewRedisWorkContextRegistry(sc)
	svc := component.NewComponentServiceServer(component.NewRedisComponentRegistry(client, time.Minute), queue, logger, nil, nil, nil).
		WithWorkContextRegistry(claims).
		WithSlotModelResolver(models).
		WithGateways(component.GatewayInfo{URL: "https://models.test"}, component.GatewayInfo{})
	return &chainEnv{svc: svc, queue: queue, manager: manager, claims: claims}
}

// dispatchNode runs one mission with one AGENT node that has the given slot
// pins through the projection, the scheduler and brainExecutor.Dispatch, and
// enqueues the agent work item the way delegateToAgentViaWorkQueue does. It
// returns the work id.
func (e *chainEnv) dispatchNode(t *testing.T, slots []*missionpb.LLMSlotConfig) string {
	t.Helper()
	return e.enqueueTask(t, e.dispatchTask(t, slots, nil, 0))
}

// dispatchTask runs the projection, the scheduler and brainExecutor.Dispatch
// for one AGENT node and returns the task that DelegateToAgent gets. nodeCap is
// the max_tokens_per_call of the node, or nil. missionCap is the value of the
// mission constraints.
func (e *chainEnv) dispatchTask(
	t *testing.T, slots []*missionpb.LLMSlotConfig, nodeCap *int32, missionCap int32,
) agent.Task {
	t.Helper()
	def := &missionpb.MissionDefinition{
		Id:          "m1",
		Constraints: &missionpb.MissionConstraints{MaxTokensPerCall: missionCap},
		Nodes: map[string]*missionpb.MissionNode{
			"recon": {
				Type: missionpb.NodeType_NODE_TYPE_AGENT,
				Config: &missionpb.MissionNode_AgentConfig{AgentConfig: &missionpb.AgentNodeConfig{
					AgentName:        "recon",
					LlmSlots:         slots,
					MaxTokensPerCall: nodeCap,
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

	return task
}

// enqueueTask puts the agent work item of the task on the queue the way
// delegateToAgentViaWorkQueue does, and returns the work id.
func (e *chainEnv) enqueueTask(t *testing.T, task agent.Task) string {
	t.Helper()
	workID := "agent-recon-chain"
	_, err := e.queue.Enqueue(context.Background(), chainTenant, "agent", "recon", component.WorkItem{
		WorkID:           workID,
		WorkType:         "execute",
		SlotPins:         gibsonharness.WorkSlotPins(task.SlotOverrides),
		MaxTokensPerCall: task.MaxTokensPerCall,
	})
	require.NoError(t, err)
	// The served agent claimed its work item, as PollWork records.
	require.NoError(t, e.claims.BindWorkClaim(context.Background(), workID, chainClaimant))
	return workID
}

// resolve calls ResolveModel for a slot of the work item, as a served agent in
// pull mode does. It returns the provider and the model of the reply.
func (e *chainEnv) resolve(workID, slot string) (provider, model string, err error) {
	resp, err := e.resolveReply(workID, slot)
	if err != nil {
		return "", "", err
	}
	return resp.GetProvider(), resp.GetModel(), nil
}

// resolveReply is resolve with the whole reply.
func (e *chainEnv) resolveReply(workID, slot string) (*componentpb.ResolveModelResponse, error) {
	tid, tidErr := auth.NewTenantID(chainTenant)
	if tidErr != nil {
		return nil, fmt.Errorf("tenant: %w", tidErr)
	}
	ctx := auth.WithIdentity(auth.ContextWithTenantString(context.Background(), chainTenant),
		auth.Identity{Subject: chainClaimant, Tenant: tid})
	resp, err := e.svc.ResolveModel(ctx, &componentpb.ResolveModelRequest{WorkId: workID, Slot: slot})
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", slot, err)
	}
	return resp, nil
}

// A node that pins a provider and a model gets that provider and model when
// its served agent resolves the slot. The tenant default serves nothing.
func TestNodeSlotPin_ReachesTheResolutionOfTheServedAgent(t *testing.T) {
	env := newChainEnv(t, nil)
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "fast-p", Model: "f-large"}})

	provider, model, err := env.resolve(workID, "fast")
	require.NoError(t, err)

	assert.Equal(t, "fast-p", provider)
	assert.Equal(t, "f-large", model)
}

// A slot that the node does not pin keeps the tenant default.
func TestNodeSlotPin_AnUnpinnedSlotKeepsTheTenantDefault(t *testing.T) {
	env := newChainEnv(t, nil)
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "fast-p", Model: "f-large"}})

	provider, model, err := env.resolve(workID, "primary")
	require.NoError(t, err)

	assert.Equal(t, "default-p", provider)
	assert.Equal(t, "d-1", model)
}

// A pin with a provider and no model gets the saved default model of that
// provider.
func TestNodeSlotPin_AProviderOnlyPinUsesThatProvider(t *testing.T) {
	env := newChainEnv(t, nil)
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "fast-p"}})

	provider, model, err := env.resolve(workID, "fast")
	require.NoError(t, err)

	assert.Equal(t, "fast-p", provider)
	assert.Equal(t, "f-small", model)
}

// A pin of a provider and a model that the tenant does not have fails the
// resolution with no silent fallback to another provider.
func TestNodeSlotPin_APinOfAMissingProviderFailsTheResolution(t *testing.T) {
	env := newChainEnv(t, nil)
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "absent-p", Model: "a-1"}})

	provider, model, err := env.resolve(workID, "fast")

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(errors.Unwrap(err)))
	assert.Empty(t, provider)
	assert.Empty(t, model)
}

// The model gate decides on the pinned provider too. A pin never bypasses it.
func TestNodeSlotPin_TheModelGateDecidesOnThePin(t *testing.T) {
	env := newChainEnv(t, newAllowProviderFilter("default-p"))
	workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "fast-p", Model: "f-large"}})

	_, _, err := env.resolve(workID, "fast")

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(errors.Unwrap(err)))
}

// A provider-only pin never falls back to another provider in silence. Each
// case fails the resolution, and no provider is picked.
func TestNodeSlotPin_AProviderOnlyPinNeverFallsBack(t *testing.T) {
	cases := []struct {
		name   string
		pin    *missionpb.LLMSlotConfig
		filter modelgate.Filter
		want   codes.Code
	}{
		{name: "the tenant has no such provider", pin: &missionpb.LLMSlotConfig{Slot: "fast", Provider: "absent-p"}, want: codes.NotFound},
		{name: "the provider has no saved default model", pin: &missionpb.LLMSlotConfig{Slot: "fast", Provider: "unsaved-p"}, want: codes.NotFound},
		{
			name:   "the model gate denies the saved model of the provider",
			pin:    &missionpb.LLMSlotConfig{Slot: "fast", Provider: "fast-p"},
			filter: newAllowProviderFilter("default-p"),
			want:   codes.PermissionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newChainEnv(t, tc.filter)
			workID := env.dispatchNode(t, []*missionpb.LLMSlotConfig{tc.pin})

			provider, _, err := env.resolve(workID, "fast")

			require.Error(t, err)
			assert.Equal(t, tc.want, status.Code(errors.Unwrap(err)))
			assert.Empty(t, provider, "the tenant default must not serve a pinned slot")
		})
	}
}

// resolveOnTheHarness resolves a slot the way an agent in callback mode does:
// the child harness of the node answers, built from the task that
// DelegateToAgent got. The callback service passes the harness to
// gibsonharness.ResolveModel.
func (e *chainEnv) resolveOnTheHarness(t *testing.T, task agent.Task, slot string) (*gibsonharness.ModelResolution, error) {
	t.Helper()
	factory, err := gibsonharness.NewHarnessFactory(gibsonharness.HarnessConfig{
		SlotManagerForTenant: fixedTenantSlots(e.manager),
		Logger:               slog.New(slog.DiscardHandler),
		TargetFacts:          func() gibsonharness.TargetFactsLookup { return noTargets{} },
	})
	require.NoError(t, err)
	mc := gibsonharness.MissionContext{
		ID: types.NewID(), TenantID: chainTenant, CurrentAgent: "recon",
		NodeSlotOverrides: task.SlotOverrides, NodeMaxTokensPerCall: task.MaxTokensPerCall,
	}
	h, err := factory.Create("recon", mc, gibsonharness.TargetInfo{})
	require.NoError(t, err)
	res, err := gibsonharness.ResolveModel(context.Background(), h, chainTenant, slot,
		gibsonharness.GatewayInfo{URL: "https://models.test"})
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", slot, err)
	}
	return res, nil
}

// One node pin reaches the answer of BOTH services, from the mission definition
// through the projection, the scheduler and the dispatch. The pinned provider
// and model, and the token cap of the node, are the same on the ComponentService
// (an agent in pull mode) and on the harness behind the callback service (an
// agent in callback mode).
func TestNodeSlotPin_ReachesResolveModelOnBothServices(t *testing.T) {
	env := newChainEnv(t, nil)
	nodeCap := int32(700)
	task := env.dispatchTask(t,
		[]*missionpb.LLMSlotConfig{{Slot: "fast", Provider: "fast-p", Model: "f-large"}}, &nodeCap, 5000)
	require.Equal(t, int32(700), task.MaxTokensPerCall, "the node cap wins over the mission cap")
	workID := env.enqueueTask(t, task)

	pull, err := env.resolveReply(workID, "fast")
	require.NoError(t, err)
	callback, err := env.resolveOnTheHarness(t, task, "fast")
	require.NoError(t, err)

	assert.Equal(t, "fast-p", pull.GetProvider())
	assert.Equal(t, "f-large", pull.GetModel())
	assert.EqualValues(t, 700, pull.GetMaxOutputTokens())
	assert.Equal(t, "fast-p", callback.Provider)
	assert.Equal(t, "f-large", callback.Model)
	assert.EqualValues(t, 700, callback.MaxOutputTokens)
	assert.Equal(t, pull.GetRouteHeaders(), callback.RouteHeaders)

	// A slot that the node does not pin keeps the tenant default on both.
	pull, err = env.resolveReply(workID, "primary")
	require.NoError(t, err)
	callback, err = env.resolveOnTheHarness(t, task, "primary")
	require.NoError(t, err)
	assert.Equal(t, "default-p", pull.GetProvider())
	assert.Equal(t, "default-p", callback.Provider)
}

// A node with no cap gets the cap of the mission on both services.
func TestNodeSlotPin_TheMissionTokenCapReachesBothServices(t *testing.T) {
	env := newChainEnv(t, nil)
	task := env.dispatchTask(t, nil, nil, 3000)
	workID := env.enqueueTask(t, task)

	pull, err := env.resolveReply(workID, "primary")
	require.NoError(t, err)
	callback, err := env.resolveOnTheHarness(t, task, "primary")
	require.NoError(t, err)

	assert.EqualValues(t, 3000, pull.GetMaxOutputTokens())
	assert.EqualValues(t, 3000, callback.MaxOutputTokens)
}
