// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/modelgate"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// deciderProvider is a provider with structured output that answers every
// Decider call with "wait" and records the model of each call.
type deciderProvider struct {
	*servingProvider
}

func (p *deciderProvider) SupportsStructuredOutput(types.ResponseFormatType) bool { return true }

func (p *deciderProvider) CompleteStructured(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	resp, err := p.Complete(ctx, req)
	if err != nil {
		return nil, err
	}
	resp.RawJSON = `{"action":"wait"}`
	return resp, nil
}

// noTargets is a target lookup that has no target.
type noTargets struct{}

func (noTargets) Get(context.Context, types.ID) (*types.Target, error) {
	return nil, errors.New("no target in this test")
}

// decideWith runs one Decider call of a mission with the given definition on
// the mission harness that executeMission builds with newMissionHarness. The
// harness comes from the real harness factory over a real DaemonSlotManager.
// The tenant has the default provider "default-p" and a second provider
// "fast-p". A non-nil filter is the model gate.
func decideWith(t *testing.T, def *missionpb.MissionDefinition, filter modelgate.Filter) (defaultP, fastP *deciderProvider, out brain.DeciderOutput, err error) {
	t.Helper()
	defaultP = &deciderProvider{&servingProvider{name: "default-p", models: []string{"d-1"}}}
	fastP = &deciderProvider{&servingProvider{name: "fast-p", models: []string{"f-small", "f-large"}}}
	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(defaultP))
	require.NoError(t, registry.RegisterProvider(fastP))
	logger := slog.New(slog.DiscardHandler)
	manager := NewDaemonSlotManager(registry, logger).WithDefaultProvider("default-p")
	if filter != nil {
		manager.WithModelFilter(filter)
	}

	factory, ferr := gibsonharness.NewHarnessFactory(gibsonharness.HarnessConfig{
		LLMRegistry: registry,
		SlotManager: manager,
		Logger:      logger,
		// The Decider dispatches no tool, so it reads no target.
		TargetFacts: func() gibsonharness.TargetFactsLookup { return noTargets{} },
	})
	require.NoError(t, ferr)

	m := &mission.Mission{ID: types.NewID(), Name: "pin", TenantID: chainTenant}
	missionCtx := newRunMissionContext(m, &mission.MissionRun{RunNumber: 1}, def, "run-1")
	h, herr := newMissionHarness(factory, missionCtx, def, gibsonharness.TargetInfo{})
	require.NoError(t, herr)

	exec := newBrainExecutor(nil, logger)
	exec.register("m1", &missionBinding{ctx: context.Background(), tenant: chainTenant, harness: h, slot: deciderSlot})
	out, err = exec.Decide(context.Background(), brain.MissionContext{
		MissionID:   "m1",
		Goal:        "find things",
		DeciderSlot: deciderSlotFrom(def.GetDeciderSlot()),
	})
	return defaultP, fastP, out, err
}

// The Decider of a mission with a decider_slot runs on the pinned provider
// and model, not on the tenant default (gibson#1210).
func TestDecide_ServedByTheDeciderSlotPin(t *testing.T) {
	defaultP, fastP, out, err := decideWith(t, &missionpb.MissionDefinition{
		Id:          "m1",
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "fast-p", Model: "f-large"},
	}, nil)
	require.NoError(t, err)
	assert.Nil(t, out.Complete, "the decision is wait")
	assert.Equal(t, []string{"f-large"}, fastP.servedModels(), "the pinned provider serves the pinned model")
	assert.Empty(t, defaultP.servedModels(), "the tenant default serves nothing")
}

// A decider_slot that names only a provider runs on the saved default model
// of that provider.
func TestDecide_ProviderOnlyPinUsesTheSavedModel(t *testing.T) {
	defaultP, fastP, _, err := decideWith(t, &missionpb.MissionDefinition{
		Id:          "m1",
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "fast-p"},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"f-small"}, fastP.servedModels())
	assert.Empty(t, defaultP.servedModels())
}

// A decider_slot that names only a model follows the node pin rule of
// gibson#1203: the tenant default provider serves the pinned model.
func TestDecide_ModelOnlyPinRunsOnTheDefaultProvider(t *testing.T) {
	defaultP, fastP, _, err := decideWith(t, &missionpb.MissionDefinition{
		Id:          "m1",
		DeciderSlot: &missionpb.LLMSlotConfig{Model: "f-large"},
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"f-large"}, defaultP.servedModels())
	assert.Empty(t, fastP.servedModels())
}

// A pin that the tenant cannot serve fails the mission with the reason. It
// never falls back to the tenant default in silence (the rule of gibson#1203),
// and the brain does not retry it forever.
func TestDecide_UnservablePinFailsTheMission(t *testing.T) {
	defaultP, fastP, out, err := decideWith(t, &missionpb.MissionDefinition{
		Id:          "m1",
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "missing-p", Model: "x-1"},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, out.Complete)
	assert.Equal(t, "failed", out.Complete.Outcome)
	assert.Contains(t, out.Complete.Reason, "decider_slot")
	assert.Contains(t, out.Complete.Reason, "missing-p")
	assert.Empty(t, defaultP.servedModels(), "no fallback to the tenant default")
	assert.Empty(t, fastP.servedModels())
}

// The model gate still decides for a pinned Decider. A pin does not open a
// path around the gate.
func TestDecide_TheModelGateDeniesAPinnedDecider(t *testing.T) {
	defaultP, fastP, out, err := decideWith(t, &missionpb.MissionDefinition{
		Id:          "m1",
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "fast-p", Model: "f-large"},
	}, newAllowProviderFilter("default-p"))
	require.NoError(t, err)
	require.NotNil(t, out.Complete)
	assert.Equal(t, "failed", out.Complete.Outcome)
	assert.Contains(t, out.Complete.Reason, "model_access_denied")
	assert.Empty(t, defaultP.servedModels(), "no fallback to the tenant default")
	assert.Empty(t, fastP.servedModels())
}

// Without a pin, a Decider that cannot resolve its slot keeps the retry of the
// brain: the error goes back to the DeciderWorker.
func TestDecide_UnpinnedResolutionFailureKeepsTheRetry(t *testing.T) {
	_, _, out, err := decideWith(t, &missionpb.MissionDefinition{Id: "m1"}, newAllowProviderFilter())
	require.Error(t, err)
	assert.Nil(t, out.Complete)
}

// A mission with no decider_slot keeps the tenant default.
func TestDecide_NoDeciderSlotUsesTheTenantDefault(t *testing.T) {
	defaultP, fastP, _, err := decideWith(t, &missionpb.MissionDefinition{Id: "m1"}, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"d-1"}, defaultP.servedModels())
	assert.Empty(t, fastP.servedModels())
}

// recordingHarnessFactory records the mission context of each Create and
// refuses it, so executeMission stops at the harness step.
type recordingHarnessFactory struct {
	created []gibsonharness.MissionContext
}

func (f *recordingHarnessFactory) Create(_ string, mc gibsonharness.MissionContext, _ gibsonharness.TargetInfo) (gibsonharness.AgentHarness, error) {
	f.created = append(f.created, mc)
	return nil, errors.New("recording factory builds no harness")
}

func (f *recordingHarnessFactory) CreateChild(gibsonharness.AgentHarness, string) (gibsonharness.AgentHarness, error) {
	return nil, errors.New("recording factory builds no child")
}

// executeMission builds the mission harness with the decider_slot pin
// (gibson#1210). This test fails if the call site drops the pin.
func TestExecuteMission_TheMissionHarnessCarriesTheDeciderPin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mm, tenant := execMissionTestManager(ctx, t)
	mm.pool = &mockPool{conn: minimalConn()}
	mm.graphWriter = newFakeGraphWriter()
	factory := &recordingHarnessFactory{}
	mm.harnessFactory = factory
	seedRunnableActive(mm, tenant, "m-pin")

	mm.executeMission(context.Background(), "m-pin", &missionpb.MissionDefinition{
		Name:        "recon",
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "fast-p", Model: "f-large"},
	})

	assertWorldFailed(t, mm, tenant, "m-pin")
	require.Len(t, factory.created, 1, "executeMission reached the harness step")
	pin := factory.created[0].NodeSlotOverrides[deciderSlot]
	require.NotNil(t, pin, "the mission harness carries the decider pin")
	assert.Equal(t, "fast-p", pin.Provider)
	assert.Equal(t, "f-large", pin.Model)
}
