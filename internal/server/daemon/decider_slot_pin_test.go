// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/mission"
	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// modelRecorder is the test gateway of the Decider. It answers every call with
// "wait" and records the target and the request of each call.
type modelRecorder struct {
	targets []modelclient.Target
	callers []modelclient.Caller
	reqs    []modelclient.Request
	err     error
}

func (r *modelRecorder) Respond(
	_ context.Context, c modelclient.Caller, t modelclient.Target, req modelclient.Request,
) (*modelclient.Response, error) {
	r.callers = append(r.callers, c)
	r.targets = append(r.targets, t)
	r.reqs = append(r.reqs, req)
	if r.err != nil {
		return nil, r.err
	}
	return &modelclient.Response{Output: []modelclient.Item{{
		Type: modelclient.ItemMessage, Role: modelclient.RoleAssistant,
		Content: []modelclient.ContentPart{{Type: modelclient.PartOutputText, Text: `{"action":"wait"}`}},
	}}}, nil
}

// servedBy returns a view of the models that the gateway got for one provider.
func (r *modelRecorder) servedBy(provider string) *servedModels {
	return &servedModels{r: r, provider: provider}
}

type servedModels struct {
	r        *modelRecorder
	provider string
}

func (s *servedModels) servedModels() []string {
	var out []string
	for _, t := range s.r.targets {
		if t.Provider == s.provider {
			out = append(out, t.Model)
		}
	}
	return out
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
func decideWith(t *testing.T, def *missionpb.MissionDefinition, filter modelgate.Filter) (defaultP, fastP *servedModels, out brain.DeciderOutput, err error) {
	t.Helper()
	providers := []SlotProvider{
		{Name: "default-p", DefaultModel: "d-1"},
		{Name: "fast-p", DefaultModel: "f-small"},
	}
	gateway := &modelRecorder{}
	defaultP, fastP = gateway.servedBy("default-p"), gateway.servedBy("fast-p")
	logger := slog.New(slog.DiscardHandler)
	manager := NewDaemonSlotManager(providers, logger).WithDefaultProvider("default-p")
	if filter != nil {
		manager.WithModelFilter(filter)
	}

	factory, ferr := gibsonharness.NewHarnessFactory(gibsonharness.HarnessConfig{
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
	exec.models = gateway
	exec.register("m1", &missionBinding{
		ctx: context.Background(), tenant: chainTenant, harness: h, slot: deciderSlot,
		deciderPin: deciderSlotFrom(def.GetDeciderSlot()), initiator: "user:u1",
	})
	out, err = exec.Decide(context.Background(), brain.MissionContext{MissionID: "m1", Goal: "find things"})
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

// failingFilter is a model gate whose authorizer fails.
type failingFilter struct{}

func (failingFilter) Permitted(context.Context, []modelgate.Candidate) ([]modelgate.Candidate, error) {
	return nil, fmt.Errorf("fga: connection refused: %w", authz.ErrFgaUnavailable)
}

func (failingFilter) InvalidateCache() {}

// A gate that could not decide denies the call, but it does not end a pinned
// mission: a later decision can succeed, so the brain keeps its retry.
func TestDecide_AGateThatCannotDecideKeepsTheRetry(t *testing.T) {
	defaultP, fastP, out, err := decideWith(t, &missionpb.MissionDefinition{
		Id:          "m1",
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "fast-p", Model: "f-large"},
	}, failingFilter{})
	require.Error(t, err)
	require.ErrorIs(t, err, modelgate.ErrUnavailable)
	assert.Nil(t, out.Complete, "the mission does not end")
	assert.Empty(t, defaultP.servedModels())
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

// The Decider sends its call to the model gateway with the exact model name, the
// tenant and the mission of the binding, and the structured output schema. It
// emits no event of its own: the gateway trace is the one source.
func TestDecide_SendsOneGatewayCallWithTheIdentityOfTheMission(t *testing.T) {
	gateway := &modelRecorder{}
	providers := []SlotProvider{{Name: "default-p", DefaultModel: "d-1"}}
	logger := slog.New(slog.DiscardHandler)
	manager := NewDaemonSlotManager(providers, logger).WithDefaultProvider("default-p")
	factory, err := gibsonharness.NewHarnessFactory(gibsonharness.HarnessConfig{
		SlotManager: manager, Logger: logger,
		TargetFacts: func() gibsonharness.TargetFactsLookup { return noTargets{} },
	})
	require.NoError(t, err)
	def := &missionpb.MissionDefinition{Id: "m1"}
	m := &mission.Mission{ID: types.NewID(), Name: "pin", TenantID: chainTenant}
	missionCtx := newRunMissionContext(m, &mission.MissionRun{RunNumber: 1}, def, "run-1")
	h, err := newMissionHarness(factory, missionCtx, def, gibsonharness.TargetInfo{})
	require.NoError(t, err)

	exec := newBrainExecutor(nil, logger)
	exec.models = gateway
	exec.register("m1", &missionBinding{
		ctx: context.Background(), tenant: chainTenant, harness: h, slot: deciderSlot, initiator: "user:u1",
	})
	_, err = exec.Decide(context.Background(), brain.MissionContext{MissionID: "m1", Goal: "find things"})
	require.NoError(t, err)

	require.Len(t, gateway.targets, 1)
	assert.Equal(t, modelclient.Target{Tenant: chainTenant, Provider: "default-p", Model: "d-1"}, gateway.targets[0])
	c := gateway.callers[0]
	assert.Equal(t, chainTenant, c.Tenant)
	assert.Equal(t, "m1", c.Mission)
	assert.NotEmpty(t, c.Task)
	assert.Equal(t, "user:u1", c.Initiator)
	assert.Equal(t, "brain-decider", c.Purpose)
	req := gateway.reqs[0]
	require.NotNil(t, req.Text)
	assert.Equal(t, "json_schema", req.Text.Format.Type)
	assert.Contains(t, string(req.Text.Format.Schema), `"additionalProperties":false`)
	assert.NotEmpty(t, req.Input)
}

// A gateway refusal of a pinned Decider ends the mission with the reason, as a
// refusal by the slot gate did.
func TestDecide_AGatewayRefusalOfAPinnedDeciderFailsTheMission(t *testing.T) {
	providers := []SlotProvider{{Name: "fast-p", DefaultModel: "f-large"}}
	logger := slog.New(slog.DiscardHandler)
	manager := NewDaemonSlotManager(providers, logger).WithDefaultProvider("fast-p")
	factory, err := gibsonharness.NewHarnessFactory(gibsonharness.HarnessConfig{
		SlotManager: manager, Logger: logger,
		TargetFacts: func() gibsonharness.TargetFactsLookup { return noTargets{} },
	})
	require.NoError(t, err)
	def := &missionpb.MissionDefinition{
		Id: "m1", DeciderSlot: &missionpb.LLMSlotConfig{Provider: "fast-p", Model: "f-large"},
	}
	m := &mission.Mission{ID: types.NewID(), Name: "pin", TenantID: chainTenant}
	h, err := newMissionHarness(factory, newRunMissionContext(m, &mission.MissionRun{RunNumber: 1}, def, "run-1"),
		def, gibsonharness.TargetInfo{})
	require.NoError(t, err)

	exec := newBrainExecutor(nil, logger)
	exec.models = &modelRecorder{err: &modelclient.APIError{Status: 403, Body: "denied"}}
	exec.register("m1", &missionBinding{
		ctx: context.Background(), tenant: chainTenant, harness: h, slot: deciderSlot,
		deciderPin: deciderSlotFrom(def.GetDeciderSlot()),
	})
	out, err := exec.Decide(context.Background(), brain.MissionContext{MissionID: "m1"})
	require.NoError(t, err)
	require.NotNil(t, out.Complete)
	assert.Equal(t, "failed", out.Complete.Outcome)
	assert.Contains(t, out.Complete.Reason, "decider_slot")
}

// An error of the gateway that is not a refusal goes back to the brain, which
// retries on the next evidence change.
func TestDecide_AGatewayOutageKeepsTheRetry(t *testing.T) {
	providers := []SlotProvider{{Name: "default-p", DefaultModel: "d-1"}}
	logger := slog.New(slog.DiscardHandler)
	manager := NewDaemonSlotManager(providers, logger).WithDefaultProvider("default-p")
	factory, err := gibsonharness.NewHarnessFactory(gibsonharness.HarnessConfig{
		SlotManager: manager, Logger: logger,
		TargetFacts: func() gibsonharness.TargetFactsLookup { return noTargets{} },
	})
	require.NoError(t, err)
	def := &missionpb.MissionDefinition{Id: "m1"}
	m := &mission.Mission{ID: types.NewID(), Name: "pin", TenantID: chainTenant}
	h, err := newMissionHarness(factory, newRunMissionContext(m, &mission.MissionRun{RunNumber: 1}, def, "run-1"),
		def, gibsonharness.TargetInfo{})
	require.NoError(t, err)
	exec := newBrainExecutor(nil, logger)
	exec.models = &modelRecorder{err: &modelclient.APIError{Status: 502, Body: "bad gateway"}}
	exec.register("m1", &missionBinding{ctx: context.Background(), tenant: chainTenant, harness: h, slot: deciderSlot})
	out, err := exec.Decide(context.Background(), brain.MissionContext{MissionID: "m1"})
	require.Error(t, err)
	assert.Nil(t, out.Complete)
}
