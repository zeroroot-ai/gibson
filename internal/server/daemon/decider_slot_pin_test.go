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
// the mission harness that startMissionExecution builds with newMissionHarness. The harness comes
// from the real harness factory over a real DaemonSlotManager. The tenant has
// the default provider "default-p" and a second provider "fast-p".
func decideWith(t *testing.T, def *missionpb.MissionDefinition) (defaultP, fastP *deciderProvider, err error) {
	t.Helper()
	defaultP = &deciderProvider{&servingProvider{name: "default-p", models: []string{"d-1"}}}
	fastP = &deciderProvider{&servingProvider{name: "fast-p", models: []string{"f-small", "f-large"}}}
	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(defaultP))
	require.NoError(t, registry.RegisterProvider(fastP))
	logger := slog.New(slog.DiscardHandler)
	manager := NewDaemonSlotManager(registry, logger).WithDefaultProvider("default-p")

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
	_, err = exec.Decide(context.Background(), brain.MissionContext{MissionID: "m1", Goal: "find things"})
	return defaultP, fastP, err
}

// The Decider of a mission with a decider_slot runs on the pinned provider
// and model, not on the tenant default (gibson#1210).
func TestDecide_ServedByTheDeciderSlotPin(t *testing.T) {
	defaultP, fastP, err := decideWith(t, &missionpb.MissionDefinition{
		Id:          "m1",
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "fast-p", Model: "f-large"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"f-large"}, fastP.servedModels(), "the pinned provider serves the pinned model")
	assert.Empty(t, defaultP.servedModels(), "the tenant default serves nothing")
}

// A decider_slot that names only a provider runs on the saved default model
// of that provider.
func TestDecide_ProviderOnlyPinUsesTheSavedModel(t *testing.T) {
	defaultP, fastP, err := decideWith(t, &missionpb.MissionDefinition{
		Id:          "m1",
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "fast-p"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"f-small"}, fastP.servedModels())
	assert.Empty(t, defaultP.servedModels())
}

// A pin that the tenant cannot serve fails the Decider. It never falls back
// to the tenant default in silence (the rule of gibson#1203).
func TestDecide_UnservablePinFailsAndNeverFallsBack(t *testing.T) {
	defaultP, fastP, err := decideWith(t, &missionpb.MissionDefinition{
		Id:          "m1",
		DeciderSlot: &missionpb.LLMSlotConfig{Provider: "missing-p", Model: "x-1"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing-p")
	assert.Empty(t, defaultP.servedModels(), "no fallback to the tenant default")
	assert.Empty(t, fastP.servedModels())
}

// A mission with no decider_slot keeps the tenant default.
func TestDecide_NoDeciderSlotUsesTheTenantDefault(t *testing.T) {
	defaultP, fastP, err := decideWith(t, &missionpb.MissionDefinition{Id: "m1"})
	require.NoError(t, err)
	assert.Equal(t, []string{"d-1"}, defaultP.servedModels())
	assert.Empty(t, fastP.servedModels())
}
