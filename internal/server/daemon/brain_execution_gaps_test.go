// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
)

// textModels answers each Decider call with the given text.
type textModels struct{ text string }

func (m textModels) Respond(context.Context, modelclient.Caller, modelclient.Target, modelclient.Request,
) (*modelclient.Response, error) {
	return &modelclient.Response{Output: []modelclient.Item{{
		Type: modelclient.ItemMessage, Role: modelclient.RoleAssistant,
		Content: []modelclient.ContentPart{{Type: modelclient.PartOutputText, Text: m.text}},
	}}}, nil
}

func TestDecide_Failures(t *testing.T) {
	ctx := context.Background()
	mc := brain.MissionContext{MissionID: "m1", Goal: "find things"}
	picked := gibsonharness.SlotModel{Provider: "p", Model: "m"}

	t.Run("no binding for the mission", func(t *testing.T) {
		_, err := newBrainExecutor(nil, slog.Default()).Decide(ctx, mc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no binding for mission m1")
	})

	t.Run("a harness that cannot resolve a slot", func(t *testing.T) {
		b := newBrainExecutor(nil, slog.Default())
		b.models = &modelRecorder{}
		b.register("m1", &missionBinding{ctx: ctx, tenant: "acme", harness: nil})
		_, err := b.Decide(ctx, mc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot resolve a slot to a model")
	})

	t.Run("the model does not return the decision schema", func(t *testing.T) {
		b := newBrainExecutor(nil, slog.Default())
		b.models = textModels{text: "I think we should wait"}
		b.register("m1", &missionBinding{
			ctx: ctx, tenant: "acme", eng: brain.NewEngine("acme", braintest.NewMemTimelineStore()),
			harness: &slotModelHarness{picked: picked},
		})
		_, err := b.Decide(ctx, mc)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "did not return the decision schema")
	})
}

func TestAwaitMissionGate_AWorkItemWithNoMissionNeedsNoGate(t *testing.T) {
	b := newBrainExecutor(nil, slog.Default())
	b.gate = func(string) MissionGateAwaiter {
		t.Fatal("the gate was read for a work item with no mission")
		return nil
	}
	eng := brain.NewEngine("acme", braintest.NewMemTimelineStore())
	require.NoError(t, b.awaitMissionGate(context.Background(), eng, brain.DispatchRequest{WorkID: "w1"}))
}

func TestDeciderInput_MapsEachRole(t *testing.T) {
	items := deciderInput([]deciderMessage{
		{Role: deciderRoleSystem, Content: "be brief"},
		{Role: deciderRoleAssistant, Content: "earlier"},
		{Role: "user", Content: "now"},
	})
	require.Len(t, items, 3)
	assert.Equal(t, modelclient.RoleSystem, items[0].Role)
	assert.Equal(t, modelclient.RoleAssistant, items[1].Role)
	assert.Equal(t, modelclient.RoleUser, items[2].Role)
}

func TestMissionInitiatorOf_OnlyAPersonIsAnInitiator(t *testing.T) {
	assert.Equal(t, "user:u-1", missionInitiatorOf(principal.Principal{Kind: principal.User, ID: "u-1"}))
	assert.Empty(t, missionInitiatorOf(principal.Principal{Kind: principal.User}), "a user with no id")
	assert.Empty(t, missionInitiatorOf(principal.Principal{Kind: principal.Service, ID: "svc-1"}), "a service")
	assert.Empty(t, missionInitiatorOf(principal.Principal{}))
}
