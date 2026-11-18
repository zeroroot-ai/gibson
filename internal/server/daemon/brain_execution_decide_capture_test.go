// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
)

// slotModelHarness is an AgentHarness that only resolves a slot to a model. The
// Decider resolves its slot and then calls the gateway. Embedding the interface
// keeps the fake to the one method under test.
type slotModelHarness struct {
	gibsonharness.AgentHarness
	picked gibsonharness.SlotModel
	err    error
}

func (h *slotModelHarness) ResolveSlotModel(context.Context, string) (gibsonharness.SlotModel, error) {
	return h.picked, h.err
}

// The Decider emits no llm_call.observed event of its own (gibson#1392). The
// gateway trace is the one source of that event and of token.used, so a second
// emit here would count the call twice.
func TestDecide_EmitsNoLLMCallEvent(t *testing.T) {
	h := &slotModelHarness{picked: gibsonharness.SlotModel{Provider: "p", Model: "claude-haiku-4-5"}}
	eng := brain.NewEngine("tenant-a", braintest.NewMemTimelineStore())
	b := newBrainExecutor(nil, slog.Default())
	b.models = &modelRecorder{}
	b.register("m1", &missionBinding{ctx: context.Background(), tenant: "tenant-a", eng: eng, harness: h})

	if _, err := b.Decide(context.Background(), brain.MissionContext{MissionID: "m1", Goal: "find things"}); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	eng.Tick() // Submit only enqueues; Tick drains the intake queue into the World.
	if got := eng.LlmCalls(); len(got) != 0 {
		t.Errorf("Decide emitted %d llm_call.observed events, want 0: %+v", len(got), got)
	}
}

// A Decider with no model client fails loud. It never falls back to a provider.
func TestDecide_NoModelClientIsAnError(t *testing.T) {
	h := &slotModelHarness{picked: gibsonharness.SlotModel{Provider: "p", Model: "m"}}
	b := newBrainExecutor(nil, slog.Default())
	b.register("m1", &missionBinding{ctx: context.Background(), tenant: "tenant-a", harness: h})
	if _, err := b.Decide(context.Background(), brain.MissionContext{MissionID: "m1"}); err == nil {
		t.Fatal("Decide with no model client gave no error")
	}
}
