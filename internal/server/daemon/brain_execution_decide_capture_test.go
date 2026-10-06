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
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// deciderLLMHarness is an AgentHarness that only answers
// CompleteStructuredAnyWithUsage — the in-process call brainExecutor.Decide
// makes. Embedding the interface keeps the fake to the one method under test.
type deciderLLMHarness struct {
	gibsonharness.AgentHarness

	gotMessages []llm.Message
	result      *gibsonharness.StructuredCompletionResult
	err         error
}

func (h *deciderLLMHarness) CompleteStructuredAnyWithUsage(_ context.Context, _ string, messages []llm.Message, _ any, _ ...gibsonharness.CompletionOption) (*gibsonharness.StructuredCompletionResult, error) {
	h.gotMessages = messages
	if h.err != nil {
		return nil, h.err
	}
	return h.result, nil
}

// TestDecide_CapturesLLMCallOntoTimeline is the gibson#271 flight-recorder
// unit: the Decider's own reasoning turn — the brain's own LLM call, made
// in-process rather than over the callback RPCs captureLLMCall instruments —
// must land on the mission's Timeline as an LlmCallObserved, the same as
// every other fleet-agent LLM call. Before this fix it never did.
func TestDecide_CapturesLLMCallOntoTimeline(t *testing.T) {
	h := &deciderLLMHarness{
		result: &gibsonharness.StructuredCompletionResult{
			Result:           &deciderDecision{Action: "wait"},
			Model:            "claude-haiku-4-5",
			RawJSON:          `{"action":"wait"}`,
			PromptTokens:     123,
			CompletionTokens: 17,
		},
	}
	eng := brain.NewEngine("tenant-a", braintest.NewMemTimelineStore())
	b := newBrainExecutor(nil, slog.Default())
	b.register("m1", &missionBinding{ctx: context.Background(), eng: eng, harness: h})

	_, err := b.Decide(context.Background(), brain.MissionContext{MissionID: "m1", Goal: "find things"})
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	eng.Tick() // Submit only enqueues; Tick drains the intake queue into the World.

	calls := eng.LlmCalls()
	if len(calls) != 1 {
		t.Fatalf("want 1 captured LLM call, got %d: %+v", len(calls), calls)
	}
	c := calls[0]
	if c.Model != "claude-haiku-4-5" {
		t.Errorf("Model = %q, want claude-haiku-4-5", c.Model)
	}
	if c.PromptTokens != 123 || c.CompletionTokens != 17 {
		t.Errorf("tokens = %d/%d, want 123/17", c.PromptTokens, c.CompletionTokens)
	}
	if c.Completion != `{"action":"wait"}` {
		t.Errorf("Completion = %q, want the raw decision JSON", c.Completion)
	}
	if c.RunID != "" {
		t.Errorf("RunID = %q, want empty (a mission-level Decider call owns no AgentRun)", c.RunID)
	}
	if len(c.Messages) == 0 {
		t.Error("the Decider's own prompt must be captured, got no messages")
	}
	if c.RecordedAtUnixNano == 0 {
		t.Error("RecordedAtUnixNano must be stamped for retention sweeps")
	}

	// The mission-scoped frame must surface the Decider's own call too — same
	// mission-evidence edge as every other LLM call (mission_scope.go).
	if got := eng.MissionFrameAt("m1", eng.Timeline.Len()).LlmCallSnapshot(); len(got) != 1 {
		t.Errorf("mission m1 frame llm calls = %+v, want 1", got)
	}
}

// TestDecide_LLMErrorNeverCaptured proves the success-only rule, same as the
// callback LLM RPCs: a failed Decide call is not folded into the Timeline.
func TestDecide_LLMErrorNeverCaptured(t *testing.T) {
	h := &deciderLLMHarness{err: context.DeadlineExceeded}
	eng := brain.NewEngine("tenant-a", braintest.NewMemTimelineStore())
	b := newBrainExecutor(nil, slog.Default())
	b.register("m1", &missionBinding{ctx: context.Background(), eng: eng, harness: h})

	if _, err := b.Decide(context.Background(), brain.MissionContext{MissionID: "m1"}); err == nil {
		t.Fatal("expected the harness error to surface")
	}
	eng.Tick()
	if got := eng.LlmCalls(); len(got) != 0 {
		t.Errorf("a failed Decide must not be captured, got %+v", got)
	}
}
