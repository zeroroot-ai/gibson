// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package helpers

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// The exit test of the AAIF alignment reads llm_call.observed from the summary
// that GetTimeline returns. The daemon builds that summary with %+v of the event.
// These tests print the real event type the same way, so a change of the event
// shape fails here and not in a cluster run.
func TestParseLlmCallObserved_ReadsTheFieldsOfTheEvent(t *testing.T) {
	ev := &brain.LlmCallObserved{
		CallID: "call-1", MissionID: "m1", Model: "gpt-4o-mini", Provider: "mock",
		PromptTokens: 120, CompletionTokens: 45, Cost: "0.000123",
		Items: []json.RawMessage{
			json.RawMessage(`{"type":"function_call_output","output":"PORT-22-OPEN"}`),
			json.RawMessage(`{"type":"message","text":"I will run a port scan."}`),
		},
	}
	for name, summary := range map[string]string{
		"pointer": fmt.Sprintf("%+v", ev),
		"value":   fmt.Sprintf("%+v", *ev),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseLlmCallObserved(summary)
			require.NoError(t, err)
			require.Equal(t, "call-1", got.CallID)
			require.Equal(t, "gpt-4o-mini", got.Model)
			require.Equal(t, "mock", got.Provider)
			require.Equal(t, 120, got.PromptTokens)
			require.Equal(t, 45, got.CompletionTokens)
			require.Equal(t, "0.000123", got.Cost)
			require.Equal(t, []string{
				`{"type":"function_call_output","output":"PORT-22-OPEN"}`,
				`{"type":"message","text":"I will run a port scan."}`,
			}, got.Items)
		})
	}
}

func TestParseLlmCallObserved_AnEmptyCostIsEmpty(t *testing.T) {
	got, err := ParseLlmCallObserved(fmt.Sprintf("%+v", &brain.LlmCallObserved{CallID: "c", PromptTokens: 1}))
	require.NoError(t, err)
	require.Empty(t, got.Cost, "an unknown cost must read as empty")
	require.Empty(t, got.Items)
}

func TestParseLlmCallObserved_RefusesASummaryWithNoCallID(t *testing.T) {
	_, err := ParseLlmCallObserved("&{Model:x}")
	require.Error(t, err, "the fixture must fail: a summary with no call id is not an llm_call.observed event")
}

func TestOfKind_AndTheLoadMatcher(t *testing.T) {
	events := []TimelineEvent{{Kind: "a"}, {Kind: "b"}, {Kind: "a"}}
	require.Len(t, OfKind(events, "a"), 2)
	require.Empty(t, OfKind(events, "c"))
}

// The Agent Skills test counts load events by the text "Name:<name> ". This test
// prints the real event the way GetTimeline does, so a change of the field order
// fails here.
func TestAgentSkillLoadedSummaryHoldsTheNameAndTheDigest(t *testing.T) {
	ev := &brain.AgentSkillLoaded{MissionID: "m1", Name: "e2e-alpha", Digest: "sha256:abc"}
	s := fmt.Sprintf("%+v", ev)
	require.Contains(t, s, "Name:e2e-alpha ")
	require.Contains(t, s, "Digest:sha256:abc")
	require.Contains(t, s, "MissionID:m1")
}

// The A2A part of the AAIF test reads the target and the parent of a dispatch
// from the summary. The checks there use "Target:<name> " and "ParentID:".
func TestWorkDispatchedSummaryHoldsTheTargetAndTheParent(t *testing.T) {
	child := fmt.Sprintf("%+v", &brain.WorkDispatched{ID: "w2", ItemKind: "agent", Target: "e2e-a2a-callee", ParentID: "w1"})
	require.Contains(t, child, "Target:e2e-a2a-callee ")
	require.Contains(t, child, "ParentID:w1 ")
	root := fmt.Sprintf("%+v", &brain.WorkDispatched{ID: "w1", ItemKind: "agent", Target: "e2e-a2a-caller"})
	require.Contains(t, root, "ParentID: ", "a root dispatch has an empty parent")
}

// A failed call holds its status. The wait for a good call skips it.
func TestParseLlmCallObserved_ReadsTheStatusOfAFailedCall(t *testing.T) {
	failed, err := ParseLlmCallObserved(fmt.Sprintf("%+v", brain.LlmCallObserved{
		CallID: "c1", ErrorText: "route not found", HTTPStatus: 404,
	}))
	require.NoError(t, err)
	require.Equal(t, 404, failed.HTTPStatus)
	require.True(t, failed.Failed())

	good, err := ParseLlmCallObserved(fmt.Sprintf("%+v", brain.LlmCallObserved{CallID: "c2", PromptTokens: 120}))
	require.NoError(t, err)
	require.Zero(t, good.HTTPStatus)
	require.False(t, good.Failed())
}
