// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"strings"
	"testing"
)

func TestLlmCall_CreateAndSnapshot(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{
		CallID: "c1", RunID: "r1", Model: "claude-haiku-4-5",
		ScopeID: "s1", PromptTokens: 100, CompletionTokens: 40,
	})

	got := w.LlmCallSnapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 llm call, got %d", len(got))
	}
	c := got[0]
	if c.CallID != "c1" || c.RunID != "r1" || c.Model != "claude-haiku-4-5" {
		t.Fatalf("unexpected snapshot: %+v", c)
	}
	if c.TotalTokens() != 140 {
		t.Fatalf("TotalTokens = %d, want 140", c.TotalTokens())
	}
}

func TestLlmCall_IdempotentEnrichment(t *testing.T) {
	w := NewWorld("t1")
	// First observation: identity + run link, no token data yet.
	Reduce(w, LlmCallObserved{CallID: "c1", RunID: "r1", Model: "m"})
	// Second observation of the same call: fills tokens, must NOT duplicate.
	Reduce(w, LlmCallObserved{CallID: "c1", PromptTokens: 10, CompletionTokens: 5})

	got := w.LlmCallSnapshot()
	if len(got) != 1 {
		t.Fatalf("idempotent: want 1 call, got %d", len(got))
	}
	c := got[0]
	if c.RunID != "r1" || c.Model != "m" {
		t.Fatalf("enrichment erased a known value: %+v", c)
	}
	if c.PromptTokens != 10 || c.CompletionTokens != 5 {
		t.Fatalf("tokens not enriched: %+v", c)
	}
}

func TestLlmCall_EnrichmentNeverErases(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{CallID: "c1", RunID: "r1", PromptTokens: 10})
	// A barer later report must not blank the known run link or tokens.
	Reduce(w, LlmCallObserved{CallID: "c1"})

	c := w.LlmCallSnapshot()[0]
	if c.RunID != "r1" || c.PromptTokens != 10 {
		t.Fatalf("barer report erased data: %+v", c)
	}
}

func TestLlmCall_TranscriptSetOnce(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{
		CallID:   "c1",
		Messages: []LlmMessage{{Role: "user", Content: "hello"}},
	})
	// A second observation must NOT overwrite an existing transcript.
	Reduce(w, LlmCallObserved{
		CallID:     "c1",
		Completion: "world", // fills the empty completion
		Messages:   []LlmMessage{{Role: "user", Content: "DIFFERENT"}},
	})

	c := w.LlmCallSnapshot()[0]
	if len(c.Messages) != 1 || c.Messages[0].Content != "hello" {
		t.Fatalf("transcript messages overwritten: %+v", c.Messages)
	}
	if c.Completion != "world" {
		t.Fatalf("completion not filled: %q", c.Completion)
	}
	// Snapshot returns a copy: mutating it must not affect the World.
	c.Messages[0].Content = "mutated"
	if w.LlmCallSnapshot()[0].Messages[0].Content != "hello" {
		t.Fatal("snapshot aliases the stored transcript")
	}
}

func TestLlmCall_EmptyCallIDIgnored(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{CallID: "", Model: "m"})
	if got := w.LlmCallSnapshot(); len(got) != 0 {
		t.Fatalf("empty CallID must be ignored, got %d", len(got))
	}
}

func TestLlmCall_DeterministicOrderAndReplay(t *testing.T) {
	events := []Event{
		LlmCallObserved{CallID: "c2", Model: "m2"},
		LlmCallObserved{CallID: "c1", Model: "m1"},
		LlmCallObserved{CallID: "c3", Model: "m3"},
	}
	fold := func() []LlmCallSnapshot {
		w := NewWorld("t1")
		for _, e := range events {
			Reduce(w, e)
		}
		return w.LlmCallSnapshot()
	}
	a, b := fold(), fold()
	if len(a) != 3 {
		t.Fatalf("want 3 calls, got %d", len(a))
	}
	if a[0].CallID != "c1" || a[1].CallID != "c2" || a[2].CallID != "c3" {
		t.Fatalf("not CallID-sorted: %+v", a)
	}
	// Two independent folds of the same Timeline must be identical (ADR-0001).
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("replay mismatch: %+v vs %+v", a, b)
	}
}

// TestLlmCall_CapturesToolCallsFullFidelity is the gibson#271 flight-recorder
// unit: a tool-calling turn's ToolCalls must not be silently dropped, on
// either a historical prompt message or the completion itself. Before this,
// LlmMessage only carried Role+Content and LlmCall had no
// CompletionToolCalls, so a tool-calling turn's transcript was incomplete.
func TestLlmCall_CapturesToolCallsFullFidelity(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{
		CallID: "c1",
		Messages: []LlmMessage{
			{Role: "user", Content: "scan 10.0.0.5"},
			{Role: "assistant", ToolCalls: []LlmToolCall{
				{ID: "call_1", Type: "function", Name: "nmap", Arguments: `{"host":"10.0.0.5"}`},
			}},
			{Role: "tool", ToolCallID: "call_1", Content: `{"ports":[22,80]}`},
		},
		CompletionToolCalls: []LlmToolCall{
			{ID: "call_2", Type: "function", Name: "nikto", Arguments: `{"host":"10.0.0.5"}`},
		},
	})

	c := w.LlmCallSnapshot()[0]
	if len(c.Messages) != 3 {
		t.Fatalf("want 3 messages, got %d: %+v", len(c.Messages), c.Messages)
	}
	if len(c.Messages[1].ToolCalls) != 1 || c.Messages[1].ToolCalls[0].Name != "nmap" {
		t.Fatalf("assistant message tool call not captured: %+v", c.Messages[1])
	}
	if c.Messages[1].ToolCalls[0].Arguments != `{"host":"10.0.0.5"}` {
		t.Fatalf("tool call arguments not captured: %+v", c.Messages[1].ToolCalls[0])
	}
	if c.Messages[2].ToolCallID != "call_1" {
		t.Fatalf("tool-result message ToolCallID not captured: %+v", c.Messages[2])
	}
	if len(c.CompletionToolCalls) != 1 || c.CompletionToolCalls[0].Name != "nikto" {
		t.Fatalf("completion tool calls not captured: %+v", c.CompletionToolCalls)
	}
}

// TestLlmCall_RedactionAppliedAtFoldTime proves retention/redaction is
// configurable per tenant (gibson#271 acceptance criterion): once a tenant's
// FlightRecorderPolicy has Redact=true, secret-shaped substrings in the
// transcript and any tool-call arguments are scrubbed once, at fold time.
func TestLlmCall_RedactionAppliedAtFoldTime(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FlightRecorderPolicySet{Redact: true})
	Reduce(w, LlmCallObserved{
		CallID:     "c1",
		Messages:   []LlmMessage{{Role: "user", Content: "use api_key=abcdefgh12345678 to auth"}},
		Completion: "Bearer sk-abcdefghijklmnopqrstuvwx",
		CompletionToolCalls: []LlmToolCall{
			{ID: "call_1", Name: "curl", Arguments: `{"header":"Authorization: Bearer sk-abcdefghijklmnopqrstuvwx"}`},
		},
	})

	c := w.LlmCallSnapshot()[0]
	if strings.Contains(c.Messages[0].Content, "abcdefgh12345678") {
		t.Fatalf("secret survived redaction: %q", c.Messages[0].Content)
	}
	if !strings.Contains(c.Messages[0].Content, redactedPlaceholder) {
		t.Fatalf("redacted message missing placeholder: %q", c.Messages[0].Content)
	}
	if strings.Contains(c.Completion, "sk-abcdefghijklmnopqrstuvwx") {
		t.Fatalf("completion secret survived redaction: %q", c.Completion)
	}
	if strings.Contains(c.CompletionToolCalls[0].Arguments, "sk-abcdefghijklmnopqrstuvwx") {
		t.Fatalf("tool call argument secret survived redaction: %q", c.CompletionToolCalls[0].Arguments)
	}
}

// TestLlmCall_NoRedactionByDefault proves capture stays full-fidelity (no
// silent scrubbing) until a tenant opts in — redaction is configurable, not
// on by default.
func TestLlmCall_NoRedactionByDefault(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{
		CallID:     "c1",
		Completion: "Bearer sk-abcdefghijklmnopqrstuvwx",
	})
	c := w.LlmCallSnapshot()[0]
	if c.Completion != "Bearer sk-abcdefghijklmnopqrstuvwx" {
		t.Fatalf("capture must stay full-fidelity by default, got %q", c.Completion)
	}
}

// TestLlmCall_RetentionSweepPurgesTextKeepsMetadata proves the retention half
// of the acceptance criterion: full text ages out per CutoffUnixNano, but the
// call's metadata (ids, model, tokens) — what the graph projects — survives.
func TestLlmCall_RetentionSweepPurgesTextKeepsMetadata(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{
		CallID: "old", Model: "m", PromptTokens: 10, CompletionTokens: 5,
		Messages:           []LlmMessage{{Role: "user", Content: "old secret content"}},
		Completion:         "old completion",
		RecordedAtUnixNano: 1000,
	})
	Reduce(w, LlmCallObserved{
		CallID: "new", Model: "m", PromptTokens: 10, CompletionTokens: 5,
		Messages:           []LlmMessage{{Role: "user", Content: "new content"}},
		Completion:         "new completion",
		RecordedAtUnixNano: 5000,
	})

	Reduce(w, FlightRecorderRetentionSwept{CutoffUnixNano: 2000})

	calls := w.LlmCallSnapshot()
	if len(calls) != 2 {
		t.Fatalf("want 2 calls, got %d", len(calls))
	}
	var oldCall, newCall LlmCallSnapshot
	for _, c := range calls {
		if c.CallID == "old" {
			oldCall = c
		} else {
			newCall = c
		}
	}
	if oldCall.Completion != purgedPlaceholder {
		t.Fatalf("text past cutoff should be purged, got %q", oldCall.Completion)
	}
	if oldCall.Model != "m" || oldCall.PromptTokens != 10 {
		t.Fatalf("metadata must survive a retention sweep: %+v", oldCall)
	}
	if newCall.Completion != "new completion" {
		t.Fatalf("text before cutoff must be untouched, got %q", newCall.Completion)
	}
}

// TestFlightRecorderPolicy_DefaultIsCaptureEverything proves the always-on
// default: a fresh World's policy never redacts and never expires text,
// so existing deployments keep today's behavior until a tenant opts in.
func TestFlightRecorderPolicy_DefaultIsCaptureEverything(t *testing.T) {
	w := NewWorld("t1")
	got := w.FlightRecorderPolicy()
	if got != DefaultFlightRecorderPolicy {
		t.Fatalf("fresh World policy = %+v, want default %+v", got, DefaultFlightRecorderPolicy)
	}
	if got.Redact || got.RetentionDays != 0 {
		t.Fatalf("default policy must capture everything unredacted, got %+v", got)
	}
}

// TestFlightRecorderPolicy_ReplayDeterministic proves a policy change is part
// of the deterministic Timeline: two independent folds of the same event
// sequence (policy set, then a call that must be redacted under it) produce
// identical World state.
func TestFlightRecorderPolicy_ReplayDeterministic(t *testing.T) {
	events := []Event{
		FlightRecorderPolicySet{Redact: true, RetentionDays: 30},
		LlmCallObserved{CallID: "c1", Completion: "api_key=supersecret123456"},
	}
	fold := func() LlmCallSnapshot {
		w := NewWorld("t1")
		for _, e := range events {
			Reduce(w, e)
		}
		return w.LlmCallSnapshot()[0]
	}
	a, b := fold(), fold()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("replay mismatch: %+v vs %+v", a, b)
	}
	if strings.Contains(a.Completion, "supersecret123456") {
		t.Fatalf("secret survived redaction under replay: %q", a.Completion)
	}
}
