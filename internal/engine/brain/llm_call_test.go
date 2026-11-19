// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"encoding/json"
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
		CallID: "c1", RequestItems: 1,
		Items: []json.RawMessage{json.RawMessage(`{"type":"message","role":"user","content":"hello"}`)},
	})
	// A second observation must NOT overwrite an existing transcript.
	Reduce(w, LlmCallObserved{
		CallID: "c1", RequestItems: 2,
		ErrorText: "world", // fills the empty error text
		Items: []json.RawMessage{
			json.RawMessage(`{"type":"message","role":"user","content":"DIFFERENT"}`),
			json.RawMessage(`{"type":"message","role":"assistant","content":"x"}`),
		},
	})

	c := w.LlmCallSnapshot()[0]
	if len(c.Items) != 1 || !strings.Contains(string(c.Items[0]), "hello") || c.RequestItems != 1 {
		t.Fatalf("transcript items overwritten: %s (request items %d)", c.Items, c.RequestItems)
	}
	if c.ErrorText != "world" {
		t.Fatalf("error text not filled: %q", c.ErrorText)
	}
	// Snapshot returns a copy: mutating it must not affect the World.
	c.Items[0] = json.RawMessage(`"mutated"`)
	if !strings.Contains(string(w.LlmCallSnapshot()[0].Items[0]), "hello") {
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
	// Two independent folds of the same Timeline must be identical (ADR-0101).
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("replay mismatch: %+v vs %+v", a, b)
	}
}

// TestLlmCall_EnrichesEveryFieldOnSecondObservation exercises every
// progressive-enrichment branch in applyLlmCallObserved: a bare first
// observation creates the entity with nothing set, so the second observation
// must go through the merge loop (not the create-entity path) to fill in
// RunID, Model, ScopeID, tokens, Items, ErrorText, HTTPStatus,
// and RecordedAtUnixNano.
func TestLlmCall_EnrichesEveryFieldOnSecondObservation(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{CallID: "c1"}) // bare: nothing set yet
	Reduce(w, LlmCallObserved{
		CallID: "c1", RunID: "r1", Model: "m", ScopeID: "s1",
		PromptTokens: 10, CompletionTokens: 5,
		Items:              []json.RawMessage{json.RawMessage(`{"type":"message","role":"user"}`)},
		RequestItems:       1,
		ErrorText:          "hello",
		HTTPStatus:         503,
		RecordedAtUnixNano: 42,
	})

	c := w.LlmCallSnapshot()[0]
	if c.RunID != "r1" || c.Model != "m" || c.ScopeID != "s1" {
		t.Fatalf("identity/provenance fields not enriched: %+v", c)
	}
	if c.PromptTokens != 10 || c.CompletionTokens != 5 {
		t.Fatalf("tokens not enriched: %+v", c)
	}
	if len(c.Items) != 1 || c.RequestItems != 1 || c.ErrorText != "hello" || c.HTTPStatus != 503 {
		t.Fatalf("transcript not enriched: %+v", c)
	}
	if c.RecordedAtUnixNano != 42 {
		t.Fatalf("RecordedAtUnixNano not enriched: %+v", c)
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
		CallID:       "c1",
		RequestItems: 1,
		Items: []json.RawMessage{
			json.RawMessage(`{"type":"function_call_output","output":"use api_key=abcdefgh12345678 to auth"}`),
			json.RawMessage(`{"type":"function_call","arguments":"{\"header\":\"Bearer sk-abcdefghijklmnopqrstuvwx\"}"}`),
		},
		ErrorText: "Bearer sk-abcdefghijklmnopqrstuvwx",
	})

	c := w.LlmCallSnapshot()[0]
	all := string(c.Items[0]) + string(c.Items[1])
	if strings.Contains(all, "abcdefgh12345678") || strings.Contains(all, "sk-abcdefghijklmnopqrstuvwx") {
		t.Fatalf("secret survived redaction in the items: %s", all)
	}
	if !strings.Contains(all, redactedPlaceholder) {
		t.Fatalf("redacted items miss the placeholder: %s", all)
	}
	if strings.Contains(c.ErrorText, "sk-abcdefghijklmnopqrstuvwx") {
		t.Fatalf("error text secret survived redaction: %q", c.ErrorText)
	}
}

// TestLlmCall_NoRedactionByDefault proves capture stays full-fidelity (no
// silent scrubbing) until a tenant opts in — redaction is configurable, not
// on by default.
func TestLlmCall_NoRedactionByDefault(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{
		CallID:    "c1",
		ErrorText: "Bearer sk-abcdefghijklmnopqrstuvwx",
	})
	c := w.LlmCallSnapshot()[0]
	if c.ErrorText != "Bearer sk-abcdefghijklmnopqrstuvwx" {
		t.Fatalf("capture must stay full-fidelity by default, got %q", c.ErrorText)
	}
}

// TestLlmCall_RetentionSweepPurgesTextKeepsMetadata proves the retention half
// of the acceptance criterion: full text ages out per CutoffUnixNano, but the
// call's metadata (ids, model, tokens) — what the graph projects — survives.
func TestLlmCall_RetentionSweepPurgesTextKeepsMetadata(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{
		CallID: "old", Model: "m", PromptTokens: 10, CompletionTokens: 5,
		Items:              []json.RawMessage{json.RawMessage(`{"type":"message","content":"old secret content"}`)},
		RequestItems:       1,
		ErrorText:          "old completion",
		RecordedAtUnixNano: 1000,
	})
	Reduce(w, LlmCallObserved{
		CallID: "new", Model: "m", PromptTokens: 10, CompletionTokens: 5,
		Items:              []json.RawMessage{json.RawMessage(`{"type":"message","content":"new content"}`)},
		RequestItems:       1,
		ErrorText:          "new completion",
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
	if oldCall.ErrorText != purgedPlaceholder {
		t.Fatalf("text past cutoff should be purged, got %q", oldCall.ErrorText)
	}
	if strings.Contains(string(oldCall.Items[0]), "old secret content") || len(oldCall.Items) != 1 {
		t.Fatalf("items past cutoff should be purged, got %s", oldCall.Items)
	}
	if oldCall.Model != "m" || oldCall.PromptTokens != 10 {
		t.Fatalf("metadata must survive a retention sweep: %+v", oldCall)
	}
	if newCall.ErrorText != "new completion" || !strings.Contains(string(newCall.Items[0]), "new content") {
		t.Fatalf("text before cutoff must be untouched, got %q %s", newCall.ErrorText, newCall.Items)
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
		LlmCallObserved{CallID: "c1", ErrorText: "api_key=supersecret123456"},
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
	if strings.Contains(a.ErrorText, "supersecret123456") {
		t.Fatalf("secret survived redaction under replay: %q", a.ErrorText)
	}
}
