package brain

import (
	"reflect"
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
