// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"encoding/json"
	"strings"
	"testing"
)

func itemsOf(texts ...string) []json.RawMessage {
	out := make([]json.RawMessage, 0, len(texts))
	for _, s := range texts {
		b, _ := json.Marshal(map[string]any{"type": "message", "content": []any{map[string]any{"text": s}}})
		out = append(out, b)
	}
	return out
}

func TestLlmCallObserved_KeepsItemsCacheCountsAndCost(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, LlmCallObserved{
		CallID: "c1", Model: "m", Provider: "anthropic", Items: itemsOf("hello"),
		CacheReadTokens: 7, CacheWriteTokens: 3, Cost: "0.5",
	})
	got := w.LlmCallSnapshot()[0]
	if len(got.Items) != 1 || got.Provider != "anthropic" || got.CacheReadTokens != 7 ||
		got.CacheWriteTokens != 3 || got.Cost != "0.5" {
		t.Fatalf("call = %+v", got)
	}
	// A later report enriches blanks and never erases a known value.
	Reduce(w, LlmCallObserved{CallID: "c1", Cost: "9", Items: itemsOf("other")})
	again := w.LlmCallSnapshot()[0]
	if again.Cost != "0.5" || !strings.Contains(string(again.Items[0]), "hello") {
		t.Errorf("a second report changed the call: %+v", again)
	}
}

// An unpriced call keeps the empty cost. It is never turned into "0".
func TestLlmCallObserved_UnknownCostStaysEmpty(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, LlmCallObserved{CallID: "c1", Model: "m"})
	if got := w.LlmCallSnapshot()[0].Cost; got != "" {
		t.Errorf("cost = %q, want empty", got)
	}
}

func TestLlmCallObserved_RedactsEachStringOfEachItem(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, FlightRecorderPolicySet{Redact: true})
	secret := "Bearer abcdefghijklmnop12345"
	Reduce(w, LlmCallObserved{CallID: "c1", Items: itemsOf("token is " + secret)})
	got := string(w.LlmCallSnapshot()[0].Items[0])
	if strings.Contains(got, "abcdefghijklmnop12345") {
		t.Errorf("item still holds the secret: %s", got)
	}
	var v any
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Errorf("the redacted item is not JSON: %v", err)
	}
}

func TestLlmCall_ItemsSurviveASnapshotAndTheCodec(t *testing.T) {
	w := NewWorld("t")
	ev := LlmCallObserved{CallID: "c1", Items: itemsOf("a", "b"), Provider: "p", Cost: "1.5", CacheReadTokens: 2}
	b, err := EncodeEvent(ev)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecodeEvent(b)
	if err != nil {
		t.Fatal(err)
	}
	Reduce(w, dec)
	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatal(err)
	}
	got := restored.LlmCallSnapshot()[0]
	if len(got.Items) != 2 || got.Provider != "p" || got.Cost != "1.5" || got.CacheReadTokens != 2 {
		t.Errorf("restored call = %+v", got)
	}
}

// An event of the older shape has none of the new fields.
func TestLlmCallObserved_OldShapeDecodes(t *testing.T) {
	ev, err := DecodeEvent([]byte(`{"kind":"llm_call.observed","payload":{"CallID":"c1","Model":"m","PromptTokens":3}}`))
	if err != nil {
		t.Fatal(err)
	}
	got := ev.(LlmCallObserved)
	if got.Items != nil || got.Cost != "" || got.PromptTokens != 3 {
		t.Errorf("event = %+v", got)
	}
}

// The tokens of one call count one time, however often the event arrives. An
// event with no CallID counts every time, as the old path does.
func TestTokenUsed_ACallCountsOnce(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", RunID: "r1"})
	tokens := func() int64 { return w.MissionSnapshot()[0].TokensUsed }

	Reduce(w, TokenUsed{MissionID: "m1", Tokens: 100, CallID: "gw-1"})
	Reduce(w, TokenUsed{MissionID: "m1", Tokens: 100, CallID: "gw-1"})
	if got := tokens(); got != 100 {
		t.Fatalf("tokens after a repeated call = %d, want 100", got)
	}
	Reduce(w, TokenUsed{MissionID: "m1", Tokens: 50, CallID: "gw-2"})
	Reduce(w, TokenUsed{MissionID: "m1", Tokens: 7})
	Reduce(w, TokenUsed{MissionID: "m1", Tokens: 7})
	if got := tokens(); got != 164 {
		t.Fatalf("tokens = %d, want 164 (150 from two calls, 14 from two events with no CallID)", got)
	}
}

// A restore keeps the spend and the counted calls, so a call delivered again
// after a restart still counts once.
func TestTokenUsed_ASnapshotKeepsTheSpendAndTheCalls(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", RunID: "r1"})
	Reduce(w, TokenUsed{MissionID: "m1", Tokens: 100, CallID: "gw-1"})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatal(err)
	}
	if got := restored.MissionSnapshot()[0].TokensUsed; got != 100 {
		t.Fatalf("restored spend = %d, want 100", got)
	}
	Reduce(restored, TokenUsed{MissionID: "m1", Tokens: 100, CallID: "gw-1"})
	if got := restored.MissionSnapshot()[0].TokensUsed; got != 100 {
		t.Errorf("a call delivered again after a restore counted: spend = %d, want 100", got)
	}
}

func TestTokenUsed_TheSetEndsWithTheMission(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", RunID: "r1"})
	Reduce(w, TokenUsed{MissionID: "m1", Tokens: 1, CallID: "gw-1"})
	Reduce(w, MissionDone{ID: "m1", RunID: "r1", Outcome: MissionCompleted})
	if len(w.countedTokenCalls) != 0 {
		t.Errorf("counted calls = %v, want none after the mission ended", w.countedTokenCalls)
	}
}
