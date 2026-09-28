// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"strings"
	"testing"
)

// TestFlightRecorder_ReplayReproducesTheWorld is the core gibson#271
// determinism unit: World == fold(Timeline) for the flight recorder's own
// events (a policy change, a full LLM transcript with tool calls, and the
// tool call it caused), mirroring TestWorld_FoldAndReplay /
// TestEntityObserved_ReplayReproducesTheWorld for the other entity kinds.
func TestFlightRecorder_ReplayReproducesTheWorld(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("tenant-1")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(FlightRecorderPolicySet{Redact: true, RetentionDays: 30})
	apply(LlmCallObserved{
		CallID: "call-1", RunID: "run-1", MissionID: "mission-1", Model: "claude-haiku-4-5",
		PromptTokens: 42, CompletionTokens: 9,
		Messages: []LlmMessage{
			{Role: "user", Content: "scan the target"},
			{Role: "assistant", ToolCalls: []LlmToolCall{
				{ID: "tc-1", Type: "function", Name: "nmap", Arguments: `{"host":"10.0.0.5"}`},
			}},
		},
		CompletionToolCalls: []LlmToolCall{
			{ID: "tc-1", Type: "function", Name: "nmap", Arguments: `{"host":"10.0.0.5"}`},
		},
		RecordedAtUnixNano: 1_000_000,
	})
	apply(AgentToolCallObserved{
		ToolCallID: "tc-1", MissionID: "mission-1", RunID: "run-1", ToolName: "nmap",
		Arguments: `{"host":"10.0.0.5"}`, Result: `{"ports":[22,80]}`,
		RecordedAtUnixNano: 1_000_100,
	})

	wantCalls := w.LlmCallSnapshot()
	wantTools := w.AgentToolCallSnapshot()
	wantPolicy := w.FlightRecorderPolicy()

	replayed := Replay("tenant-1", tl)
	if got := replayed.LlmCallSnapshot(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("LlmCall replay diverged:\n got %+v\nwant %+v", got, wantCalls)
	}
	if got := replayed.AgentToolCallSnapshot(); !reflect.DeepEqual(got, wantTools) {
		t.Fatalf("AgentToolCall replay diverged:\n got %+v\nwant %+v", got, wantTools)
	}
	if got := replayed.FlightRecorderPolicy(); got != wantPolicy {
		t.Fatalf("FlightRecorderPolicy replay diverged: got %+v want %+v", got, wantPolicy)
	}
}

// TestFlightRecorder_SnapshotRoundTrips proves a hydrate-on-restart (snapshot
// + restore) reproduces the same captured transcript, tool call, and
// tenant policy — a tenant's opt-in redaction/retention setting must not
// silently reset to the capture-everything default across a restart
// (gibson#271).
func TestFlightRecorder_SnapshotRoundTrips(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, FlightRecorderPolicySet{Redact: true, RetentionDays: 14})
	Reduce(w, LlmCallObserved{
		CallID: "call-1", Model: "m", Completion: "safe text",
		CompletionToolCalls: []LlmToolCall{{ID: "tc-1", Name: "nmap", Arguments: "safe args"}},
		RecordedAtUnixNano:  500,
	})
	Reduce(w, AgentToolCallObserved{
		ToolCallID: "tc-1", ToolName: "nmap", Arguments: "safe args", Result: "safe result",
		RecordedAtUnixNano: 500,
	})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.LlmCallSnapshot(), w.LlmCallSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("LlmCalls did not round-trip:\n got %+v\nwant %+v", got, want)
	}
	if got, want := restored.AgentToolCallSnapshot(), w.AgentToolCallSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("AgentToolCalls did not round-trip:\n got %+v\nwant %+v", got, want)
	}
	if got, want := restored.FlightRecorderPolicy(), w.FlightRecorderPolicy(); got != want {
		t.Fatalf("FlightRecorderPolicy did not round-trip: got %+v want %+v", got, want)
	}
	if !restored.FlightRecorderPolicy().Redact {
		t.Fatal("tenant's opt-in redaction must survive a snapshot restore")
	}
}

// TestFlightRecorder_PolicyChangeMidTimeline_ReplaysSameEachTime proves
// ordering-sensitive determinism: a call folded BEFORE a policy change stays
// unredacted even under replay, and a call folded AFTER is redacted every
// time — the fold order on the Timeline, not wall-clock time, decides it.
func TestFlightRecorder_PolicyChangeMidTimeline_ReplaysSameEachTime(t *testing.T) {
	events := []Event{
		LlmCallObserved{CallID: "before", Completion: "api_key=leakedsecret12345"},
		FlightRecorderPolicySet{Redact: true},
		LlmCallObserved{CallID: "after", Completion: "api_key=leakedsecret12345"},
	}
	fold := func() []LlmCallSnapshot {
		w := NewWorld("t")
		for _, e := range events {
			Reduce(w, e)
		}
		return w.LlmCallSnapshot()
	}
	a, b := fold(), fold()
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("replay mismatch: %+v vs %+v", a, b)
	}
	var before, after LlmCallSnapshot
	for _, c := range a {
		if c.CallID == "before" {
			before = c
		} else {
			after = c
		}
	}
	if !strings.Contains(before.Completion, "leakedsecret12345") {
		t.Fatalf("a call folded before the policy took effect must stay unredacted, got %q", before.Completion)
	}
	if strings.Contains(after.Completion, "leakedsecret12345") {
		t.Fatalf("a call folded after the policy took effect must be redacted, got %q", after.Completion)
	}
}

func TestRedactSecrets_ScrubsCommonSecretShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"bearer token", "Authorization: Bearer sk-abcdefghijklmnopqrstuvwx"},
		{"aws access key", "key is AKIAABCDEFGHIJKLMNOP now rotate it"},
		{"api key kv", `api_key: "abcdefgh12345678"`},
		{"pem private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactSecrets(tc.in)
			if got == tc.in {
				t.Fatalf("expected %q to be scrubbed, got unchanged", tc.in)
			}
			if !strings.Contains(got, redactedPlaceholder) {
				t.Fatalf("scrubbed text missing placeholder: %q", got)
			}
		})
	}
}

func TestRedactSecrets_LeavesOrdinaryTextAlone(t *testing.T) {
	in := "scan 10.0.0.5 for open ports and report findings"
	if got := RedactSecrets(in); got != in {
		t.Fatalf("ordinary text must be left alone, got %q", got)
	}
}

// TestEngine_AgentToolCallsAndFlightRecorderPolicy exercises the Engine-level
// read accessors (the locked-wrapper counterparts to LlmCalls/World access
// used elsewhere) so the dashboard/read-path callers have a tested entry
// point onto the flight recorder's captured data.
func TestEngine_AgentToolCallsAndFlightRecorderPolicy(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(FlightRecorderPolicySet{Redact: true, RetentionDays: 7})
	e.Submit(AgentToolCallObserved{ToolCallID: "tc1", ToolName: "nmap"})
	e.Tick()

	got := e.AgentToolCalls()
	if len(got) != 1 || got[0].ToolCallID != "tc1" {
		t.Fatalf("Engine.AgentToolCalls() = %+v, want [tc1]", got)
	}
	if policy := e.FlightRecorderPolicy(); !policy.Redact || policy.RetentionDays != 7 {
		t.Fatalf("Engine.FlightRecorderPolicy() = %+v, want Redact=true RetentionDays=7", policy)
	}
}

// TestFlightRecorderRetentionSwept_ZeroCutoffIsNoOp proves a zero cutoff
// (the event's zero value) never purges anything — a defensive guard against
// an unset CutoffUnixNano wiping every captured call.
func TestFlightRecorderRetentionSwept_ZeroCutoffIsNoOp(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, LlmCallObserved{CallID: "c1", Completion: "keep me", RecordedAtUnixNano: 100})
	Reduce(w, AgentToolCallObserved{ToolCallID: "tc1", Result: "keep me too", RecordedAtUnixNano: 100})

	Reduce(w, FlightRecorderRetentionSwept{}) // CutoffUnixNano: 0

	if got := w.LlmCallSnapshot()[0].Completion; got != "keep me" {
		t.Fatalf("a zero cutoff must not purge, got %q", got)
	}
	if got := w.AgentToolCallSnapshot()[0].Result; got != "keep me too" {
		t.Fatalf("a zero cutoff must not purge, got %q", got)
	}
}

// TestFlightRecorderEvents_CodecRoundTrip proves the flight recorder's three
// event kinds (AgentToolCallObserved, FlightRecorderPolicySet,
// FlightRecorderRetentionSwept) survive the durable Timeline's JSON envelope
// round trip (EncodeEvent/DecodeEvent) — required for durable persistence
// (ADR-0011) and for the codec's kind registry to stay complete.
func TestFlightRecorderEvents_CodecRoundTrip(t *testing.T) {
	events := []Event{
		AgentToolCallObserved{
			ToolCallID: "tc1", MissionID: "m1", RunID: "r1", ScopeID: "s1",
			ToolName: "nmap", Arguments: `{"host":"x"}`, Result: `{"ok":true}`,
			Err: "", RecordedAtUnixNano: 42,
		},
		FlightRecorderPolicySet{Redact: true, RetentionDays: 30},
		FlightRecorderRetentionSwept{CutoffUnixNano: 12345},
	}
	for _, ev := range events {
		t.Run(ev.Kind(), func(t *testing.T) {
			b, err := EncodeEvent(ev)
			if err != nil {
				t.Fatalf("EncodeEvent: %v", err)
			}
			decoded, err := DecodeEvent(b)
			if err != nil {
				t.Fatalf("DecodeEvent: %v", err)
			}
			if !reflect.DeepEqual(decoded, ev) {
				t.Fatalf("round trip: got %#v (%T), want %#v", decoded, decoded, ev)
			}
		})
	}
}
