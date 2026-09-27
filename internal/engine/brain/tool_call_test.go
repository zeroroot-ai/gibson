// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"strings"
	"testing"
)

func TestAgentToolCall_CreateAndSnapshot(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, AgentToolCallObserved{
		ToolCallID: "tc1", MissionID: "m1", RunID: "r1", ScopeID: "s1",
		ToolName: "nmap", Arguments: `{"host":"10.0.0.5"}`, Result: `{"ports":[22,80]}`,
		RecordedAtUnixNano: 100,
	})

	got := w.AgentToolCallSnapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 tool call, got %d", len(got))
	}
	c := got[0]
	if c.ToolCallID != "tc1" || c.MissionID != "m1" || c.RunID != "r1" || c.ToolName != "nmap" {
		t.Fatalf("unexpected snapshot: %+v", c)
	}
	if c.Arguments != `{"host":"10.0.0.5"}` || c.Result != `{"ports":[22,80]}` {
		t.Fatalf("arguments/result not captured full-fidelity: %+v", c)
	}
}

func TestAgentToolCall_EmptyToolCallIDIgnored(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, AgentToolCallObserved{ToolCallID: "", ToolName: "nmap"})
	if got := w.AgentToolCallSnapshot(); len(got) != 0 {
		t.Fatalf("empty ToolCallID must be ignored, got %d", len(got))
	}
}

// TestAgentToolCall_IdempotentEnrichment mirrors the LlmCall reducer contract:
// a later, barer observation of the same call must enrich, never erase.
func TestAgentToolCall_IdempotentEnrichment(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, AgentToolCallObserved{ToolCallID: "tc1", ToolName: "nmap", RunID: "r1"})
	Reduce(w, AgentToolCallObserved{ToolCallID: "tc1", Arguments: `{"host":"x"}`, Result: `{"ok":true}`})

	got := w.AgentToolCallSnapshot()
	if len(got) != 1 {
		t.Fatalf("idempotent: want 1 call, got %d", len(got))
	}
	c := got[0]
	if c.ToolName != "nmap" || c.RunID != "r1" {
		t.Fatalf("enrichment erased a known value: %+v", c)
	}
	if c.Arguments != `{"host":"x"}` || c.Result != `{"ok":true}` {
		t.Fatalf("tool call not enriched: %+v", c)
	}
}

func TestAgentToolCall_ErrCaptured(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, AgentToolCallObserved{ToolCallID: "tc1", ToolName: "nmap", Err: "connection refused"})
	c := w.AgentToolCallSnapshot()[0]
	if c.Err != "connection refused" {
		t.Fatalf("tool call error not captured: %+v", c)
	}
}

func TestAgentToolCall_DeterministicOrderAndReplay(t *testing.T) {
	events := []Event{
		AgentToolCallObserved{ToolCallID: "tc2", ToolName: "t2"},
		AgentToolCallObserved{ToolCallID: "tc1", ToolName: "t1"},
		AgentToolCallObserved{ToolCallID: "tc3", ToolName: "t3"},
	}
	fold := func() []AgentToolCallSnapshot {
		w := NewWorld("t1")
		for _, e := range events {
			Reduce(w, e)
		}
		return w.AgentToolCallSnapshot()
	}
	a, b := fold(), fold()
	if len(a) != 3 || a[0].ToolCallID != "tc1" || a[1].ToolCallID != "tc2" || a[2].ToolCallID != "tc3" {
		t.Fatalf("not ToolCallID-sorted: %+v", a)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("replay mismatch: %+v vs %+v", a, b)
	}
}

// TestAgentToolCall_RedactionAppliedAtFoldTime proves tool I/O honors the same
// per-tenant redaction policy as LLM transcripts (gibson#271).
func TestAgentToolCall_RedactionAppliedAtFoldTime(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FlightRecorderPolicySet{Redact: true})
	Reduce(w, AgentToolCallObserved{
		ToolCallID: "tc1", ToolName: "curl",
		Arguments: `{"header":"Authorization: Bearer sk-abcdefghijklmnopqrstuvwx"}`,
		Result:    "api_key=abcdefgh12345678 accepted",
	})

	c := w.AgentToolCallSnapshot()[0]
	if strings.Contains(c.Arguments, "sk-abcdefghijklmnopqrstuvwx") {
		t.Fatalf("tool call argument secret survived redaction: %q", c.Arguments)
	}
	if strings.Contains(c.Result, "abcdefgh12345678") {
		t.Fatalf("tool call result secret survived redaction: %q", c.Result)
	}
}

// TestAgentToolCall_RetentionSweepPurgesTextKeepsMetadata mirrors the LlmCall
// retention unit: full I/O text ages out, metadata survives.
func TestAgentToolCall_RetentionSweepPurgesTextKeepsMetadata(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, AgentToolCallObserved{
		ToolCallID: "old", ToolName: "nmap", Arguments: "old args", Result: "old result",
		RecordedAtUnixNano: 1000,
	})
	Reduce(w, AgentToolCallObserved{
		ToolCallID: "new", ToolName: "nmap", Arguments: "new args", Result: "new result",
		RecordedAtUnixNano: 5000,
	})

	Reduce(w, FlightRecorderRetentionSwept{CutoffUnixNano: 2000})

	calls := w.AgentToolCallSnapshot()
	var oldCall, newCall AgentToolCallSnapshot
	for _, c := range calls {
		if c.ToolCallID == "old" {
			oldCall = c
		} else {
			newCall = c
		}
	}
	if oldCall.Arguments != purgedPlaceholder || oldCall.Result != purgedPlaceholder {
		t.Fatalf("text past cutoff should be purged: %+v", oldCall)
	}
	if oldCall.ToolName != "nmap" {
		t.Fatalf("metadata must survive a retention sweep: %+v", oldCall)
	}
	if newCall.Arguments != "new args" || newCall.Result != "new result" {
		t.Fatalf("text before cutoff must be untouched: %+v", newCall)
	}
}
