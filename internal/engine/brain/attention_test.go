package brain

import (
	"reflect"
	"testing"
)

// TestAttention_SurpriseBoost: a surprised (contradiction) host gets the same
// belief as its non-surprised twin but a higher attention — the surprise input
// boosts it (ADR-0005/0006: attention = belief field + surprise).
func TestAttention_SurpriseBoost(t *testing.T) {
	e := NewEngine("t")
	e.AddSystem(BeliefSystem(PlaceholderBeliefProvider()))

	// Same coordinate, different strong signals -> a contradiction -> the newcomer
	// carries a Surprise. Same ports -> identical belief.
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", SSHHostKey: "KEY-A", OpenPorts: []int{22}})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", SSHHostKey: "KEY-B", OpenPorts: []int{22}})
	e.Tick()

	snap := e.World.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("want 2 hosts (contradiction), got %d: %+v", len(snap), snap)
	}
	var surprised, normal HostSnapshot
	for _, h := range snap {
		if h.Surprise != "" {
			surprised = h
		} else {
			normal = h
		}
	}
	if surprised.Surprise == "" {
		t.Fatalf("expected one surprised host: %+v", snap)
	}
	if surprised.Belief.Juicy != normal.Belief.Juicy {
		t.Fatalf("twins should have equal belief: %v vs %v", surprised.Belief.Juicy, normal.Belief.Juicy)
	}
	if surprised.Attention != normal.Attention+surpriseBoost {
		t.Fatalf("surprised attention=%v, want normal(%v)+boost(%v)", surprised.Attention, normal.Attention, surpriseBoost)
	}
	if surprised.Attention != surprised.Belief.Juicy+surpriseBoost {
		t.Fatalf("attention=%v, want juicy(%v)+boost", surprised.Attention, surprised.Belief.Juicy)
	}
}

// TestFinding_RaisedAndReplay: a surprise that is investigated/confirmed is
// promoted to a Finding (idempotent by ID); replay reproduces it.
func TestFinding_RaisedAndReplay(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(FindingRaised{ID: "f1", Title: "exposed jenkins", ScopeID: "s", Address: "10.0.0.5", Severity: "high"})
	apply(FindingRaised{ID: "f1", Title: "dup ignored", ScopeID: "s", Address: "10.0.0.5", Severity: "low"})

	want := []FindingSnapshot{{ID: "f1", Title: "exposed jenkins", ScopeID: "s", Address: "10.0.0.5", Severity: "high"}}
	if got := w.FindingSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("findings:\n got %+v\nwant %+v", got, want)
	}
	if r := Replay("t", tl); !reflect.DeepEqual(r.FindingSnapshot(), want) {
		t.Fatalf("replay diverged: %+v", r.FindingSnapshot())
	}
}
