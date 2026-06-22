package brain

import (
	"reflect"
	"testing"
)

// TestBelief_ScoredQuiescentReplay proves the belief field is computed by a
// BeliefProvider as an engine System, recorded on the host, quiescent once
// current, and reproduced by replay.
func TestBelief_ScoredQuiescentReplay(t *testing.T) {
	e := NewEngine("t")
	e.AddSystem(BeliefSystem(PlaceholderBeliefProvider()))

	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80, 443}})
	e.Tick() // sense host -> belief system scores it (then quiescent)

	snap := e.World.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("got %d hosts, want 1", len(snap))
	}
	// placeholder: 3 open ports -> exploitable 3/4, reachable 1, juicy 0.75
	want := Belief{Juicy: 0.75, Exploitable: 0.75, Reachable: 1.0, Model: "placeholder-v0"}
	if snap[0].Belief != want {
		t.Fatalf("belief = %+v, want %+v", snap[0].Belief, want)
	}

	// Quiescent: re-scoring yields the same belief, so no event.
	if n := e.Tick(); n != 0 {
		t.Fatalf("extra tick applied %d events, want 0 (belief not quiescent)", n)
	}

	// Replay reproduces belief (BeliefScored was logged).
	if r := Replay("t", e.Timeline); !reflect.DeepEqual(r.Snapshot(), e.World.Snapshot()) {
		t.Fatalf("replay diverged:\n got %+v\nwant %+v", r.Snapshot(), e.World.Snapshot())
	}
}

// TestBelief_TracksEvidence: as evidence changes (a new open port), belief is
// recomputed (higher exploitability).
func TestBelief_TracksEvidence(t *testing.T) {
	e := NewEngine("t")
	e.AddSystem(BeliefSystem(PlaceholderBeliefProvider()))

	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22}})
	e.Tick()
	first := e.World.Snapshot()[0].Belief.Exploitable // 1/2 = 0.5

	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5", OpenPorts: []int{22, 80}})
	e.Tick()
	second := e.World.Snapshot()[0].Belief.Exploitable // 2/3 ≈ 0.667

	if !(second > first) {
		t.Fatalf("exploitability did not rise with evidence: %v -> %v", first, second)
	}
}
