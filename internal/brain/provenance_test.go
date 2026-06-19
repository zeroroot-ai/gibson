package brain

import (
	"reflect"
	"testing"
)

// TestAgentRun_FoldDedupEnrichReplay proves agent runs fold idempotently by RunID,
// the parent link + agent name enrich progressively (learned later, never clobbered),
// and the World survives replay (ADR-0007 run-provenance).
func TestAgentRun_FoldDedupEnrichReplay(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	// Child observed before its parent link/name are known, then enriched.
	apply(AgentRunObserved{RunID: "child", ScopeID: "m1"})
	apply(AgentRunObserved{RunID: "child", ParentRunID: "parent", AgentName: "recon", ScopeID: "m1"})
	// Duplicate of the parent run: no new entity, no clobber.
	apply(AgentRunObserved{RunID: "parent", AgentName: "orchestrator", ScopeID: "m1"})
	apply(AgentRunObserved{RunID: "parent", AgentName: "orchestrator", ScopeID: "m1"})
	// Empty RunID is ignored.
	apply(AgentRunObserved{RunID: "", AgentName: "noop"})

	got := w.AgentRunSnapshot()
	want := []AgentRunSnapshot{
		{RunID: "child", ParentRunID: "parent", AgentName: "recon", ScopeID: "m1"},
		{RunID: "parent", ParentRunID: "", AgentName: "orchestrator", ScopeID: "m1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("agent runs:\n got %+v\nwant %+v", got, want)
	}

	// Replay reproduces the same World.
	if replayed := Replay("t", tl).AgentRunSnapshot(); !reflect.DeepEqual(replayed, want) {
		t.Fatalf("replay mismatch:\n got %+v\nwant %+v", replayed, want)
	}
}
