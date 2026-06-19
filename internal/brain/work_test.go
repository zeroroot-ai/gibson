package brain

import (
	"reflect"
	"testing"
)

// TestWork_AsyncLifecycle proves work is tracked as an entity through an async
// lifecycle: dispatch (running) → completion (done/failed) whenever it arrives,
// with no duration tracking. A "slow" completion many events later is the same
// path as a fast one. Replay reproduces the lifecycle.
func TestWork_AsyncLifecycle(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(WorkDispatched{ID: "w1", ItemKind: "tool", Target: "nmap"})
	apply(WorkDispatched{ID: "w2", ItemKind: "agent", Target: "exploit-jenkins"})
	// w2 completes first (fast); w1 is still running (slow) — order is irrelevant.
	apply(WorkCompleted{ID: "w2", Result: "shell"})

	want := []WorkSnapshot{
		{ID: "w1", Kind: "tool", Target: "nmap", State: WorkRunning},
		{ID: "w2", Kind: "agent", Target: "exploit-jenkins", State: WorkDone, Result: "shell"},
	}
	if got := w.WorkSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("work snapshot:\n got %+v\nwant %+v", got, want)
	}

	// w1 completes much later (still the same path) — and as a failure.
	apply(WorkCompleted{ID: "w1", Err: "host unreachable"})
	if got := w.WorkSnapshot()[0]; got.State != WorkFailed || got.Err != "host unreachable" {
		t.Fatalf("w1 = %+v, want failed/unreachable", got)
	}

	if replayed := Replay("t", tl); !reflect.DeepEqual(replayed.WorkSnapshot(), w.WorkSnapshot()) {
		t.Fatalf("replay diverged:\n got %+v\nwant %+v", replayed.WorkSnapshot(), w.WorkSnapshot())
	}
}

// TestWork_CompletionForUnknownIgnored: a completion for work we never dispatched
// is ignored (out-of-order / duplicate safety), not a crash or phantom entity.
func TestWork_CompletionForUnknownIgnored(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, WorkCompleted{ID: "ghost", Result: "x"})
	if got := len(w.WorkSnapshot()); got != 0 {
		t.Fatalf("got %d work items, want 0", got)
	}
}
