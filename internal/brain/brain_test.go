package brain

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestWorld_FoldAndReplay proves the core invariant: World == fold(Timeline).
// It also exercises update-on-match for a repeated identity and scope
// disambiguation (same address, different scope = distinct entities).
func TestWorld_FoldAndReplay(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("tenant-1")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(HostObserved{ScopeID: "scope-a", Address: "10.0.0.5", Ports: []int{22, 80}})
	apply(HostObserved{ScopeID: "scope-a", Address: "10.0.0.5", Ports: []int{22, 443}}) // same host: ports change (volatile)
	apply(HostObserved{ScopeID: "scope-b", Address: "10.0.0.5", Ports: []int{22}})       // same IP, different scope: distinct

	want := []HostSnapshot{
		{ScopeID: "scope-a", Address: "10.0.0.5", Ports: []int{22, 443}},
		{ScopeID: "scope-b", Address: "10.0.0.5", Ports: []int{22}},
	}
	got := w.Snapshot()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("world snapshot:\n got %+v\nwant %+v", got, want)
	}
	if tl.Len() != 3 {
		t.Fatalf("timeline len = %d, want 3", tl.Len())
	}

	// Replay reproduces the World exactly from the Timeline alone.
	replayed := Replay("tenant-1", tl)
	if !reflect.DeepEqual(replayed.Snapshot(), got) {
		t.Fatalf("replay diverged:\n got %+v\nwant %+v", replayed.Snapshot(), got)
	}
}

// TestEngine_TickAppliesAndFolds proves the clock-tick loop drains the intake
// queue into the Timeline and folds it into the World (sweep-to-quiescence).
func TestEngine_TickAppliesAndFolds(t *testing.T) {
	e := NewEngine("tenant-1")
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.1", Ports: []int{22}})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.2", Ports: []int{443}})

	if n := e.Tick(); n != 2 {
		t.Fatalf("tick applied %d events, want 2", n)
	}
	if got := len(e.World.Snapshot()); got != 2 {
		t.Fatalf("world has %d hosts, want 2", got)
	}
	if e.Timeline.Len() != 2 {
		t.Fatalf("timeline len = %d, want 2", e.Timeline.Len())
	}
}

// TestEngine_RunDrainsAndStops proves Run applies submitted events on its ticker
// and performs a final drain on cancellation.
func TestEngine_RunDrainsAndStops(t *testing.T) {
	e := NewEngine("tenant-1")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.Run(ctx); close(done) }()

	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.9", Ports: []int{22}})
	time.Sleep(3 * TickInterval) // let at least one tick apply it
	cancel()
	<-done // Run returns after its final drain; safe to read the World now

	if got := len(e.World.Snapshot()); got != 1 {
		t.Fatalf("world has %d hosts, want 1", got)
	}
}
