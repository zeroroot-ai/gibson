package brain

import "testing"

// RewindTo makes frame N the live state: Timeline truncated to N, World re-folded.
func TestRewindTo_TruncatesAndReplays(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.AddSystem(fakeDispatcher(nil))
	e.AddSystem(MissionCompletionSystem)

	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "a", Kind: "tool", Target: "t"},
		{ID: "b", Kind: "tool", Target: "t", DependsOn: []string{"a"}},
	}})
	e.Tick() // runs to completion

	full := e.Timeline.Len()
	if full == 0 {
		t.Fatal("expected a non-empty timeline")
	}
	// Capture the frame after the first event (just the projection).
	want := e.FrameAt(1).MissionSnapshot()

	e.RewindTo(1)

	if e.Timeline.Len() != 1 {
		t.Fatalf("timeline should be truncated to 1, got %d", e.Timeline.Len())
	}
	got := e.World.MissionSnapshot()
	if len(got) != len(want) || len(got) != 1 {
		t.Fatalf("rewound world mission count: got %d want %d", len(got), len(want))
	}
	if got[0].Status != MissionRunning {
		t.Errorf("after rewind to frame 1 the mission should be running again, got %s", got[0].Status)
	}
	// Frame 1 is just the projection event, so the work is back to pending (the
	// projection creates the mission + its pending nodes; later dispatch/complete
	// events were truncated).
	for _, wi := range e.World.WorkSnapshot() {
		if wi.State != WorkPending {
			t.Errorf("rewound work %s should be pending, got %s", wi.ID, wi.State)
		}
	}
}

func TestRewindTo_ClampsAndReplaysForward(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.AddSystem(fakeDispatcher(nil))
	e.AddSystem(MissionCompletionSystem)
	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "a", Kind: "tool", Target: "t"}}})
	e.Tick()
	done := e.Timeline.Len()

	// Rewind past the end clamps to len (no-op state); rewind to 0 clears everything.
	e.RewindTo(done + 100)
	if e.Timeline.Len() != done {
		t.Errorf("rewind past end should clamp, got %d want %d", e.Timeline.Len(), done)
	}
	e.RewindTo(0)
	if e.Timeline.Len() != 0 || len(e.World.MissionSnapshot()) != 0 {
		t.Errorf("rewind to 0 should empty the world")
	}

	// Re-running forward works after rewind: resubmit + tick completes again.
	e.Submit(MissionProjected{ID: "m2", Nodes: []WorkNode{{ID: "x", Kind: "tool", Target: "t"}}})
	e.Tick()
	ms := e.Missions()
	if len(ms) != 1 || ms[0].ID != "m2" || ms[0].Status != MissionCompleted {
		t.Fatalf("forward replay after rewind failed: %+v", ms)
	}
}
