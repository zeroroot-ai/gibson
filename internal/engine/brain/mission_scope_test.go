package brain

import "testing"

// MissionSlice is the pure events→mission-slice attribution that the mission-scoped
// fold is built on (gibson#1060). It must attribute work-id-only events (completion)
// to the owning mission, keep two missions isolated, and treat tenant-ambient
// observations as belonging to no mission.
func TestMissionSlice_AttributesAndIsolates(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(MissionStarted{ID: "A", Goal: "ga"})
	e.Submit(MissionStarted{ID: "B", Goal: "gb"})
	e.Submit(WorkDispatched{ID: "wa1", MissionID: "A", ItemKind: "tool", Target: "t"})
	e.Submit(WorkDispatched{ID: "wb1", MissionID: "B", ItemKind: "tool", Target: "t"})
	e.Submit(HostObserved{ScopeID: "s", Address: "10.0.0.5"}) // tenant-ambient
	e.Submit(WorkCompleted{ID: "wa1", Result: "ok"})          // names only a work id
	e.Submit(WorkCompleted{ID: "wb1", Result: "ok"})
	e.Tick()

	all := e.Events()
	if len(all) != 7 {
		t.Fatalf("timeline = %d events, want 7", len(all))
	}

	// Mission A's slice: started + dispatched + completed — exactly 3. The
	// completion is attributed via the work id A owns; B's events and the ambient
	// host are excluded.
	a := MissionSlice(all, "A")
	if len(a) != 3 {
		t.Fatalf("mission A slice = %d events, want 3 (%v)", len(a), a)
	}
	for _, ev := range a {
		if _, ok := ev.(HostObserved); ok {
			t.Fatal("ambient observation bled into mission A slice")
		}
		if d, ok := ev.(WorkDispatched); ok && d.MissionID != "A" {
			t.Fatalf("mission B work bled into A slice: %+v", d)
		}
	}

	// An empty mission id returns the whole Timeline (tenant-wide, unchanged).
	if len(MissionSlice(all, "")) != 7 {
		t.Fatal("empty mission id should return the whole timeline")
	}

	// MissionFrameAt folds only the mission's slice.
	wA := e.MissionFrameAt("A", 99)
	if ms := wA.MissionSnapshot(); len(ms) != 1 || ms[0].ID != "A" {
		t.Fatalf("mission A frame missions = %+v, want [A]", ms)
	}
	if h := wA.Snapshot(); len(h) != 0 {
		t.Fatalf("mission A frame hosts = %d, want 0 (ambient excluded)", len(h))
	}
	if wk := wA.WorkSnapshot(); len(wk) != 1 || wk[0].ID != "wa1" || wk[0].State != WorkDone {
		t.Fatalf("mission A frame work = %+v, want [wa1 done]", wk)
	}

	// Clamping: seq 0 folds nothing.
	if ms := e.MissionFrameAt("A", 0).MissionSnapshot(); len(ms) != 0 {
		t.Fatalf("mission A frame@0 = %+v, want empty", ms)
	}
}
