package brain

import (
	"sort"
	"testing"
)

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

// The rich frame (PRD #1059 M2, gibson#1061) surfaces a mission's in-flight Work
// reconstructed as-of the scrubbed tick: a WorkItem appears at its dispatch tick
// (status "running" = in-flight) and leaves the in-flight set at its completion
// tick (status "done"/"failed"). The fold is mission-scoped, so no other mission's
// work bleeds in. This asserts the in-flight set at seq 0 / mid / total.
func TestMissionFrameAt_InFlightWork(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(MissionStarted{ID: "A", Goal: "ga"})                                           // A slice idx 0
	e.Submit(WorkDispatched{ID: "wa1", MissionID: "A", ItemKind: "tool", Target: "nmap"})   // idx 1: wa1 running
	e.Submit(WorkDispatched{ID: "wa2", MissionID: "A", ItemKind: "agent", Target: "recon"}) // idx 2: wa2 running
	e.Submit(WorkDispatched{ID: "wb1", MissionID: "B", ItemKind: "tool", Target: "nmap"})   // mission B (excluded)
	e.Submit(WorkCompleted{ID: "wa1", Result: "ok"})                                        // idx 3: wa1 done
	e.Tick()

	// The mission-scoped slice for A is its 4 events (B's dispatch excluded).
	slice := e.MissionEvents("A")
	if len(slice) != 4 {
		t.Fatalf("mission A slice = %d events, want 4 (%v)", len(slice), slice)
	}

	// inflight returns the ids of WorkItems still running in the folded frame.
	inflight := func(w *World) []string {
		var ids []string
		for _, wi := range w.WorkSnapshot() {
			if wi.State == WorkRunning {
				ids = append(ids, wi.ID)
			}
		}
		sort.Strings(ids)
		return ids
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// seq 0: nothing dispatched yet — no work at all.
	if wk := e.MissionFrameAt("A", 0).WorkSnapshot(); len(wk) != 0 {
		t.Fatalf("frame@0 work = %+v, want none", wk)
	}

	// seq 2 folds the first 2 events (MissionStarted + wa1 dispatch): only wa1 in flight.
	if got := inflight(e.MissionFrameAt("A", 2)); !eq(got, []string{"wa1"}) {
		t.Fatalf("frame@2 in-flight = %v, want [wa1]", got)
	}

	// seq 3 folds wa2's dispatch too: both wa1 and wa2 in flight.
	if got := inflight(e.MissionFrameAt("A", 3)); !eq(got, []string{"wa1", "wa2"}) {
		t.Fatalf("frame@3 in-flight = %v, want [wa1 wa2]", got)
	}

	// seq 4 (total): wa1 completed (idx 3) — it clears the in-flight set; wa2 stays.
	end := e.MissionFrameAt("A", 4)
	if got := inflight(end); !eq(got, []string{"wa2"}) {
		t.Fatalf("frame@end in-flight = %v, want [wa2] (wa1 should have cleared)", got)
	}
	// wa1 is still carried with its terminal status; mission B's work never appears.
	for _, wi := range end.WorkSnapshot() {
		if wi.ID == "wb1" {
			t.Fatal("mission B work bled into mission A frame")
		}
		if wi.ID == "wa1" && wi.State != WorkDone {
			t.Fatalf("wa1 status = %q, want done", wi.State)
		}
	}
}

// The rich frame (PRD #1059 M2, gibson#1062) surfaces a mission's Decider decisions
// reconstructed as-of the scrubbed tick: a decision appears at its DecisionRequested
// tick (status "pending" = in flight), gains the work it chose to dispatch, and
// reaches "completed" at its DecisionCompleted tick — carrying the completion reason
// as rationale where the decision ended the mission. The fold is mission-scoped, so
// another mission's decisions never bleed in. This asserts the decision set at seq
// 0 / mid / total.
func TestMissionFrameAt_Decisions(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(MissionStarted{ID: "A", Goal: "ga"})                                         // A idx 0
	e.Submit(DecisionRequested{MissionID: "A", Cursor: 0})                                // A idx 1: open A#d1
	e.Submit(WorkDispatched{ID: "wa1", MissionID: "A", ItemKind: "tool", Target: "nmap"}) // A idx 2: A#d1 chose wa1
	e.Submit(DecisionCompleted{MissionID: "A"})                                           // A idx 3: A#d1 completed
	e.Submit(DecisionRequested{MissionID: "A", Cursor: 1})                                // A idx 4: open A#d2
	e.Submit(MissionDone{ID: "A", Outcome: MissionCompleted, Reason: "goal resolved"})    // A idx 5: A#d2 rationale
	e.Submit(DecisionCompleted{MissionID: "A"})                                           // A idx 6: A#d2 completed
	// mission B — a separate decision that must never bleed into A's slice.
	e.Submit(DecisionRequested{MissionID: "B", Cursor: 0})
	e.Submit(WorkDispatched{ID: "wb1", MissionID: "B", ItemKind: "tool", Target: "nmap"})
	e.Tick()

	// A's slice is its 7 events (B's decision + dispatch excluded).
	slice := e.MissionEvents("A")
	if len(slice) != 7 {
		t.Fatalf("mission A slice = %d events, want 7 (%v)", len(slice), slice)
	}

	ids := func(w *World) []string {
		var out []string
		for _, d := range w.DecisionSnapshot() {
			out = append(out, d.ID+"/"+d.Status)
		}
		sort.Strings(out)
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// seq 0: no decision requested yet.
	if d := e.MissionFrameAt("A", 0).DecisionSnapshot(); len(d) != 0 {
		t.Fatalf("frame@0 decisions = %+v, want none", d)
	}

	// seq 2 folds MissionStarted + the first DecisionRequested: A#d1 pending, no
	// dispatch yet (wa1 is idx 2, not folded).
	f2 := e.MissionFrameAt("A", 2)
	if got := ids(f2); !eq(got, []string{"A#d1/pending"}) {
		t.Fatalf("frame@2 decisions = %v, want [A#d1/pending]", got)
	}
	if d := f2.DecisionSnapshot(); len(d[0].Dispatches) != 0 {
		t.Fatalf("frame@2 A#d1 dispatches = %+v, want none", d[0].Dispatches)
	}

	// seq 3 folds wa1's dispatch: A#d1 still pending but now carries the chosen work.
	f3 := e.MissionFrameAt("A", 3).DecisionSnapshot()
	if len(f3) != 1 || len(f3[0].Dispatches) != 1 || f3[0].Dispatches[0].WorkID != "wa1" {
		t.Fatalf("frame@3 A#d1 = %+v, want one dispatch of wa1", f3)
	}

	// seq 4 folds DecisionCompleted: A#d1 completed.
	if got := ids(e.MissionFrameAt("A", 4)); !eq(got, []string{"A#d1/completed"}) {
		t.Fatalf("frame@4 decisions = %v, want [A#d1/completed]", got)
	}

	// seq total (7): both decisions present; A#d2 completed and carries the mission
	// completion as its rationale; mission B's decision never appears.
	end := e.MissionFrameAt("A", 7).DecisionSnapshot()
	if got := ids(e.MissionFrameAt("A", 7)); !eq(got, []string{"A#d1/completed", "A#d2/completed"}) {
		t.Fatalf("frame@end decisions = %v, want [A#d1/completed A#d2/completed]", got)
	}
	for _, d := range end {
		if d.MissionID == "B" {
			t.Fatal("mission B decision bled into mission A frame")
		}
		if d.ID == "A#d2" {
			if d.Outcome != string(MissionCompleted) {
				t.Fatalf("A#d2 outcome = %q, want %q", d.Outcome, MissionCompleted)
			}
			if d.Rationale != "goal resolved" {
				t.Fatalf("A#d2 rationale = %q, want %q", d.Rationale, "goal resolved")
			}
		}
	}
}

// The rich frame (PRD #1059 M2, gibson#1063) surfaces a mission's LLM calls
// reconstructed as-of the scrubbed tick. An LLM-call observation carries no
// mission id but does carry the run_id of the AgentRun (a WorkItem) that issued
// it, so it is attributed to the mission via the run_id→WorkItem→mission linkage;
// a mission-level call (empty run_id) attaches to the mission directly. A call
// appears at its own observation tick and the set folds in cumulatively, and a
// call whose run_id names another mission's work never bleeds in. This asserts the
// folded call set at seq 0 / mid / total.
func TestMissionFrameAt_LlmCalls(t *testing.T) {
	e := NewEngine("t1")
	e.Submit(MissionStarted{ID: "A", Goal: "ga"})                                                             // A idx 0
	e.Submit(WorkDispatched{ID: "wa1", MissionID: "A", ItemKind: "agent", Target: "recon"})                   // A idx 1: A owns wa1
	e.Submit(LlmCallObserved{CallID: "ca1", RunID: "wa1", Model: "m", PromptTokens: 10, CompletionTokens: 5}) // A idx 2: run-linked
	e.Submit(LlmCallObserved{CallID: "cam", RunID: "", Model: "m", PromptTokens: 3, CompletionTokens: 1})     // A idx 3: mission-level
	// mission B — its work + the call that work issued must never bleed into A.
	e.Submit(WorkDispatched{ID: "wb1", MissionID: "B", ItemKind: "agent", Target: "recon"})
	e.Submit(LlmCallObserved{CallID: "cb1", RunID: "wb1", Model: "m", PromptTokens: 7, CompletionTokens: 2})
	e.Tick()

	// A's slice is its 4 events: the mission start, wa1's dispatch, the run-linked
	// call (run_id wa1), and the mission-level call (empty run_id). B's dispatch and
	// B's call (run_id wb1) are excluded.
	slice := e.MissionEvents("A")
	if len(slice) != 4 {
		t.Fatalf("mission A slice = %d events, want 4 (%v)", len(slice), slice)
	}

	calls := func(w *World) []string {
		var out []string
		for _, c := range w.LlmCallSnapshot() {
			out = append(out, c.CallID)
		}
		sort.Strings(out)
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	// seq 0: nothing folded — no calls.
	if c := e.MissionFrameAt("A", 0).LlmCallSnapshot(); len(c) != 0 {
		t.Fatalf("frame@0 calls = %+v, want none", c)
	}

	// seq 2 folds MissionStarted + wa1 dispatch — the call (idx 2) is not folded yet.
	if got := calls(e.MissionFrameAt("A", 2)); !eq(got, nil) {
		t.Fatalf("frame@2 calls = %v, want none", got)
	}

	// seq 3 folds the run-linked call: ca1 appears at its tick.
	if got := calls(e.MissionFrameAt("A", 3)); !eq(got, []string{"ca1"}) {
		t.Fatalf("frame@3 calls = %v, want [ca1]", got)
	}

	// seq total (4): both A's calls present; B's call (run_id wb1) never appears.
	end := e.MissionFrameAt("A", 4)
	if got := calls(end); !eq(got, []string{"ca1", "cam"}) {
		t.Fatalf("frame@end calls = %v, want [ca1 cam]", got)
	}
	for _, c := range end.LlmCallSnapshot() {
		if c.CallID == "cb1" {
			t.Fatal("mission B LLM call bled into mission A frame")
		}
		if c.CallID == "ca1" && c.TotalTokens() != 15 {
			t.Fatalf("ca1 total tokens = %d, want 15", c.TotalTokens())
		}
	}
}
