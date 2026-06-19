package brain

import (
	"reflect"
	"testing"
)

// stubDecider is a deterministic placeholder for the (later) LLM Decider. It is
// quiescent: dispatch one scan for a running mission with no work, complete the
// mission once all work is done, otherwise do nothing.
type stubDecider struct{}

func (stubDecider) Decide(w *World) []Decision {
	ms := w.MissionSnapshot()
	var mission *MissionSnapshot
	for i := range ms {
		if ms[i].Status == MissionRunning {
			mission = &ms[i]
			break
		}
	}
	if mission == nil {
		return nil
	}
	work := w.WorkSnapshot()
	if len(work) == 0 {
		return []Decision{{Action: DecideDispatch, WorkID: "w1", WorkKind: "tool", WorkTarget: "nmap"}}
	}
	for _, wi := range work {
		if wi.State != WorkDone && wi.State != WorkFailed {
			return nil // work still running — wait
		}
	}
	return []Decision{{Action: DecideComplete, MissionID: mission.ID, Reason: "work complete"}}
}

// TestOrchestrator_Loop drives the full loop: a mission launch leads the
// Orchestrator (a System over the World) to dispatch work; when the work
// completes, it completes the mission. Sweep-to-quiescence settles each tick, and
// the loop is driven by a pluggable Decider (the LLM lands here later).
func TestOrchestrator_Loop(t *testing.T) {
	e := NewEngine("t")
	e.AddSystem(Orchestrator{Decider: stubDecider{}}.System())

	e.Submit(MissionStarted{ID: "m1", Goal: "exfiltrate PII"})
	e.Tick() // start -> dispatch w1 -> work running (then quiescent)

	if ms := e.World.MissionSnapshot(); len(ms) != 1 || ms[0].Status != MissionRunning {
		t.Fatalf("after start: missions = %+v, want one running", e.World.MissionSnapshot())
	}
	if ws := e.World.WorkSnapshot(); len(ws) != 1 || ws[0].State != WorkRunning {
		t.Fatalf("after start: work = %+v, want one running", e.World.WorkSnapshot())
	}

	e.Submit(WorkCompleted{ID: "w1", Result: "done"})
	e.Tick() // work done -> orchestrator completes the mission

	want := []MissionSnapshot{{ID: "m1", Goal: "exfiltrate PII", Status: MissionCompleted, Reason: "work complete"}}
	if got := e.World.MissionSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("after completion:\n got %+v\nwant %+v", got, want)
	}

	// Quiescent: nothing left to do, a further tick applies no events.
	if n := e.Tick(); n != 0 {
		t.Fatalf("extra tick applied %d events, want 0 (not quiescent)", n)
	}

	// Replay reproduces mission + work state from the Timeline (which captured the
	// orchestrator-emitted events too).
	replayed := Replay("t", e.Timeline)
	if !reflect.DeepEqual(replayed.MissionSnapshot(), e.World.MissionSnapshot()) ||
		!reflect.DeepEqual(replayed.WorkSnapshot(), e.World.WorkSnapshot()) {
		t.Fatalf("replay diverged")
	}
}
