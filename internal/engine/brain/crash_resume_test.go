package brain

import (
	"context"
	"testing"
)

// crashAndResume simulates a daemon crash + restart for a World that has
// in-flight work: it calls ResumeFailInFlight (the reconciliation step from
// engine.go Hydrate) and returns the resulting failure events.
func crashAndResume(w *World) []Event {
	return ResumeFailInFlight(w)
}

// TestCrashResume_RetryPolicyReDispatches proves that crash-failed work with a
// non-zero RetryPolicy is re-dispatched by RetrySystem on the next tick —
// bounded by MaxRetries (ADR-0011 decision 5: "re-dispatch iff RetryPolicy
// allows").
func TestCrashResume_RetryPolicyReDispatches(t *testing.T) {
	// Build a World with one running tool (MaxRetries=2).
	w := NewWorld("t1")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "scan", Kind: "tool", Target: "nmap", MaxRetries: 2},
	}})
	Reduce(w, WorkDispatched{ID: "scan", MissionID: "m1", ItemKind: "tool", Target: "nmap"})

	if w.WorkSnapshot()[0].State != WorkRunning {
		t.Fatalf("pre-condition: scan should be running")
	}

	// Simulate crash: ResumeFailInFlight marks it failed.
	failEvs := crashAndResume(w)
	if len(failEvs) != 1 {
		t.Fatalf("want 1 fail event, got %d", len(failEvs))
	}
	Reduce(w, failEvs[0])

	if s := w.WorkSnapshot()[0].State; s != WorkFailed {
		t.Fatalf("after crash, scan should be WorkFailed; got %s", s)
	}

	// RetrySystem must re-arm it (Attempts=1 ≤ MaxRetries=2).
	retryEvs := RetrySystem(w)
	if len(retryEvs) != 1 {
		t.Fatalf("RetrySystem: want 1 WorkRetried event, got %d", len(retryEvs))
	}
	if _, ok := retryEvs[0].(WorkRetried); !ok {
		t.Fatalf("RetrySystem: want WorkRetried, got %T", retryEvs[0])
	}
	Reduce(w, retryEvs[0])

	if s := w.WorkSnapshot()[0].State; s != WorkPending {
		t.Fatalf("after WorkRetried, scan should be WorkPending; got %s", s)
	}
}

// TestCrashResume_NoRetryPolicyStaysFailed proves that a crash-failed work
// item with MaxRetries=0 (no CUE RetryPolicy) is NOT re-dispatched — no blind
// auto-re-dispatch (ADR-0011 decision 5).
func TestCrashResume_NoRetryPolicyStaysFailed(t *testing.T) {
	// A tool node with no RetryPolicy (MaxRetries=0, the default).
	w := NewWorld("t1")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "exploit", Kind: "tool", Target: "exploit-rce", MaxRetries: 0},
	}})
	Reduce(w, WorkDispatched{ID: "exploit", MissionID: "m1", ItemKind: "tool", Target: "exploit-rce"})

	// Crash.
	for _, ev := range crashAndResume(w) {
		Reduce(w, ev)
	}

	if s := w.WorkSnapshot()[0].State; s != WorkFailed {
		t.Fatalf("crash-failed work with no policy: want WorkFailed, got %s", s)
	}

	// RetrySystem must NOT emit a WorkRetried event — Attempts(1) > MaxRetries(0).
	retryEvs := RetrySystem(w)
	if len(retryEvs) != 0 {
		t.Fatalf("no blind re-dispatch: RetrySystem must not fire for MaxRetries=0, got %v", retryEvs)
	}

	// State remains WorkFailed — no corruption.
	if s := w.WorkSnapshot()[0].State; s != WorkFailed {
		t.Fatalf("after RetrySystem: want still WorkFailed, got %s", s)
	}
}

// TestCrashResume_RetryBoundedByMaxRetries proves that RetrySystem respects the
// MaxRetries ceiling end-to-end: a node that always fails exhausts its retries
// and stays failed (not re-armed indefinitely).
func TestCrashResume_RetryBoundedByMaxRetries(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.AddSystem(fakeDispatcher(map[string]bool{"scan": true})) // always fails
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)

	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "scan", Kind: "tool", Target: "nmap", MaxRetries: 1},
	}})
	// Crash mid-first-dispatch: inject a failure as if the daemon restarted.
	e.Submit(WorkCompleted{ID: "scan", Err: "interrupted: daemon restarted mid-flight"})
	e.Tick() // drain: crash-fail + RetrySystem re-arms (Attempts=1 ≤ MaxRetries=1)
	// The fakeDispatcher will complete scan on the second attempt as a failure
	// (always-fail), so RetrySystem would need Attempts ≤ MaxRetries again, but
	// now Attempts=2 > MaxRetries=1, so it stays failed.

	var scan WorkSnapshot
	for _, wi := range e.Work() {
		if wi.ID == "scan" {
			scan = wi
		}
	}
	if scan.State != WorkFailed {
		t.Fatalf("scan: want WorkFailed after exhausting retries, got %s", scan.State)
	}
	if scan.Attempts != 2 {
		t.Errorf("scan: want 2 attempts (crash-fail + 1 retry), got %d", scan.Attempts)
	}
	ms := e.Missions()
	if len(ms) != 1 || ms[0].Status != MissionFailed {
		t.Fatalf("mission: want MissionFailed after retry exhausted, got %+v", ms)
	}
}

// TestCrashResume_GoalMissionDeciderReEngages proves that after a crash-fail,
// a goal mission's Decider re-engages with judgment on the re-folded World
// (ADR-0011 decision 5: "the Decider re-engages with judgment on the
// re-folded World rather than a blind re-dispatch").
//
// Mechanism: a WorkFailed counts in terminalWorkCount → the evidence cursor
// advances → DeciderGateSystem fires a new DecisionRequested.
func TestCrashResume_GoalMissionDeciderReEngages(t *testing.T) {
	deciderCallCount := 0
	llm := llmFunc(func(_ context.Context, mc MissionContext) (DeciderOutput, error) {
		deciderCallCount++
		// First call: dispatch a tool.
		if deciderCallCount == 1 {
			return DeciderOutput{Dispatches: []DeciderDispatch{
				{Kind: "tool", Target: "nmap", Input: `{"target":"10.0.0.1"}`},
			}}, nil
		}
		// Second call: close the mission after seeing the re-folded World.
		return DeciderOutput{Complete: &DeciderComplete{Outcome: "failed", Reason: "tool crashed; giving up"}}, nil
	})

	e := NewEngine("t1")
	dw := NewDeciderWorker(e, llm, func() []Capability {
		return []Capability{
			{Kind: "tool", Name: "nmap", InputSchema: `{"type":"object"}`},
		}
	})
	e.AddSystem(SchedulerSystem)
	e.AddSystem(DeciderGateSystem)
	// No automatic dispatcher — the Decider dispatches manually.
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)
	e.Subscribe(dw.Tap)

	e.Submit(MissionProjected{ID: "m1", Goal: "scan network"})
	// Round 1: gate fires → worker dispatches nmap.
	e.Tick()
	dw.Drain(context.Background())
	e.Tick() // apply dispatched events

	// Confirm nmap was dispatched and is now running.
	var nmapID string
	for _, wi := range e.Work() {
		if wi.Target == "nmap" && wi.State == WorkRunning {
			nmapID = wi.ID
		}
	}
	if nmapID == "" {
		t.Fatalf("nmap should be running after first Decider round; work=%+v", e.Work())
	}

	// Simulate a crash: inject crash-failure for the running nmap work.
	e.Submit(WorkCompleted{ID: nmapID, Err: "interrupted: daemon restarted mid-flight"})
	e.Tick() // apply crash-fail; gate should see new terminal evidence → DecisionRequested

	// Drain the second Decider invocation (it sees the crash-failed tool).
	dw.Drain(context.Background())
	e.Tick() // apply the mission-done event the Decider submitted

	if deciderCallCount < 2 {
		t.Errorf("Decider must re-engage after crash-fail; got %d calls, want ≥2", deciderCallCount)
	}
	if got := missionStatus(e, "m1"); got != MissionFailed {
		t.Errorf("mission: want MissionFailed (Decider gave up), got %s", got)
	}
}

// TestCrashResume_LateWorkCompletedIsIdempotent proves that a WorkCompleted
// arriving from a worker that outlived the daemon, for a work item already in
// a terminal state (WorkFailed via ResumeFailInFlight), is a no-op — no
// corruption, no state flip (ADR-0011 decision 5).
func TestCrashResume_LateWorkCompletedIsIdempotent(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, WorkDispatched{ID: "slow-tool", MissionID: "m1", ItemKind: "tool", Target: "slow"})

	// Crash: mark it failed (as ResumeFailInFlight does).
	Reduce(w, WorkCompleted{ID: "slow-tool", Err: "interrupted: daemon restarted mid-flight"})

	before := w.WorkSnapshot()
	if len(before) != 1 || before[0].State != WorkFailed {
		t.Fatalf("pre-condition: work should be WorkFailed; got %+v", before)
	}

	// Late completion from the worker that was still running: must be idempotent.
	// Case 1: late success — must NOT flip WorkFailed → WorkDone.
	Reduce(w, WorkCompleted{ID: "slow-tool", Result: "late success"})
	after := w.WorkSnapshot()
	if after[0].State != WorkFailed {
		t.Errorf("late success on already-failed work must not flip state; got %s", after[0].State)
	}
	if after[0].Err != "interrupted: daemon restarted mid-flight" {
		t.Errorf("late success must not clear the failure error; got %q", after[0].Err)
	}

	// Case 2: re-apply same failure — must not corrupt.
	Reduce(w, WorkCompleted{ID: "slow-tool", Err: "duplicate"})
	after2 := w.WorkSnapshot()
	if after2[0].State != WorkFailed {
		t.Errorf("second failure on already-failed work must be idempotent; got %s", after2[0].State)
	}
	if after2[0].Err != "interrupted: daemon restarted mid-flight" {
		t.Errorf("re-applied failure must not overwrite the original error; got %q", after2[0].Err)
	}
}

// TestCrashResume_AlreadyDoneWorkCompletedIdempotent ensures the terminal-guard
// also covers WorkDone (not just WorkFailed). A second WorkCompleted for an
// already-done item is a no-op.
func TestCrashResume_AlreadyDoneWorkCompletedIdempotent(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, WorkDispatched{ID: "w1", ItemKind: "tool", Target: "t"})
	Reduce(w, WorkCompleted{ID: "w1", Result: "first result"})

	if s := w.WorkSnapshot()[0].State; s != WorkDone {
		t.Fatalf("pre-condition: w1 should be WorkDone, got %s", s)
	}

	// A duplicate/late completion must not clobber the result.
	Reduce(w, WorkCompleted{ID: "w1", Result: "duplicate"})
	snap := w.WorkSnapshot()[0]
	if snap.State != WorkDone {
		t.Errorf("duplicate completion: want still WorkDone, got %s", snap.State)
	}
	if snap.Result != "first result" {
		t.Errorf("duplicate completion: want original result, got %q", snap.Result)
	}

	// A late failure on a done item must also be a no-op.
	Reduce(w, WorkCompleted{ID: "w1", Err: "late error"})
	snap2 := w.WorkSnapshot()[0]
	if snap2.State != WorkDone {
		t.Errorf("late error on done work: want still WorkDone, got %s", snap2.State)
	}
}
