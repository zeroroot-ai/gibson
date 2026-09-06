// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

// scanWorld builds a World holding one scan mission against target and one
// unrelated non-scan mission, so every test starts from a shape where scoping
// can actually go wrong.
func scanWorld(t *testing.T, missionID, target string, status MissionStatus) *World {
	t.Helper()
	w := NewWorld("t1")
	Reduce(w, MissionStarted{ID: missionID, Name: ScanMissionName, TargetID: target})
	if status != MissionRunning {
		Reduce(w, MissionDone{ID: missionID, Outcome: status})
	}
	return w
}

// raiseInto raises a Finding attributed to missionID and then sets its status,
// which is how every Finding reaches `fixed` in production: an agent moves it
// after the scan that raised it.
func raiseInto(w *World, id, missionID, status string) {
	Reduce(w, FindingRaised{ID: id, MissionID: missionID})
	if status != "" && status != FindingStatusOpen {
		Reduce(w, FindingStatusChanged{ID: id, Status: status})
	}
}

func findingByID(t *testing.T, w *World, id string) FindingSnapshot {
	t.Helper()
	for _, f := range w.FindingSnapshot() {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("finding %q is not in the World", id)
	return FindingSnapshot{}
}

// applyAll reduces every event a System produced, which is what the tick does.
func applyAll(w *World, evs []Event) {
	for _, ev := range evs {
		Reduce(w, ev)
	}
}

// TestRescan_FixedAndUnseen_BecomesVerified is the transition the whole issue
// exists for: a fix held, and nothing observed it holding.
func TestRescan_FixedAndUnseen_BecomesVerified(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionRunning)
	raiseInto(w, "f1", "scan-1", FindingStatusFixed)

	// A second scan of the same target runs and does NOT re-raise f1.
	Reduce(w, MissionStarted{ID: "scan-2", Name: ScanMissionName, TargetID: "target-a"})
	Reduce(w, MissionDone{ID: "scan-2", Outcome: MissionCompleted})

	applyAll(w, RescanReconciliationSystem(w))

	if got := findingByID(t, w, "f1").Status; got != FindingStatusVerified {
		t.Fatalf("a fixed Finding the rescan did not see must be verified, got %q", got)
	}
}

// TestRescan_FixedAndSeenAgain_ReturnsToOpen — the fix did not hold. This is the
// case that makes verified mean something: absence has to be able to be absent.
func TestRescan_FixedAndSeenAgain_ReturnsToOpen(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionRunning)
	raiseInto(w, "f1", "scan-1", FindingStatusFixed)

	Reduce(w, MissionStarted{ID: "scan-2", Name: ScanMissionName, TargetID: "target-a"})
	Reduce(w, FindingRaised{ID: "f1", MissionID: "scan-2"}) // seen again
	Reduce(w, MissionDone{ID: "scan-2", Outcome: MissionCompleted})

	applyAll(w, RescanReconciliationSystem(w))

	if got := findingByID(t, w, "f1").Status; got != FindingStatusOpen {
		t.Fatalf("a fixed Finding the rescan saw again must return to open, got %q", got)
	}
}

// TestRescan_OpenAndUnseen_DoesNotMove. A scan not seeing something nobody
// claimed to fix is not evidence, and silently closing it would lose a real
// weakness.
func TestRescan_OpenAndUnseen_DoesNotMove(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionRunning)
	raiseInto(w, "open-one", "scan-1", FindingStatusOpen)
	raiseInto(w, "fixing-one", "scan-1", FindingStatusFixing)

	Reduce(w, MissionStarted{ID: "scan-2", Name: ScanMissionName, TargetID: "target-a"})
	Reduce(w, MissionDone{ID: "scan-2", Outcome: MissionCompleted})

	applyAll(w, RescanReconciliationSystem(w))

	if got := findingByID(t, w, "open-one").Status; got != FindingStatusOpen {
		t.Errorf("an open Finding must survive a rescan that did not see it, got %q", got)
	}
	if got := findingByID(t, w, "fixing-one").Status; got != FindingStatusFixing {
		t.Errorf("a fixing Finding has a merge request in flight; a rescan's silence says nothing, got %q", got)
	}
}

// TestRescan_FailedScan_VerifiesNothing. A scan that could not run produces the
// same report as a scan that found everything clean: an empty one. Only one of
// those is evidence.
func TestRescan_FailedScan_VerifiesNothing(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionRunning)
	raiseInto(w, "f1", "scan-1", FindingStatusFixed)

	Reduce(w, MissionStarted{ID: "scan-2", Name: ScanMissionName, TargetID: "target-a"})
	Reduce(w, MissionDone{ID: "scan-2", Outcome: MissionFailed})

	evs := RescanReconciliationSystem(w)
	for _, ev := range evs {
		if sc, ok := ev.(FindingStatusChanged); ok {
			t.Fatalf("a failed scan changed %q to %q; an unfinished look is not evidence of absence", sc.ID, sc.Status)
		}
	}
	applyAll(w, evs)

	if got := findingByID(t, w, "f1").Status; got != FindingStatusFixed {
		t.Fatalf("a failed scan must leave a fixed Finding fixed, got %q", got)
	}
}

// TestRescan_OutOfScopeFinding_IsNeverTouched is the "too wide" failure. A
// Finding no scan ever raised — a pentest finding, a hand-filed one — has an
// empty ScanScope and must survive every scan completion in the tenant.
func TestRescan_OutOfScopeFinding_IsNeverTouched(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionRunning)
	// Raised with no mission at all: the component path carries no mission context.
	raiseInto(w, "hand-filed", "", FindingStatusFixed)
	// Raised by a mission that is not a scan.
	Reduce(w, MissionStarted{ID: "pentest-1", Name: "pentest", TargetID: "target-a"})
	raiseInto(w, "from-pentest", "pentest-1", FindingStatusFixed)

	Reduce(w, MissionDone{ID: "scan-1", Outcome: MissionCompleted})
	applyAll(w, RescanReconciliationSystem(w))

	for _, id := range []string{"hand-filed", "from-pentest"} {
		f := findingByID(t, w, id)
		if f.ScanScope != "" {
			t.Errorf("%s: a Finding no scan raised must have no scan scope, got %q", id, f.ScanScope)
		}
		if f.Status != FindingStatusFixed {
			t.Errorf("%s: a scan verified a Finding it was never responsible for, status %q", id, f.Status)
		}
	}
}

// TestRescan_AnotherTargetsScan_DoesNotReconcile. Two Applications scan
// independently; one finishing says nothing about the other's Findings.
func TestRescan_AnotherTargetsScan_DoesNotReconcile(t *testing.T) {
	w := scanWorld(t, "scan-a", "target-a", MissionRunning)
	raiseInto(w, "f-a", "scan-a", FindingStatusFixed)

	Reduce(w, MissionStarted{ID: "scan-b", Name: ScanMissionName, TargetID: "target-b"})
	Reduce(w, MissionDone{ID: "scan-b", Outcome: MissionCompleted})

	applyAll(w, RescanReconciliationSystem(w))

	if got := findingByID(t, w, "f-a").Status; got != FindingStatusFixed {
		t.Fatalf("a scan of another target reconciled target-a's Finding, status %q", got)
	}
}

// TestRescan_RunsOncePerScan. The marker is what keeps a completed scan's
// judgement from outliving the scan: an agent that marks a Finding fixed after
// the scan finished must wait for the NEXT scan, not be verified on the next
// tick by one that never saw the fix.
func TestRescan_RunsOncePerScan(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionRunning)
	raiseInto(w, "f1", "scan-1", FindingStatusOpen)
	Reduce(w, MissionDone{ID: "scan-1", Outcome: MissionCompleted})

	applyAll(w, RescanReconciliationSystem(w))

	// The agent fixes it AFTER the scan completed.
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixed})

	if evs := RescanReconciliationSystem(w); len(evs) != 0 {
		t.Fatalf("a reconciled scan judged a fix it never saw: %#v", evs)
	}
	if got := findingByID(t, w, "f1").Status; got != FindingStatusFixed {
		t.Fatalf("the fix must wait for the next scan, got %q", got)
	}
}

// TestRescan_IsQuiescent — a second pass over an already-reconciled World emits
// nothing, so the System can run on every tick.
func TestRescan_IsQuiescent(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionRunning)
	raiseInto(w, "f1", "scan-1", FindingStatusFixed)
	Reduce(w, MissionDone{ID: "scan-1", Outcome: MissionCompleted})

	first := RescanReconciliationSystem(w)
	if len(first) == 0 {
		t.Fatal("the first pass must reconcile")
	}
	applyAll(w, first)

	if evs := RescanReconciliationSystem(w); len(evs) != 0 {
		t.Fatalf("the System is not quiescent, second pass emitted %#v", evs)
	}
}

// TestRescan_BranchCompletionCannotVerify is the acceptance criterion that a
// single branch finishing cannot verify a Finding another branch owns. The
// runtime branch completing says nothing about a Finding the image branch
// raised — each branch is blind to the other two, which is why the mission
// joins at `report` and why this System keys on the mission, never on work.
func TestRescan_BranchCompletionCannotVerify(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionRunning)
	raiseInto(w, "from-image", "scan-1", FindingStatusFixed)

	// The runtime branch finishes. The mission has not.
	Reduce(w, WorkDispatched{ID: WorkID("scan-1", "tls"), MissionID: "scan-1"})
	Reduce(w, WorkCompleted{ID: WorkID("scan-1", "tls")})

	if evs := RescanReconciliationSystem(w); len(evs) != 0 {
		t.Fatalf("a branch completion reconciled: %#v", evs)
	}
	if got := findingByID(t, w, "from-image").Status; got != FindingStatusFixed {
		t.Fatalf("one branch finishing verified a Finding another branch owns, status %q", got)
	}
}

// TestRescan_ReRaiseKeepsStatusAndMovesLastScan. A re-raise is a sighting, not a
// new Finding: an agent's status and everything else it holds survive, and only
// the rescan provenance moves. Without that, the second scan of an unchanged
// Application is indistinguishable from no scan at all.
func TestRescan_ReRaiseKeepsStatusAndMovesLastScan(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionRunning)
	Reduce(w, FindingRaised{ID: "f1", MissionID: "scan-1", Title: "original", Severity: "high"})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixed})

	Reduce(w, MissionStarted{ID: "scan-2", Name: ScanMissionName, TargetID: "target-a"})
	Reduce(w, FindingRaised{ID: "f1", MissionID: "scan-2", Title: "ignored", Severity: "low"})

	f := findingByID(t, w, "f1")
	if f.Status != FindingStatusFixed {
		t.Errorf("a re-raise must not reset the status an agent set, got %q", f.Status)
	}
	if f.Title != "original" || f.Severity != "high" {
		t.Errorf("a re-raise must not overwrite the Finding, got title=%q severity=%q", f.Title, f.Severity)
	}
	if f.LastScan != "scan-2" {
		t.Errorf("a re-raise must move LastScan to the scan that saw it, got %q", f.LastScan)
	}
	if f.ScanScope != "target-a" {
		t.Errorf("ScanScope must stay the recurring scan's target, got %q", f.ScanScope)
	}
}

// TestRescan_NonScanMissionIsNotReconciled. Only the scan definition reconciles;
// another mission type completing must not mark or move anything.
func TestRescan_NonScanMissionIsNotReconciled(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MissionStarted{ID: "m1", Name: "pentest", TargetID: "target-a"})
	Reduce(w, MissionDone{ID: "m1", Outcome: MissionCompleted})

	if evs := RescanReconciliationSystem(w); len(evs) != 0 {
		t.Fatalf("a non-scan mission reconciled: %#v", evs)
	}
}

// TestScanReconciled_UnknownMission_ChangesNothing — the event is in the
// Timeline either way; an unknown mission must not panic or invent one.
func TestScanReconciled_UnknownMission_ChangesNothing(t *testing.T) {
	w := scanWorld(t, "scan-1", "target-a", MissionCompleted)
	Reduce(w, ScanReconciled{MissionID: "nobody"})

	for _, m := range w.MissionSnapshot() {
		if m.Reconciled {
			t.Fatalf("mission %q was marked reconciled by an event naming another", m.ID)
		}
	}
}

// TestScanReconciled_IsInItsMissionSlice — the verdict belongs to the scan that
// reached it, so a mission-scoped replay includes it.
func TestScanReconciled_IsInItsMissionSlice(t *testing.T) {
	evs := []Event{
		ScanReconciled{MissionID: "scan-1"},
		ScanReconciled{MissionID: "scan-2"},
	}
	got := MissionSlice(evs, "scan-1")
	if len(got) != 1 {
		t.Fatalf("want exactly scan-1's verdict, got %#v", got)
	}
	if sr, ok := got[0].(ScanReconciled); !ok || sr.MissionID != "scan-1" {
		t.Fatalf("wrong event in the slice: %#v", got[0])
	}
}

// TestRescan_ScanWithNoTarget_ReconcilesNothing is the case the ScanScope
// emptiness guard actually exists for, and it is the widest failure available.
//
// A Finding raised outside any scan has an empty ScanScope. Comparing scopes
// alone would then read `"" != ""` as "in scope" for a scan mission that has no
// target — a scan submitted without one, or one whose target never bound — and
// that single scan completing would verify every hand-filed and pentest Finding
// in the tenant at once. Emptiness has to be refused explicitly rather than
// falling out of the comparison.
func TestRescan_ScanWithNoTarget_ReconcilesNothing(t *testing.T) {
	w := NewWorld("t1")
	// A Finding no scan ever raised: empty ScanScope.
	raiseInto(w, "hand-filed", "", FindingStatusFixed)

	// A scan mission that never bound a target.
	Reduce(w, MissionStarted{ID: "scan-untargeted", Name: ScanMissionName, TargetID: ""})
	Reduce(w, MissionDone{ID: "scan-untargeted", Outcome: MissionCompleted})

	for _, ev := range RescanReconciliationSystem(w) {
		if sc, ok := ev.(FindingStatusChanged); ok {
			t.Fatalf("an untargeted scan moved %q to %q; every out-of-scope Finding in the tenant was in range", sc.ID, sc.Status)
		}
	}
	if got := findingByID(t, w, "hand-filed").Status; got != FindingStatusFixed {
		t.Fatalf("a Finding no scan raised must be untouched, got %q", got)
	}
}

// TestScanReconciled_RoundTripsThroughTheTimeline. The marker has to survive
// persistence, not just live in memory: the World is a fold of the Timeline, so
// an event that does not decode is an event that never happened on replay. A
// daemon restart would then re-reconcile every completed scan it has ever run
// and re-verify Findings an agent has since re-opened.
func TestScanReconciled_RoundTripsThroughTheTimeline(t *testing.T) {
	data, err := EncodeEvent(ScanReconciled{MissionID: "scan-1"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeEvent(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	sr, ok := got.(ScanReconciled)
	if !ok {
		t.Fatalf("decoded to %T, not ScanReconciled", got)
	}
	if sr.MissionID != "scan-1" {
		t.Fatalf("mission id did not survive the round trip: %q", sr.MissionID)
	}
	if sr.Kind() != "scan.reconciled" {
		t.Fatalf("kind is %q", sr.Kind())
	}
}

// TestRescan_ReplayAfterRestart_DoesNotReReconcile is the property the round
// trip protects, exercised end to end: folding the Timeline again must land on
// the same World, with the scan still reconciled and the agent's later re-open
// intact.
func TestRescan_ReplayAfterRestart_DoesNotReReconcile(t *testing.T) {
	timeline := []Event{
		MissionStarted{ID: "scan-1", Name: ScanMissionName, TargetID: "target-a"},
		FindingRaised{ID: "f1", MissionID: "scan-1"},
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixed},
		MissionDone{ID: "scan-1", Outcome: MissionCompleted},
		ScanReconciled{MissionID: "scan-1"},
		FindingStatusChanged{ID: "f1", Status: FindingStatusVerified},
		// The agent finds it again by hand and re-opens it.
		FindingStatusChanged{ID: "f1", Status: FindingStatusOpen},
	}

	replayed := NewWorld("t1")
	for _, ev := range timeline {
		data, err := EncodeEvent(ev)
		if err != nil {
			t.Fatalf("encode %T: %v", ev, err)
		}
		decoded, err := DecodeEvent(data)
		if err != nil {
			t.Fatalf("decode %T: %v", ev, err)
		}
		Reduce(replayed, decoded)
	}

	if evs := RescanReconciliationSystem(replayed); len(evs) != 0 {
		t.Fatalf("replay re-reconciled a scan that had already run: %#v", evs)
	}
	if got := findingByID(t, replayed, "f1").Status; got != FindingStatusOpen {
		t.Fatalf("replay overwrote the agent's re-open, got %q", got)
	}
}
