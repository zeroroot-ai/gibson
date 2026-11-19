// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

func missionStatusOf(t *testing.T, w *World, id string) MissionStatus {
	t.Helper()
	for _, m := range w.MissionSnapshot() {
		if m.ID == id {
			return m.Status
		}
	}
	t.Fatalf("mission %s is not in the World", id)
	return ""
}

func requestApproval(w *World, hypothesis, missionID string) {
	Reduce(w, DestructiveActionRequested{HypothesisID: hypothesis, MissionID: missionID, Tenant: "t"})
}

func decideApproval(w *World, hypothesis string) {
	Reduce(w, DestructiveActionDecided{HypothesisID: hypothesis, Approved: true, UserID: "u1"})
}

// An open approval request gives "input required". The last decision gives
// "working" again.
func TestInputRequired_OpenApprovalSetsTheState(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", RunID: "r1"})
	Reduce(w, MissionStarted{ID: "m2", RunID: "r2"})

	requestApproval(w, "h1", "m1")
	if got := missionStatusOf(t, w, "m1"); got != MissionInputRequired {
		t.Fatalf("m1 with an open request = %s, want %s", got, MissionInputRequired)
	}
	if got := missionStatusOf(t, w, "m2"); got != MissionWorking {
		t.Fatalf("m2 has no request and must stay %s, got %s", MissionWorking, got)
	}

	// A second request keeps the state until both are decided.
	requestApproval(w, "h2", "m1")
	decideApproval(w, "h1")
	if got := missionStatusOf(t, w, "m1"); got != MissionInputRequired {
		t.Fatalf("m1 with one open request = %s, want %s", got, MissionInputRequired)
	}
	decideApproval(w, "h2")
	if got := missionStatusOf(t, w, "m1"); got != MissionWorking {
		t.Fatalf("m1 with no open request = %s, want %s", got, MissionWorking)
	}
}

func TestInputRequired_ARequestWithoutAMissionChangesNothing(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", RunID: "r1"})
	requestApproval(w, "h1", "")
	requestApproval(w, "h2", "unknown")
	if got := missionStatusOf(t, w, "m1"); got != MissionWorking {
		t.Fatalf("m1 = %s, want %s", got, MissionWorking)
	}
}

// A paused mission keeps "paused". A resume returns "input required" when a
// request is still open.
func TestInputRequired_PauseAndResume(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", RunID: "r1"})
	requestApproval(w, "h1", "m1")

	Reduce(w, MissionPauseRequested{ID: "m1"})
	if got := missionStatusOf(t, w, "m1"); got != MissionPaused {
		t.Fatalf("pause from input required = %s, want %s", got, MissionPaused)
	}
	decideApproval(w, "h1")
	if got := missionStatusOf(t, w, "m1"); got != MissionPaused {
		t.Fatalf("a decision must not resume a paused mission, got %s", got)
	}

	requestApproval(w, "h2", "m1")
	Reduce(w, MissionResumed{ID: "m1"})
	if got := missionStatusOf(t, w, "m1"); got != MissionInputRequired {
		t.Fatalf("resume with an open request = %s, want %s", got, MissionInputRequired)
	}
}

// ADR-0132: the fleet keeps working while a decision is pending.
func TestInputRequired_StillDispatchesWork(t *testing.T) {
	e := engineWithScheduler(nil)
	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "a", Kind: "tool", Target: "t"}}})
	e.Submit(DestructiveActionRequested{HypothesisID: "h1", MissionID: "m1", Tenant: "t1"})
	e.Tick()

	for _, wi := range e.Work() {
		if wi.State != WorkDone {
			t.Errorf("work %s = %s, want done: an open request must not stop dispatch", wi.ID, wi.State)
		}
	}
}

// A cancel gives "canceled" and not "failed".
func TestCanceled_IsATerminalStateThatIsNotAFailure(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", RunID: "r1"})
	Reduce(w, MissionDone{ID: "m1", RunID: "r1", Outcome: MissionCanceled, Reason: "stopped by user"})
	if got := missionStatusOf(t, w, "m1"); got != MissionCanceled {
		t.Fatalf("status = %s, want %s", got, MissionCanceled)
	}
	if !MissionCanceled.IsTerminal() {
		t.Error("canceled must be terminal")
	}

	// A later event does not move a canceled mission.
	Reduce(w, MissionDone{ID: "m1", RunID: "r1", Outcome: MissionFailed, Reason: "late"})
	if got := missionStatusOf(t, w, "m1"); got != MissionCanceled {
		t.Fatalf("a late failure moved the mission to %s", got)
	}
}

func TestCanceled_ASnapshotRoundTrips(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", RunID: "r1"})
	Reduce(w, MissionDone{ID: "m1", RunID: "r1", Outcome: MissionCanceled, Reason: "stopped by user"})
	Reduce(w, MissionStarted{ID: "m2", RunID: "r2"})
	requestApproval(w, "h1", "m2")

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := missionStatusOf(t, restored, "m1"); got != MissionCanceled {
		t.Errorf("m1 after restore = %s, want %s", got, MissionCanceled)
	}
	if got := missionStatusOf(t, restored, "m2"); got != MissionInputRequired {
		t.Errorf("m2 after restore = %s, want %s", got, MissionInputRequired)
	}
}

// A canceled scan is finished and is not evidence, so the rescan system marks
// it reconciled without closing a finding.
func TestCanceled_RescanTreatsItAsEnded(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionStarted{ID: "m1", RunID: "r1", Name: ScanMissionName})
	Reduce(w, MissionDone{ID: "m1", RunID: "r1", Outcome: MissionCanceled})
	events := RescanReconciliationSystem(w)
	if len(events) != 1 {
		t.Fatalf("got %d events, want one ScanReconciled", len(events))
	}
	if _, ok := events[0].(ScanReconciled); !ok {
		t.Fatalf("event = %T, want ScanReconciled", events[0])
	}
}

// A mission cannot end in a state that still runs. The reducer drops a
// MissionDone event whose outcome is not terminal.
func TestMissionDone_AnOutcomeThatIsNotTerminalChangesNothing(t *testing.T) {
	for _, outcome := range []MissionStatus{MissionSubmitted, MissionWorking, MissionInputRequired, MissionPaused} {
		t.Run(string(outcome), func(t *testing.T) {
			w := NewWorld("t")
			Reduce(w, MissionStarted{ID: "m1", RunID: "r1"})

			Reduce(w, MissionDone{ID: "m1", RunID: "r1", Outcome: outcome, Reason: "bad"})

			if got := missionStatusOf(t, w, "m1"); got != MissionWorking {
				t.Fatalf("status = %q, want working", got)
			}
		})
	}
}

func TestMissionDone_FinalOutcome(t *testing.T) {
	if got, ok := (MissionDone{}).FinalOutcome(); !ok || got != MissionCompleted {
		t.Fatalf("empty outcome = %q, %v, want completed, true", got, ok)
	}
	if got, ok := (MissionDone{Outcome: MissionCanceled}).FinalOutcome(); !ok || got != MissionCanceled {
		t.Fatalf("canceled outcome = %q, %v, want canceled, true", got, ok)
	}
	if _, ok := (MissionDone{Outcome: MissionWorking}).FinalOutcome(); ok {
		t.Fatal("working is not a final outcome")
	}
}
