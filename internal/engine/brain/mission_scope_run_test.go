// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

// tworunEvents is the Timeline of one mission record that ran twice.
func tworunEvents() []Event {
	return []Event{
		MissionProjected{ID: "m", RunID: "r1", Nodes: []WorkNode{{ID: "n"}}},
		WorkDispatched{ID: "m/n", MissionID: "m", RunID: "r1", ItemKind: "tool", Target: "t"},
		FindingRaised{MissionID: "m", MissionRunID: "r1", Title: "f1"},
		WorkCompleted{ID: "m/n", RunID: "r1", Result: "ok"},
		MissionDone{ID: "m", RunID: "r1"},
		MissionProjected{ID: "m", RunID: "r2", Nodes: []WorkNode{{ID: "n"}}},
		WorkDispatched{ID: "m/n", MissionID: "m", RunID: "r2", ItemKind: "tool", Target: "t"},
		FindingRaised{MissionID: "m", MissionRunID: "r2", Title: "f2"},
		FindingRaised{MissionID: "m", Title: "no-run-id"}, // positional: run 2
	}
}

func TestMissionSlice_HoldsOneRun(t *testing.T) {
	evs := tworunEvents()

	latest := MissionSlice(evs, "m")
	if len(latest) != 4 {
		t.Fatalf("latest slice = %d events, want 4 (%v)", len(latest), latest)
	}
	if p, ok := latest[0].(MissionProjected); !ok || p.RunID != "r2" {
		t.Fatalf("latest slice starts with %+v, want the projection of r2", latest[0])
	}

	first := missionSlice(evs, "m", "r1", true)
	if len(first) != 5 {
		t.Fatalf("run 1 slice = %d events, want 5 (%v)", len(first), first)
	}
	for _, ev := range first {
		if id := explicitRunID(ev); id != "" && id != "r1" {
			t.Fatalf("run 1 slice holds an event of %q", id)
		}
	}

	// A frame of the latest run starts from nothing, not from the end of run 1.
	tl := &Timeline{}
	for _, ev := range latest[:1] {
		tl.Append(ev)
	}
	w := Replay("t", tl)
	if wk := w.WorkSnapshot(); len(wk) != 1 || wk[0].State != WorkPending {
		t.Fatalf("frame at 1 of run 2 work = %+v, want one pending item", wk)
	}
}

// Each event that names its run gives that run to the slice.
func TestExplicitRunID(t *testing.T) {
	for _, ev := range []Event{
		MissionProjected{RunID: "r"}, MissionStarted{RunID: "r"}, MissionDone{RunID: "r"},
		MissionPauseRequested{RunID: "r"}, MissionResumed{RunID: "r"},
		WorkDispatched{RunID: "r"}, WorkCompleted{RunID: "r"},
		DecisionRequested{RunID: "r"}, DecisionCompleted{RunID: "r"},
		HostObserved{MissionRunID: "r"}, FindingRaised{MissionRunID: "r"},
		EntityObserved{MissionRunID: "r"}, LlmCallObserved{MissionRunID: "r"},
		AgentToolCallObserved{MissionRunID: "r"},
	} {
		if got := explicitRunID(ev); got != "r" {
			t.Errorf("%T: explicitRunID = %q, want r", ev, got)
		}
	}
	if got := explicitRunID(TokenUsed{}); got != "" {
		t.Errorf("an event with no run: explicitRunID = %q, want empty", got)
	}
}
