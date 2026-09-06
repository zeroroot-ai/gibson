// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

// TestProjection_TwoMissionsMayShareNodeNames is the regression: node ids are
// unique within one mission definition, but the World is per-tenant and
// long-lived, so a second mission naming a node "fetch" used to be skipped as
// already-projected. It then had zero work items, and MissionCompletionSystem
// read "nothing running, nothing ready" as "all work complete" — reporting
// SUCCESS for a mission that did nothing at all.
func TestProjection_TwoMissionsMayShareNodeNames(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "fetch", Kind: "tool", Target: "http", Input: `{"url":"https://a.example"}`},
	}})
	Reduce(w, MissionProjected{ID: "m2", Nodes: []WorkNode{
		{ID: "fetch", Kind: "tool", Target: "http", Input: `{"url":"https://b.example"}`},
	}})

	byMission := map[string][]WorkSnapshot{}
	for _, wi := range w.WorkSnapshot() {
		byMission[wi.MissionID] = append(byMission[wi.MissionID], wi)
	}
	if len(byMission["m1"]) != 1 || len(byMission["m2"]) != 1 {
		t.Fatalf("work per mission = m1:%d m2:%d, want one each",
			len(byMission["m1"]), len(byMission["m2"]))
	}
	// Each mission must carry its OWN input; sharing one work item would have
	// silently run the first mission's parameters for the second.
	if byMission["m2"][0].Input != `{"url":"https://b.example"}` {
		t.Errorf("m2 input = %q, want its own", byMission["m2"][0].Input)
	}
}

func TestProjection_ScopesDependenciesToTheSameMission(t *testing.T) {
	// A dependency names a node; unscoped, it would resolve against another
	// mission's identically-named node and gate on the wrong work.
	w := NewWorld("acme")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "scan", Kind: "tool", Target: "nmap"},
		{ID: "report", Kind: "tool", Target: "md", DependsOn: []string{"scan"}},
	}})

	for _, wi := range w.WorkSnapshot() {
		if nodeName(wi.ID) != "report" {
			continue
		}
		if len(wi.DependsOn) != 1 || wi.DependsOn[0] != WorkID("m1", "scan") {
			t.Fatalf("report depends on %v, want the mission-scoped scan id", wi.DependsOn)
		}
	}
}

func TestProjection_RemainsIdempotentWithinAMission(t *testing.T) {
	// Replay folds the same event again; it must not duplicate work.
	w := NewWorld("acme")
	ev := MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "fetch", Kind: "tool", Target: "http"}}}
	Reduce(w, ev)
	Reduce(w, ev)
	if got := len(w.WorkSnapshot()); got != 1 {
		t.Fatalf("work items = %d, want 1 after re-applying the same projection", got)
	}
}

func TestWorkID_RoundTripsThroughNodeName(t *testing.T) {
	if got := WorkID("m1", "fetch"); got != "m1/fetch" {
		t.Errorf("WorkID = %q", got)
	}
	if got := nodeName(WorkID("m1", "fetch")); got != "fetch" {
		t.Errorf("nodeName = %q, want the node back", got)
	}
	// A bare id (pre-scoping events replayed from an older Timeline) still reads
	// as its own node name rather than being mangled.
	if got := nodeName("fetch"); got != "fetch" {
		t.Errorf("nodeName of an unscoped id = %q", got)
	}
}
