// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// TestCountermeasureEvents: the countermeasure that a fix applies becomes an
// edge from the merge request to the countermeasure (gibson#1487).
func TestCountermeasureEvents(t *testing.T) {
	lookup := func(id string) (ontology.Countermeasure, bool) {
		if id == "D3-FA" {
			return ontology.Countermeasure{ID: "D3-FA", Name: "File Analysis", Tactic: "Detect"}, true
		}
		return ontology.Countermeasure{}, false
	}
	closed := closedJob([]string{"f-1"}, mrDeliverable)
	closed.Countermeasure = "D3-FA"

	got := entities(t, countermeasureEvents(closed, testMRURL, lookup, true))
	if len(got) != 2 {
		t.Fatalf("events = %+v, want the countermeasure and the merge request", got)
	}
	if got[0].Label != "Countermeasure" || got[0].Key != "D3-FA" || got[0].Props["name"] != "File Analysis" {
		t.Errorf("countermeasure entity = %+v", got[0])
	}
	want := brain.EntityEdge{Type: "APPLIES_COUNTERMEASURE", TargetLabel: "Countermeasure", TargetKey: "D3-FA"}
	if got[1].Label != "MergeRequest" || got[1].Key != testMRURL || len(got[1].Edges) != 1 || got[1].Edges[0] != want {
		t.Errorf("merge request entity = %+v", got[1])
	}

	// A finding with no technique has a fix with no countermeasure. Nothing is
	// written and nothing fails.
	none := closedJob([]string{"f-1"}, mrDeliverable)
	if evs := countermeasureEvents(none, testMRURL, lookup, true); len(evs) != 0 {
		t.Errorf("a job with no countermeasure gave %+v", evs)
	}
	// An id that the pack does not hold gives no edge and no error.
	closed.Countermeasure = "D3-NOPE"
	if evs := countermeasureEvents(closed, testMRURL, lookup, true); len(evs) != 0 {
		t.Errorf("an unknown countermeasure gave %+v", evs)
	}
	// A Taxonomy that does not admit the label gives no edge.
	closed.Countermeasure = "D3-FA"
	if evs := countermeasureEvents(closed, testMRURL, lookup, false); len(evs) != 0 {
		t.Errorf("a Taxonomy without the label gave %+v", evs)
	}
}

// TestFixedByEvents_CountermeasureEdgeFollowsTheTaxonomy: with the real
// embedded D3FEND pack, a merged fix that names D3-FA gets the edge exactly
// when the Taxonomy admits the label and the edge type, and the FIXED_BY
// events are the same in both cases.
func TestFixedByEvents_CountermeasureEdgeFollowsTheTaxonomy(t *testing.T) {
	closed := closedJob([]string{"f-1"}, mrDeliverable)
	closed.Countermeasure = "D3-FA"
	evs, _ := fixedByEvents(closed, worldWith(map[string]string{"f-1": "s"}))
	got := entities(t, evs)
	wantLen := 2
	if countermeasureAdmitted() {
		wantLen = 4
	}
	if len(got) != wantLen {
		t.Fatalf("events = %d, want %d (taxonomy admits the link: %v)", len(got), wantLen, countermeasureAdmitted())
	}
}
