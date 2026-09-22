// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

// TestFinding_RaisedCarriesTheSubmitter (gibson#208): the verified submitter on
// a FindingRaised lands on the Finding and reads back on its snapshot, on the
// live World and on a replay, so the projector can write it.
func TestFinding_RaisedCarriesTheSubmitter(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(FindingRaised{
		ID: "f1", Title: "exposed admin panel", Severity: "info",
		SubmittedBy: "agent_principal:sa-1", AgentName: "zerocool-demo", EnrolledBy: "user-9",
	})
	// A re-raise is a sighting, not a new submitter: the first record stays.
	apply(FindingRaised{ID: "f1", Title: "exposed admin panel", Severity: "info", SubmittedBy: "agent_principal:other"})

	want := []FindingSnapshot{{
		ID: "f1", Title: "exposed admin panel", Severity: "info", Status: FindingStatusOpen,
		SubmittedBy: "agent_principal:sa-1", AgentName: "zerocool-demo", EnrolledBy: "user-9",
	}}
	if got := w.FindingSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("findings:\n got %+v\nwant %+v", got, want)
	}
	if r := Replay("t", tl); !reflect.DeepEqual(r.FindingSnapshot(), want) {
		t.Fatalf("replay diverged: %+v", r.FindingSnapshot())
	}
}
