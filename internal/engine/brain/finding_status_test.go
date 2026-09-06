// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

// TestFindingStatus_ChangesInPlace: the Finding is the occurrence and holds the
// status, so a status change updates the node the graph already has rather than
// raising a second Finding (gibson#1656).
func TestFindingStatus_ChangesInPlace(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, FindingRaised{ID: "f1", Title: "vulnerable lodash", ScopeID: "s", Severity: "high"})

	for _, status := range []string{FindingStatusFixing, FindingStatusFixed, FindingStatusVerified} {
		Reduce(w, FindingStatusChanged{ID: "f1", Status: status})
		got := w.FindingSnapshot()
		if len(got) != 1 {
			t.Fatalf("a status change must not add a Finding, got %d", len(got))
		}
		if got[0].Status != status {
			t.Fatalf("status: got %q want %q", got[0].Status, status)
		}
	}
}

// TestFindingStatus_RaisedDefaultsToOpen: a Finding never carries an empty or
// invalid status, so the projector never writes one.
func TestFindingStatus_RaisedDefaultsToOpen(t *testing.T) {
	for _, raised := range []string{"", "nonsense", "OPEN"} {
		w := NewWorld("t")
		Reduce(w, FindingRaised{ID: "f1", Title: "t", Status: raised})
		got := w.FindingSnapshot()
		if len(got) != 1 || got[0].Status != FindingStatusOpen {
			t.Fatalf("raised with %q must default to open, got %+v", raised, got)
		}
	}
}

// TestFindingStatus_InvalidOrUnknownChangesNothing: the World never holds a
// status outside the four, and a change naming a Finding it does not have
// invents nothing.
func TestFindingStatus_InvalidOrUnknownChangesNothing(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, FindingRaised{ID: "f1", Title: "t", Status: FindingStatusFixed})

	Reduce(w, FindingStatusChanged{ID: "f1", Status: "wharrgarbl"})
	if got := w.FindingSnapshot(); got[0].Status != FindingStatusFixed {
		t.Fatalf("an invalid status must not move the Finding, got %q", got[0].Status)
	}

	Reduce(w, FindingStatusChanged{ID: "nobody", Status: FindingStatusOpen})
	if got := w.FindingSnapshot(); len(got) != 1 {
		t.Fatalf("a status change for an unknown Finding must add nothing, got %+v", got)
	}
}

// TestFindingStatus_RescanReopens: fixed -> open is a legal move, because a
// rescan that still sees the Finding reopens it. Only a rescan verifies.
func TestFindingStatus_RescanReopens(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, FindingRaised{ID: "f1", Title: "t"})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixed})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusOpen})

	if got := w.FindingSnapshot(); got[0].Status != FindingStatusOpen {
		t.Fatalf("a rescan that still sees the Finding reopens it, got %q", got[0].Status)
	}
}

// TestFindingStatus_ReplayAndRestore: status and the vulnerability identity
// survive both a Timeline replay and a snapshot round trip.
func TestFindingStatus_ReplayAndRestore(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(FindingRaised{
		ID: "f1", Title: "vulnerable lodash", ScopeID: "s", Severity: "high",
		VulnerabilityID: "CVE-2025-1234",
	})
	apply(FindingStatusChanged{ID: "f1", Status: FindingStatusVerified})

	want := []FindingSnapshot{{
		ID: "f1", Title: "vulnerable lodash", ScopeID: "s", Severity: "high",
		Status: FindingStatusVerified, VulnerabilityID: "CVE-2025-1234",
	}}
	if got := w.FindingSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("world:\n got %+v\nwant %+v", got, want)
	}
	if got := Replay("t", tl).FindingSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("replay diverged: %+v", got)
	}

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := restored.FindingSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot did not round-trip status:\n got %+v\nwant %+v", got, want)
	}
}

// TestValidFindingStatus: the four and nothing else.
func TestValidFindingStatus(t *testing.T) {
	for _, s := range []string{FindingStatusOpen, FindingStatusFixing, FindingStatusFixed, FindingStatusVerified} {
		if !ValidFindingStatus(s) {
			t.Errorf("%q must be valid", s)
		}
	}
	for _, s := range []string{"", "OPEN", "closed", "resolved", "wharrgarbl"} {
		if ValidFindingStatus(s) {
			t.Errorf("%q must not be valid", s)
		}
	}
}
