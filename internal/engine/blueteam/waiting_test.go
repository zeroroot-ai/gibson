// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package blueteam

import (
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

var t0 = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)

func at(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

func TestWaitingOnPerson_AllFourKinds(t *testing.T) {
	findings := []brain.FindingSnapshot{
		{ID: "refused", Status: brain.FindingStatusFixing, MergeRequest: "mr-1"},
		{ID: "scan", Status: brain.FindingStatusFixed,
			FixFacts: brain.FixFacts{CheckKind: "tool", DeployedAt: at(2)}},
		{ID: "nohealth", Status: brain.FindingStatusFixed,
			FixFacts: brain.FixFacts{CheckKind: "scan", DeployedAt: at(1), HealthUnavailableAt: at(3)}},
		{ID: "quiet", Status: brain.FindingStatusFixing, MergeRequest: "mr-2"},
	}
	actions := []brain.DestructiveActionSnapshot{
		{HypothesisID: "h1", RequestedAtUnixMS: at(0).UnixMilli()},
		{HypothesisID: "h2", RequestedAtUnixMS: at(0).UnixMilli(), Decided: true, Approved: true},
	}
	history := []brain.Event{
		brain.MergeRequestObserved{Key: "mr-1", State: brain.MergeRequestRefused, At: at(1)},
		brain.MergeRequestObserved{Key: "mr-1", State: brain.MergeRequestRefused, At: at(2)},
	}
	got := WaitingOnPerson(findings, actions, history, at(5))
	want := map[string]struct {
		kind   WaitKind
		waited time.Duration
	}{
		"h1":       {WaitDestructiveAction, 5 * time.Hour},
		"refused":  {WaitMergeRefused, 4 * time.Hour},
		"scan":     {WaitNextScan, 3 * time.Hour},
		"nohealth": {WaitNoHealthSignal, 2 * time.Hour},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d items, want %d: %+v", len(got), len(want), got)
	}
	for _, it := range got {
		w, ok := want[it.ID]
		if !ok || w.kind != it.Kind || w.waited != it.Waited {
			t.Fatalf("item %+v, want %+v", it, w)
		}
	}
	if got[0].ID != "h1" {
		t.Fatalf("the longest wait is not first: %+v", got)
	}
}

func TestWaitingOnPerson_NextReportEndsARefusal(t *testing.T) {
	findings := []brain.FindingSnapshot{{ID: "f", Status: brain.FindingStatusFixing, MergeRequest: "mr-1"}}
	history := []brain.Event{
		brain.MergeRequestObserved{Key: "mr-1", State: brain.MergeRequestRefused, At: at(1)},
		&brain.MergeRequestObserved{Key: "mr-1", State: brain.MergeRequestMerged, At: at(2)},
	}
	if got := WaitingOnPerson(findings, nil, history, at(5)); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

func TestWaitingOnPerson_ScanAfterDeployEndsTheWait(t *testing.T) {
	findings := []brain.FindingSnapshot{{ID: "f", Status: brain.FindingStatusFixed,
		FixFacts: brain.FixFacts{CheckKind: "tool", DeployedAt: at(2), RerunAt: at(3)}}}
	if got := WaitingOnPerson(findings, nil, nil, at(5)); len(got) != 0 {
		t.Fatalf("got %+v, want none", got)
	}
}

// A refused merge names the reason that the host gave.
func TestWaitingOnPerson_ARefusalCarriesItsReason(t *testing.T) {
	findings := []brain.FindingSnapshot{{ID: "f", Status: brain.FindingStatusFixing, MergeRequest: "mr-1"}}
	history := []brain.Event{
		brain.MergeRequestObserved{Key: "mr-1", State: brain.MergeRequestRefused, Reason: "review required", At: at(1)},
	}
	got := WaitingOnPerson(findings, nil, history, at(3))
	if len(got) != 1 || got[0].Kind != WaitMergeRefused || got[0].Reason != "review required" {
		t.Fatalf("got %+v, want one refused item with its reason", got)
	}
}

// An unreadable merge request and a merged fix with no verdict wait on a person,
// each with its reason. A later event ends the wait. A finding with a verdict
// does not wait (gibson#1609).
func TestWaitingOnPerson_UnreadableAndNoVerdictWaits(t *testing.T) {
	findings := []brain.FindingSnapshot{
		{ID: "unreadable", Status: brain.FindingStatusFixing, MergeRequest: "mr-1"},
		{ID: "noverdict", Status: brain.FindingStatusFixed, MergeRequest: "mr-2",
			FixFacts: brain.FixFacts{CheckKind: "scan", DeployedAt: at(1)}},
		{ID: "verdict", Status: brain.FindingStatusFixed, MergeRequest: "mr-3",
			FixFacts: brain.FixFacts{CheckKind: "scan", DeployedAt: at(1), Health: brain.HealthHeld}},
		{ID: "ended", Status: brain.FindingStatusFixing, MergeRequest: "mr-4"},
	}
	history := []brain.Event{
		brain.FixWaiting{MergeRequest: "mr-1", WaitKind: brain.WaitMergeUnreadable, Reason: "the daemon cannot read the merge request on the Git host", Waiting: true, At: at(1)},
		brain.FixWaiting{MergeRequest: "mr-1", WaitKind: brain.WaitMergeUnreadable, Reason: "again", Waiting: true, At: at(2)},
		brain.FixWaiting{MergeRequest: "mr-2", WaitKind: brain.WaitNoHealthVerdict, Reason: "no health verdict", Waiting: true, At: at(2)},
		brain.FixWaiting{MergeRequest: "mr-3", WaitKind: brain.WaitNoHealthVerdict, Reason: "no health verdict", Waiting: true, At: at(2)},
		brain.FixWaiting{MergeRequest: "mr-4", WaitKind: brain.WaitMergeUnreadable, Reason: "x", Waiting: true, At: at(1)},
		&brain.FixWaiting{MergeRequest: "mr-4", WaitKind: brain.WaitMergeUnreadable, Waiting: false, At: at(3)},
	}
	got := WaitingOnPerson(findings, nil, history, at(5))
	want := map[string]struct {
		kind   WaitKind
		reason string
		waited time.Duration
	}{
		"unreadable": {WaitMergeUnreadable, "the daemon cannot read the merge request on the Git host", 4 * time.Hour},
		"noverdict":  {WaitNoHealthVerdict, "no health verdict", 3 * time.Hour},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %d items", got, len(want))
	}
	for _, it := range got {
		w, ok := want[it.ID]
		if !ok || w.kind != it.Kind || w.reason != it.Reason || w.waited != it.Waited {
			t.Fatalf("item %+v, want %+v", it, w)
		}
	}
}

// A failed health signal with an unmerged revert, and one whose revert call
// failed, each show as an item with the reason. A held finding shows none.
func TestWaitingOnPerson_RevertPendingAndRevertFailed(t *testing.T) {
	failed := brain.FixFacts{CheckKind: "scan", DeployedAt: at(1), Health: brain.HealthFailed}
	findings := []brain.FindingSnapshot{
		{ID: "pending", Status: brain.FindingStatusFixed, MergeRequest: "mr-1", FixFacts: failed},
		{ID: "callfailed", Status: brain.FindingStatusFixed, MergeRequest: "mr-2", FixFacts: failed},
		{ID: "held", Status: brain.FindingStatusFixed, MergeRequest: "mr-3",
			FixFacts: brain.FixFacts{CheckKind: "scan", DeployedAt: at(1), Health: brain.HealthHeld}},
	}
	history := []brain.Event{
		brain.FixWaiting{MergeRequest: "mr-1", WaitKind: brain.WaitRevertPending, Reason: "revert pending: the revert merge request is not merged yet", Waiting: true, At: at(2)},
		brain.FixWaiting{MergeRequest: "mr-2", WaitKind: brain.WaitRevertFailed, Reason: "the revert call failed", Waiting: true, At: at(3)},
		brain.FixWaiting{MergeRequest: "mr-3", WaitKind: brain.WaitRevertPending, Reason: "x", Waiting: true, At: at(2)},
	}
	got := WaitingOnPerson(findings, nil, history, at(5))
	want := map[string]struct {
		kind   WaitKind
		reason string
	}{
		"pending":    {WaitRevertPending, "revert pending: the revert merge request is not merged yet"},
		"callfailed": {WaitRevertFailed, "the revert call failed"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %d items", got, len(want))
	}
	for _, it := range got {
		w, ok := want[it.ID]
		if !ok || w.kind != it.Kind || w.reason != it.Reason {
			t.Fatalf("item %+v, want %+v", it, w)
		}
	}
}
