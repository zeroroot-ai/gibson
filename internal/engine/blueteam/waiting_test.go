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
		{ID: "refused", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", FixFacts: brain.FixFacts{FixHeadSHA: "aaaa"}},
		{ID: "scan", Status: brain.FindingStatusFixed,
			FixFacts: brain.FixFacts{CheckKind: "tool", DeployedAt: at(2)}},
		{ID: "nohealth", Status: brain.FindingStatusFixed,
			FixFacts: brain.FixFacts{CheckKind: "scan", DeployedAt: at(1), HealthUnavailableAt: at(3)}},
		{ID: "quiet", Status: brain.FindingStatusFixing, MergeRequest: "mr-2", FixFacts: brain.FixFacts{FixHeadSHA: "aaaa"}},
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
	findings := []brain.FindingSnapshot{{ID: "f", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", FixFacts: brain.FixFacts{FixHeadSHA: "aaaa"}}}
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
	findings := []brain.FindingSnapshot{{ID: "f", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", FixFacts: brain.FixFacts{FixHeadSHA: "aaaa"}}}
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
		{ID: "unreadable", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", FixFacts: brain.FixFacts{FixHeadSHA: "aaaa"}},
		{ID: "noverdict", Status: brain.FindingStatusFixed, MergeRequest: "mr-2",
			FixFacts: brain.FixFacts{CheckKind: "scan", DeployedAt: at(1)}},
		{ID: "verdict", Status: brain.FindingStatusFixed, MergeRequest: "mr-3",
			FixFacts: brain.FixFacts{CheckKind: "scan", DeployedAt: at(1), Health: brain.HealthHeld}},
		{ID: "ended", Status: brain.FindingStatusFixing, MergeRequest: "mr-4", FixFacts: brain.FixFacts{FixHeadSHA: "aaaa"}},
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

// A fixed finding whose hold the daemon could not read shows as its own item with
// its own reason, until the health verdict ends it.
func TestWaitingOnPerson_HoldUnreadable(t *testing.T) {
	const reason = "the hold of the fix mission cannot be read"
	findings := []brain.FindingSnapshot{
		{ID: "open", Status: brain.FindingStatusFixed, MergeRequest: "mr-1",
			FixFacts: brain.FixFacts{CheckKind: "scan", DeployedAt: at(1)}},
		{ID: "ended", Status: brain.FindingStatusFixed, MergeRequest: "mr-2",
			FixFacts: brain.FixFacts{CheckKind: "scan", DeployedAt: at(1), Health: brain.HealthHeld}},
	}
	history := []brain.Event{
		brain.FixWaiting{MergeRequest: "mr-1", WaitKind: brain.WaitHoldUnreadable, Reason: reason, Waiting: true, At: at(2)},
		brain.FixWaiting{MergeRequest: "mr-2", WaitKind: brain.WaitHoldUnreadable, Reason: reason, Waiting: true, At: at(2)},
	}
	got := WaitingOnPerson(findings, nil, history, at(5))
	if len(got) != 1 || got[0].ID != "open" || got[0].Kind != WaitHoldUnreadable || got[0].Reason != reason {
		t.Fatalf("got %+v, want one hold_unreadable item for the open finding", got)
	}
}

func TestWaitingOnPerson_NoFixHead(t *testing.T) {
	findings := []brain.FindingSnapshot{
		{ID: "nohead", Status: brain.FindingStatusFixing, MergeRequest: "mr-1",
			FixFacts: brain.FixFacts{FixHeadMissingAt: at(2), FixHeadMissingReason: "the head moved"}},
		{ID: "head", Status: brain.FindingStatusFixing, MergeRequest: "mr-2",
			FixFacts: brain.FixFacts{FixHeadSHA: "aaaa", FixHeadMissingAt: at(2), FixHeadMissingReason: "old"}},
	}
	got := WaitingOnPerson(findings, nil, nil, at(5))
	if len(got) != 1 || got[0].ID != "nohead" || got[0].Kind != WaitNoFixHead || got[0].Reason != "the head moved" {
		t.Fatalf("got %+v, want one no_fix_head item", got)
	}
}

func TestWaitingOnPerson_NoFixHeadWithNoReason(t *testing.T) {
	findings := []brain.FindingSnapshot{
		{ID: "linked", Status: brain.FindingStatusFixing, MergeRequest: "mr-1"},
		{ID: "unlinked", Status: brain.FindingStatusFixing},
	}
	history := []brain.Event{
		brain.FindingStatusChanged{ID: "linked", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", At: at(2)},
	}
	got := WaitingOnPerson(findings, nil, history, at(5))
	if len(got) != 1 || got[0].ID != "linked" || got[0].Kind != WaitNoFixHead ||
		got[0].Reason != "no fix head was recorded" || !got[0].Since.Equal(at(2)) {
		t.Fatalf("got %+v, want one no_fix_head item for the linked finding, since the link", got)
	}
}

// A finding with a place block waits on a person from the time of the event, with
// the text of the block as the reason. A later event with no reason ends the wait,
// and a finding with no block has no such item.
func TestWaitingOnPerson_NoSingleApplication(t *testing.T) {
	reason := "waiting on a person: this finding affects more than one Application: app-a, app-b"
	findings := []brain.FindingSnapshot{
		{ID: "blocked", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", PlaceBlock: reason},
		{ID: "cleared", Status: brain.FindingStatusFixing, MergeRequest: "mr-2"},
	}
	history := []brain.Event{
		brain.FindingPlaceBlocked{ID: "blocked", Reason: reason, At: at(1)},
		brain.FindingPlaceBlocked{ID: "cleared", Reason: reason, At: at(1)},
		brain.FindingPlaceBlocked{ID: "cleared", Reason: "", At: at(2)},
	}
	var got []WaitItem
	for _, it := range WaitingOnPerson(findings, nil, history, at(5)) {
		if it.Kind == WaitNoSingleApplication {
			got = append(got, it)
		}
	}
	if len(got) != 1 || got[0].ID != "blocked" || got[0].Reason != reason || got[0].Waited != 4*time.Hour {
		t.Fatalf("got %+v, want one item for the blocked finding, since the event", got)
	}
}

// A finding with a place block shows the wait when the history read holds no
// event for it. The wait starts at the last known time of the finding, else now.
func TestWaitingOnPerson_NoSingleApplicationShowsWithShortHistory(t *testing.T) {
	findings := []brain.FindingSnapshot{
		{ID: "known", Status: brain.FindingStatusFixing, PlaceBlock: "waiting on a person: x",
			FixFacts: brain.FixFacts{DeployedAt: at(2)}},
		{ID: "unknown", Status: brain.FindingStatusFixing, PlaceBlock: "waiting on a person: y"},
	}
	got := map[string]WaitItem{}
	for _, it := range WaitingOnPerson(findings, nil, nil, at(5)) {
		got[it.ID] = it
	}
	if k := got["known"]; k.Kind != WaitNoSingleApplication || k.Waited != 3*time.Hour {
		t.Errorf("known = %+v, want the wait since the last known time", k)
	}
	if u := got["unknown"]; u.Kind != WaitNoSingleApplication || u.Waited != 0 || u.Reason != "waiting on a person: y" {
		t.Errorf("unknown = %+v, want the wait since now", u)
	}
}

// A verified finding with a stale block shows no wait.
func TestWaitingOnPerson_VerifiedFindingWithStaleBlockShowsNoWait(t *testing.T) {
	got := WaitingOnPerson([]brain.FindingSnapshot{
		{ID: "v", Status: brain.FindingStatusVerified, PlaceBlock: "waiting on a person: x"},
	}, nil, nil, at(5))
	if len(got) != 0 {
		t.Fatalf("got %+v, want no wait", got)
	}
}

// A linked fix with no head, whose link event is older than the history window and
// whose claim time is zero, still shows its wait. The time falls back to the time that
// the finding holds for its merge request, and then to now.
func TestWaitingOnPerson_NoFixHeadFallsBackWhenTheHistoryIsGone(t *testing.T) {
	findings := []brain.FindingSnapshot{
		{ID: "has-link-time", Status: brain.FindingStatusFixing, MergeRequest: "mr-1", FixFacts: brain.FixFacts{LinkedAt: at(2)}},
		{ID: "nothing", Status: brain.FindingStatusFixing, MergeRequest: "mr-2"},
	}

	got := WaitingOnPerson(findings, nil, nil, at(5)) // no history: the link event is gone

	if len(got) != 2 {
		t.Fatalf("got %+v, want a wait for each finding", got)
	}
	byID := map[string]WaitItem{}
	for _, it := range got {
		byID[it.ID] = it
	}
	if it := byID["has-link-time"]; it.Kind != WaitNoFixHead || !it.Since.Equal(at(2)) {
		t.Errorf("has-link-time = %+v, want since the time of the finding", it)
	}
	if it := byID["nothing"]; it.Kind != WaitNoFixHead || !it.Since.Equal(at(5)) || it.Waited != 0 {
		t.Errorf("nothing = %+v, want since now", it)
	}
}
