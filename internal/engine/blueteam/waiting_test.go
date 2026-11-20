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
