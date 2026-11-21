// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintest

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// The bounded read of the in-memory store keeps the events of the kinds named
// whose time is the start time or later, and an event with no time (review M6).
func TestMemTimelineStore_LoadHistoryRange(t *testing.T) {
	s := NewMemTimelineStore()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	for i, ev := range []brain.Event{
		brain.FixReverted{MergeRequest: "old", At: t0},
		brain.FixReverted{MergeRequest: "new", At: t0.Add(2 * time.Hour)},
		brain.ScanReconciled{MissionID: "no-time"},
		brain.MergeRequestObserved{Key: "other-kind", At: t0.Add(3 * time.Hour)},
	} {
		if _, err := s.Append(ctx, "t", string(rune('a'+i)), ev); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.LoadHistoryRange(ctx, "t", t0.Add(time.Hour), []string{"fix.reverted", "scan.reconciled"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].(brain.FixReverted).MergeRequest != "new" || got[1].Kind() != "scan.reconciled" {
		t.Fatalf("range = %+v", got)
	}
}

// The count before a time leaves out an event with no time, as the range
// keeps it (review R5).
func TestMemTimelineStore_CountHistoryBefore(t *testing.T) {
	s := NewMemTimelineStore()
	ctx := context.Background()
	t0 := time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)
	for i, ev := range []brain.Event{
		brain.FixReverted{MergeRequest: "old", At: t0},
		brain.ScanReconciled{MissionID: "no-time"},
		brain.FixReverted{MergeRequest: "new", At: t0.Add(2 * time.Hour)},
	} {
		if _, err := s.Append(ctx, "t", string(rune('a'+i)), ev); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.CountHistoryBefore(ctx, "t", t0.Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("count = %d, %v, want 1", n, err)
	}
}
