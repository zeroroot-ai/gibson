// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// A run that the World holds as ended reads as ended in the history, although
// the run store still says "running" (gibson#1340).
func TestOverlayRunsFromWorld(t *testing.T) {
	runs := []api.MissionRunData{
		{RunID: "run-failed", Status: "running"},
		{RunID: "run-done", Status: "running", Error: "stale"},
		{RunID: "run-live", Status: "running"},
		{RunID: "run-unknown", Status: "running", Progress: 0.4},
	}
	snaps := []brain.MissionSnapshot{
		{ID: "m1", RunID: "run-failed", Status: brain.MissionFailed, Reason: "brain stopped", Progress: 0.5, FindingsCount: 2},
		{ID: "m1", RunID: "run-done", Status: brain.MissionCompleted, Progress: 1, FindingsCount: 7},
		{ID: "m1", RunID: "run-live", Status: brain.MissionRunning, Progress: 0.25},
		{ID: "m2", RunID: "", Status: brain.MissionCompleted},
	}
	overlayRunsFromWorld(runs, snaps)

	want := []api.MissionRunData{
		{RunID: "run-failed", Status: "failed", Error: "brain stopped", Progress: 0.5, FindingsCount: 2},
		{RunID: "run-done", Status: "completed", Error: "", Progress: 1, FindingsCount: 7},
		{RunID: "run-live", Status: "running", Progress: 0.25},
		{RunID: "run-unknown", Status: "running", Progress: 0.4},
	}
	for i := range want {
		if runs[i] != want[i] {
			t.Errorf("run %s: got %+v, want %+v", want[i].RunID, runs[i], want[i])
		}
	}
}

// With no snapshot at all the history keeps what the store holds.
func TestOverlayRunsFromWorld_NoSnapshots(t *testing.T) {
	runs := []api.MissionRunData{{RunID: "r", Status: "running"}}
	overlayRunsFromWorld(runs, nil)
	if runs[0].Status != "running" {
		t.Errorf("status = %q, want the stored status", runs[0].Status)
	}
}

// A mission that ran twice holds one snapshot, the one of the newest run. The
// earlier run, which the store still holds as "running", has ended, so it does
// not read "running". A run that the store holds as ended keeps its status.
func TestOverlayRunsFromWorld_EarlierRunOfAMissionThatRanAgain(t *testing.T) {
	runs := []api.MissionRunData{
		{RunID: "run-2", MissionID: "m1", Status: "running"},
		{RunID: "run-1", MissionID: "m1", Status: "running"},
		{RunID: "run-0", MissionID: "m1", Status: "failed", Error: "old"},
		{RunID: "other", MissionID: "m2", Status: "running"},
	}
	snaps := []brain.MissionSnapshot{
		{ID: "m1", RunID: "run-2", Status: brain.MissionRunning, Progress: 0.1},
	}
	overlayRunsFromWorld(runs, snaps)

	got := []string{runs[0].Status, runs[1].Status, runs[2].Status, runs[3].Status}
	want := []string{"running", StatusRunUnknown, "failed", "running"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("run %s: status %q, want %q", runs[i].RunID, got[i], want[i])
		}
	}
	if runs[2].Error != "old" {
		t.Errorf("an ended run lost its error: %q", runs[2].Error)
	}
}
