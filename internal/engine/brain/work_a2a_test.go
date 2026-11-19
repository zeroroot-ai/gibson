// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

func TestWorkStateFromTask_EachTaskState(t *testing.T) {
	cases := map[a2a.TaskState]WorkState{
		a2a.TaskStateSubmitted:     WorkPending,
		a2a.TaskStateWorking:       WorkRunning,
		a2a.TaskStateCompleted:     WorkDone,
		a2a.TaskStateFailed:        WorkFailed,
		a2a.TaskStateRejected:      WorkFailed,
		a2a.TaskStateCanceled:      WorkCanceled,
		a2a.TaskStateInputRequired: WorkInputRequired,
		a2a.TaskStateAuthRequired:  WorkInputRequired,
		a2a.TaskStateUnspecified:   WorkFailed,
	}
	for state, want := range cases {
		if got := WorkStateFromTask(state); got != want {
			t.Errorf("WorkStateFromTask(%q) = %v, want %v", state, got, want)
		}
	}
}

func TestTaskStateFromWork_EachWorkState(t *testing.T) {
	cases := map[WorkState]a2a.TaskState{
		WorkPending:       a2a.TaskStateSubmitted,
		WorkRunning:       a2a.TaskStateWorking,
		WorkDone:          a2a.TaskStateCompleted,
		WorkSkipped:       a2a.TaskStateCanceled,
		WorkFailed:        a2a.TaskStateFailed,
		WorkCanceled:      a2a.TaskStateCanceled,
		WorkInputRequired: a2a.TaskStateInputRequired,
	}
	for state, want := range cases {
		if got := TaskStateFromWork(state); got != want {
			t.Errorf("TaskStateFromWork(%v) = %q, want %q", state, got, want)
		}
	}
}

// A task state that stops the run, with or without an answer, never comes back
// as completed, so the round trip never turns a stop into a success.
func TestWorkStateRoundTrip_NeverTurnsAFailureIntoASuccess(t *testing.T) {
	for _, state := range []a2a.TaskState{
		a2a.TaskStateFailed, a2a.TaskStateRejected, a2a.TaskStateCanceled,
		a2a.TaskStateInputRequired, a2a.TaskStateAuthRequired, a2a.TaskStateUnspecified,
	} {
		if got := TaskStateFromWork(WorkStateFromTask(state)); got == a2a.TaskStateCompleted {
			t.Errorf("state %q came back as completed", state)
		}
	}
}

// A canceled run and a run that waits for input keep their A2A state through
// the work item. An A2A client cannot tell input from auth, so auth comes back
// as input-required.
func TestWorkStateRoundTrip_KeepsCanceledAndInputRequired(t *testing.T) {
	cases := map[a2a.TaskState]a2a.TaskState{
		a2a.TaskStateCanceled:      a2a.TaskStateCanceled,
		a2a.TaskStateInputRequired: a2a.TaskStateInputRequired,
		a2a.TaskStateAuthRequired:  a2a.TaskStateInputRequired,
	}
	for in, want := range cases {
		if got := TaskStateFromWork(WorkStateFromTask(in)); got != want {
			t.Errorf("state %q came back as %q, want %q", in, got, want)
		}
	}
}

// The Task state is the mission state. Paused is the one state with no A2A name,
// and it shows as working.
func TestTaskStateFromMission_EachMissionState(t *testing.T) {
	cases := map[MissionStatus]a2a.TaskState{
		MissionSubmitted:     a2a.TaskStateSubmitted,
		MissionWorking:       a2a.TaskStateWorking,
		MissionPaused:        a2a.TaskStateWorking,
		MissionInputRequired: a2a.TaskStateInputRequired,
		MissionCompleted:     a2a.TaskStateCompleted,
		MissionFailed:        a2a.TaskStateFailed,
		MissionCanceled:      a2a.TaskStateCanceled,
		MissionStatus("???"): a2a.TaskStateFailed,
	}
	for state, want := range cases {
		if got := TaskStateFromMission(state); got != want {
			t.Errorf("TaskStateFromMission(%q) = %q, want %q", state, got, want)
		}
	}
}
