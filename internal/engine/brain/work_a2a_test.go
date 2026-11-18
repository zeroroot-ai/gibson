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
		a2a.TaskStateCanceled:      WorkFailed,
		a2a.TaskStateInputRequired: WorkFailed,
		a2a.TaskStateAuthRequired:  WorkFailed,
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
		WorkPending: a2a.TaskStateSubmitted,
		WorkRunning: a2a.TaskStateWorking,
		WorkDone:    a2a.TaskStateCompleted,
		WorkSkipped: a2a.TaskStateCanceled,
		WorkFailed:  a2a.TaskStateFailed,
	}
	for state, want := range cases {
		if got := TaskStateFromWork(state); got != want {
			t.Errorf("TaskStateFromWork(%v) = %q, want %q", state, got, want)
		}
	}
}

// A state that a WorkItem cannot hold ends the work item as failed. Mapping it
// back gives failed, so the round trip never turns a failure into a success.
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
