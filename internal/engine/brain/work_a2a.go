// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "github.com/a2aproject/a2a-go/v2/a2a"

// WorkStateFromTask maps the state of an A2A Task to the state of a WorkItem.
// It is the one place that does this mapping (owner decision 16: an agent run
// takes its Task state from its WorkItem).
//
// A WorkItem has no state for a canceled task or a task that waits for input.
// Both end the work item as failed. The text of the Task status message goes
// in WorkItem.Err, so the reason stays visible.
func WorkStateFromTask(s a2a.TaskState) WorkState {
	switch s {
	case a2a.TaskStateCompleted:
		return WorkDone
	case a2a.TaskStateSubmitted:
		return WorkPending
	case a2a.TaskStateWorking:
		return WorkRunning
	default:
		// failed, rejected, canceled, input-required, auth-required, unspecified
		return WorkFailed
	}
}

// TaskStateFromWork maps the state of a WorkItem to the A2A Task state that
// GetTask reports. A skipped item was never run, so it is canceled.
func TaskStateFromWork(s WorkState) a2a.TaskState {
	switch s {
	case WorkDone:
		return a2a.TaskStateCompleted
	case WorkPending:
		return a2a.TaskStateSubmitted
	case WorkRunning:
		return a2a.TaskStateWorking
	case WorkSkipped:
		return a2a.TaskStateCanceled
	default:
		return a2a.TaskStateFailed
	}
}
