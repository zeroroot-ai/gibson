// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "github.com/a2aproject/a2a-go/v2/a2a"

// WorkStateFromTask maps the state of an A2A Task to the state of a WorkItem.
// It is the one place that does this mapping (owner decision 16: an agent run
// takes its Task state from its WorkItem).
//
// canceled maps to canceled. input-required and auth-required map to
// input_required. rejected maps to failed. The text of the Task status message
// goes in the Err field of the work item, so the reason stays visible.
func WorkStateFromTask(s a2a.TaskState) WorkState {
	switch s {
	case a2a.TaskStateCompleted:
		return WorkDone
	case a2a.TaskStateSubmitted:
		return WorkPending
	case a2a.TaskStateWorking:
		return WorkRunning
	case a2a.TaskStateCanceled:
		return WorkCanceled
	case a2a.TaskStateInputRequired, a2a.TaskStateAuthRequired:
		return WorkInputRequired
	case a2a.TaskStateFailed, a2a.TaskStateRejected, a2a.TaskStateUnspecified:
		// These states map to failed.
	}
	return WorkFailed
}

// TaskStateFromWork maps the state of a WorkItem to the A2A Task state that
// GetTask reports. A skipped item was never run, so it is canceled. The state
// input_required maps to input-required. An A2A client cannot tell input from
// auth, so the daemon reports the first.
func TaskStateFromWork(s WorkState) a2a.TaskState {
	switch s {
	case WorkDone:
		return a2a.TaskStateCompleted
	case WorkPending:
		return a2a.TaskStateSubmitted
	case WorkRunning:
		return a2a.TaskStateWorking
	case WorkSkipped, WorkCanceled:
		return a2a.TaskStateCanceled
	case WorkInputRequired:
		return a2a.TaskStateInputRequired
	case WorkFailed:
		// A failed item reports the failed state.
	}
	return a2a.TaskStateFailed
}

// TaskStateFromMission maps the state of a mission to the A2A Task state that an
// inbound caller reads (ADR-0175). The names of the mission states are the names
// of the A2A Task states, so the Task state is the mission state. One state has
// no A2A name: a paused mission shows as working, because the mission is not
// finished and a caller can do nothing about the pause.
func TaskStateFromMission(s MissionStatus) a2a.TaskState {
	switch s {
	case MissionSubmitted:
		return a2a.TaskStateSubmitted
	case MissionWorking, MissionPaused:
		return a2a.TaskStateWorking
	case MissionInputRequired:
		return a2a.TaskStateInputRequired
	case MissionCompleted:
		return a2a.TaskStateCompleted
	case MissionCanceled:
		return a2a.TaskStateCanceled
	case MissionFailed:
		// A failed mission reports the failed state.
	}
	return a2a.TaskStateFailed
}
