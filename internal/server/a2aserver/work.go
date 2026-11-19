// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/google/uuid"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// taskNamespace is the UUID namespace of the task id of A2A work.
var taskNamespace = uuid.MustParse("0b7c61a4-5d1e-4c58-9f0e-3a7d2e9b8c41")

// TaskIDOf returns the task id of an A2A work item. The task grant of the work
// carries it, so a later A2A call from that work names its parent by it. The id
// depends only on the work id.
func TaskIDOf(workID string) string {
	return uuid.NewSHA1(taskNamespace, []byte(workID)).String()
}

// Depth returns the delegation depth of the caller. The caller names its own
// task. A task that is not the task of an A2A work item belongs to a mission
// node, which has depth 0. A run that an A2A message started has the depth of
// its parent plus 1. The depth of a new run is this value, and the limit
// applies to it.
func Depth(work []brain.WorkSnapshot, missionID, callerTask string) int {
	byTask := make(map[string]brain.WorkSnapshot, len(work))
	for _, wi := range work {
		if wi.MissionID == missionID && wi.ParentID != "" {
			byTask[TaskIDOf(wi.ID)] = wi
		}
	}
	depth := 0
	task := callerTask
	// The loop ends at a task that is not an A2A run. The bound stops a cycle in
	// the data, which should not exist.
	for i := 0; i <= len(work); i++ {
		wi, ok := byTask[task]
		if !ok {
			return depth
		}
		depth++
		task = wi.ParentID
	}
	return depth
}

// WorkOf finds the A2A work item of a mission. A mission node is not an A2A
// task, so an item with no parent is not found.
func WorkOf(work []brain.WorkSnapshot, missionID, id string) (brain.WorkSnapshot, bool) {
	for _, wi := range work {
		if wi.ID == id && wi.MissionID == missionID && wi.ParentID != "" {
			return wi, true
		}
	}
	return brain.WorkSnapshot{}, false
}

// TaskFromWork renders a work item as an A2A Task. The context of the task is
// the mission. The state of the Task comes from the state of the work item
// (owner decision 16).
func TaskFromWork(id, missionID string, wi brain.WorkSnapshot) *a2a.Task {
	t := &a2a.Task{
		ID:        a2a.TaskID(id),
		ContextID: missionID,
		Status:    a2a.TaskStatus{State: brain.TaskStateFromWork(wi.State)},
	}
	now := time.Now().UTC()
	t.Status.Timestamp = &now
	switch wi.State {
	case brain.WorkFailed, brain.WorkCanceled, brain.WorkInputRequired:
		if wi.Err != "" {
			t.Status.Message = a2a.NewMessageForTask(a2a.MessageRoleAgent, t, a2a.NewTextPart(wi.Err))
		}
	case brain.WorkPending, brain.WorkRunning, brain.WorkSkipped:
		// These states have no message and no artifact.
	case brain.WorkDone:
		if wi.Result != "" {
			t.Artifacts = []*a2a.Artifact{{
				ID: a2a.NewArtifactID(), Name: "output", Parts: a2a.ContentParts{a2a.NewTextPart(wi.Result)},
			}}
		}
	}
	return t
}
