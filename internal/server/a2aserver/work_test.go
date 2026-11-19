// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"strings"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

func TestTaskIDOf_IsStableAndUnique(t *testing.T) {
	first, again, other := TaskIDOf("w1"), TaskIDOf("w1"), TaskIDOf("w2")
	if first != again || first == other {
		t.Fatal("the task id must depend on the work id only")
	}
}

func TestDepth_CountsTheA2AChain(t *testing.T) {
	work := []brain.WorkSnapshot{
		{ID: "m1/node", MissionID: "m1"},                     // a mission node, no parent
		{ID: "a", MissionID: "m1", ParentID: "task-of-node"}, // started by the node: depth 1
		{ID: "b", MissionID: "m1", ParentID: TaskIDOf("a")},  // started by a: depth 2
		{ID: "c", MissionID: "m1", ParentID: TaskIDOf("b")},  // started by b: depth 3
		{ID: "x", MissionID: "m2", ParentID: "other"},        // another mission
		{ID: "y", MissionID: "m2", ParentID: TaskIDOf("c")},  // names a task of another mission
	}
	cases := []struct {
		name, mission, caller string
		want                  int
	}{
		{"a mission node calls", "m1", "task-of-node", 0},
		{"the first A2A run calls", "m1", TaskIDOf("a"), 1},
		{"the second calls", "m1", TaskIDOf("b"), 2},
		{"the third calls", "m1", TaskIDOf("c"), 3},
		{"an unknown caller", "m1", "unknown", 0},
		{"a task of another mission does not count", "m2", TaskIDOf("c"), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Depth(work, tc.mission, tc.caller); got != tc.want {
				t.Fatalf("depth = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestDepth_StopsOnACycle(t *testing.T) {
	work := []brain.WorkSnapshot{
		{ID: "a", MissionID: "m", ParentID: TaskIDOf("b")},
		{ID: "b", MissionID: "m", ParentID: TaskIDOf("a")},
	}
	if got := Depth(work, "m", TaskIDOf("a")); got < 2 || got > 3 {
		t.Fatalf("a cycle must end, got %d", got)
	}
}

func TestWorkOf_OnlyAnA2AItemOfTheMission(t *testing.T) {
	work := []brain.WorkSnapshot{
		{ID: "node", MissionID: "m1"},
		{ID: "a", MissionID: "m1", ParentID: "p"},
	}
	if _, ok := WorkOf(work, "m1", "node"); ok {
		t.Error("a mission node is not an A2A task")
	}
	if _, ok := WorkOf(work, "m2", "a"); ok {
		t.Error("a task of another mission must not be found")
	}
	if wi, ok := WorkOf(work, "m1", "a"); !ok || wi.ID != "a" {
		t.Error("the A2A item must be found")
	}
}

func TestTaskFromWork_FollowsTheWorkState(t *testing.T) {
	cases := []struct {
		wi    brain.WorkSnapshot
		state a2a.TaskState
		msg   bool
		art   bool
	}{
		{brain.WorkSnapshot{State: brain.WorkPending}, a2a.TaskStateSubmitted, false, false},
		{brain.WorkSnapshot{State: brain.WorkRunning}, a2a.TaskStateWorking, false, false},
		{brain.WorkSnapshot{State: brain.WorkDone, Result: "ok"}, a2a.TaskStateCompleted, false, true},
		{brain.WorkSnapshot{State: brain.WorkFailed, Err: "boom"}, a2a.TaskStateFailed, true, false},
		{brain.WorkSnapshot{State: brain.WorkCanceled, Err: "stop"}, a2a.TaskStateCanceled, true, false},
		{brain.WorkSnapshot{State: brain.WorkInputRequired, Err: "which?"}, a2a.TaskStateInputRequired, true, false},
	}
	for _, tc := range cases {
		task := TaskFromWork("t1", "m1", tc.wi)
		if task.Status.State != tc.state || task.ContextID != "m1" || task.ID != "t1" {
			t.Errorf("%s: task = %+v", tc.wi.State, task)
		}
		if (task.Status.Message != nil) != tc.msg || (len(task.Artifacts) > 0) != tc.art {
			t.Errorf("%s: message %v artifacts %d", tc.wi.State, task.Status.Message != nil, len(task.Artifacts))
		}
		if tc.msg && !strings.Contains(TextOf(task.Status.Message), tc.wi.Err) {
			t.Errorf("%s: the message must hold the reason", tc.wi.State)
		}
	}
}
