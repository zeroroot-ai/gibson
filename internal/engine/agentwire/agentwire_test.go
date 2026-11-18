// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentwire

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	sdkagent "github.com/zeroroot-ai/sdk/agent"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

func newTask(t *testing.T) agent.Task {
	t.Helper()
	task := agent.NewTask("scan", "scan the host")
	task.Goal = "find the open ports"
	return task
}

func TestBuildMessage_CarriesThePinnedSkills(t *testing.T) {
	raw, err := BuildMessage(newTask(t), Run{
		MissionRunID: "mr-1", AgentRunID: "ar-1", RunNumber: 2,
		PinnedSkills: []string{"skill:triage", "skill:review"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var msg a2a.Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	got, err := sdkagent.TaskFromMessage(&msg)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"skill:triage", "skill:review"}
	if len(got.PinnedSkills) != 2 || got.PinnedSkills[0] != want[0] || got.PinnedSkills[1] != want[1] {
		t.Fatalf("pinned skills = %v, want %v", got.PinnedSkills, want)
	}
	if got.Run.MissionRunID != "mr-1" || got.Run.AgentRunID != "ar-1" || got.Run.RunNumber != 2 {
		t.Fatalf("run = %+v", got.Run)
	}
	if got.Goal != "find the open ports" {
		t.Fatalf("goal = %q", got.Goal)
	}
}

func TestBuildMessage_NoPinnedSkillsLeavesTheKeyOut(t *testing.T) {
	raw, err := BuildMessage(newTask(t), Run{})
	if err != nil {
		t.Fatal(err)
	}
	var msg a2a.Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	got, err := sdkagent.TaskFromMessage(&msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.PinnedSkills) != 0 {
		t.Fatalf("pinned skills = %v, want none", got.PinnedSkills)
	}
}

// sdkTaskJSON runs the SDK side of the wire, so the test reads what a real
// agent returns.
func sdkTaskJSON(t *testing.T, r sdkagent.Result) []byte {
	t.Helper()
	task, err := sdkagent.ResultToTask(sdkagent.Task{ID: "t1", ContextID: "c1"}, r)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseTask_ReadsDeliverablesAndTheClaudeSession(t *testing.T) {
	raw := sdkTaskJSON(t, sdkagent.Result{
		Output:          "done",
		ClaudeSessionID: "sess-7",
		Deliverables: []*jobpb.Deliverable{
			{Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST, Ref: "42", Url: "https://forge/mr/42"},
		},
		Findings: []string{"f1"},
	})
	out, err := ParseTask(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != a2a.TaskStateCompleted {
		t.Fatalf("state = %s", out.State)
	}
	if out.ClaudeSessionID != "sess-7" || len(out.Deliverables) != 1 || len(out.FindingIDs) != 1 {
		t.Fatalf("outcome = %+v", out)
	}
	// The same values reach the run result.
	if out.Result.ClaudeSessionID != "sess-7" || len(out.Result.Deliverables) != 1 {
		t.Fatalf("result = %+v", out.Result)
	}
	var d map[string]any
	if err := json.Unmarshal(out.Result.Deliverables[0], &d); err != nil || d["ref"] != "42" {
		t.Fatalf("deliverable = %s, err %v", out.Result.Deliverables[0], err)
	}
	if out.Result.Status != agent.ResultStatusCompleted {
		t.Fatalf("status = %s", out.Result.Status)
	}
}

func TestParseTask_MapsTheTaskStateToTheResultStatus(t *testing.T) {
	cases := []struct {
		name   string
		in     sdkagent.Result
		state  a2a.TaskState
		status agent.ResultStatus
	}{
		{"canceled", sdkagent.Result{Status: a2a.TaskStateCanceled}, a2a.TaskStateCanceled, agent.ResultStatusCancelled},
		{"input required", sdkagent.Result{Status: a2a.TaskStateInputRequired, Output: "which host?"},
			a2a.TaskStateInputRequired, agent.ResultStatusFailed},
		{"failed", sdkagent.Result{ErrorInfo: &sdkagent.ResultError{Code: "E1", Message: "boom"}},
			a2a.TaskStateFailed, agent.ResultStatusFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ParseTask(sdkTaskJSON(t, tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if out.State != tc.state || out.Result.Status != tc.status {
				t.Fatalf("state %s status %s, want %s %s", out.State, out.Result.Status, tc.state, tc.status)
			}
			if out.Result.Error == nil || out.Result.Error.Message == "" {
				t.Fatalf("a stopped run needs a message, got %+v", out.Result.Error)
			}
		})
	}
}

func TestParseTask_RefusesBadJSON(t *testing.T) {
	if _, err := ParseTask([]byte("{")); err == nil {
		t.Fatal("want an error")
	}
}

func TestStateError_IsFoundThroughAWrap(t *testing.T) {
	err := types.WrapError("x", "wrapped", &StateError{State: a2a.TaskStateInputRequired, Message: "ask"})
	var se *StateError
	if !errors.As(err, &se) || se.State != a2a.TaskStateInputRequired || se.Message != "ask" {
		t.Fatalf("got %v", se)
	}
	if se.Error() == "" {
		t.Fatal("empty error text")
	}
}
