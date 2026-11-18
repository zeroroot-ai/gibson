// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package agentwire

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	sdkagent "github.com/zeroroot-ai/sdk/agent"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

func testTask() agent.Task {
	task := agent.NewTask("probe", "Find open ports")
	task.Goal = "Find open ports on the target"
	task.Timeout = 90 * time.Second
	task.Context = map[string]any{"phase": "recon"}
	mission, parent, target := types.NewID(), types.NewID(), types.NewID()
	task.MissionID, task.ParentTaskID, task.TargetID = &mission, &parent, &target
	return task
}

// decodeEnvelope reads the Gibson extension of a message back to the SDK type.
func decodeEnvelope(t *testing.T, msg a2a.Message) sdkagent.Envelope {
	t.Helper()
	raw, ok := msg.Metadata[sdkagent.ExtensionKey]
	if !ok {
		t.Fatalf("the message has no extension under %q", sdkagent.ExtensionKey)
	}
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("encode the extension: %v", err)
	}
	var env sdkagent.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("decode the extension: %v", err)
	}
	return env
}

func TestBuildMessage_RoundTripsThroughTheSDKWithTheExtensionMetadata(t *testing.T) {
	task := testTask()
	run := Run{
		MissionRunID: "run-7", AgentRunID: "agent-run-3", RunNumber: 2, JobID: "job-1",
		TraceID: "trace-1", ParentSpanID: "span-1", PinnedSkills: []string{"skill:web-recon"},
		Job: json.RawMessage(`{"goal":"fix the bug"}`),
	}

	raw, err := BuildMessage(task, run)
	if err != nil {
		t.Fatalf("BuildMessage: %v", err)
	}

	var msg a2a.Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatalf("the payload is not an a2a message: %v", err)
	}
	if string(msg.TaskID) != task.ID.String() {
		t.Errorf("task id = %q, want %q", msg.TaskID, task.ID)
	}
	if msg.ContextID != task.ID.String() {
		t.Errorf("context id = %q, want the task id when the run names none", msg.ContextID)
	}
	if msg.Role != a2a.MessageRoleUser {
		t.Errorf("role = %q, want user", msg.Role)
	}
	if got := msg.Parts[0].Text(); got != task.Goal {
		t.Errorf("text = %q, want the goal %q", got, task.Goal)
	}

	env := decodeEnvelope(t, msg)
	if env.MissionRunID != "run-7" || env.AgentRunID != "agent-run-3" || env.RunNumber != 2 || env.JobID != "job-1" {
		t.Errorf("run context = %+v", env.RunContext)
	}
	if env.TraceID != "trace-1" || env.ParentSpanID != "span-1" {
		t.Errorf("trace = %q/%q", env.TraceID, env.ParentSpanID)
	}
	if len(env.PinnedSkills) != 1 || env.PinnedSkills[0] != "skill:web-recon" {
		t.Errorf("pinned skills = %v", env.PinnedSkills)
	}
	if env.Context["phase"] != "recon" {
		t.Errorf("context = %v", env.Context)
	}
	if string(env.Job) != `{"goal":"fix the bug"}` {
		t.Errorf("job = %s", env.Job)
	}
	wantMeta := map[string]any{
		"name": "probe", "mission_id": task.MissionID.String(), "parent_task_id": task.ParentTaskID.String(),
		"target_id": task.TargetID.String(), "timeout_ms": float64(90000),
	}
	for k, want := range wantMeta {
		if env.Metadata[k] != want {
			t.Errorf("metadata[%s] = %v, want %v", k, env.Metadata[k], want)
		}
	}

	// The SDK reads the same payload back as the Task of an agent author.
	got, err := sdkagent.TaskFromMessage(&msg)
	if err != nil {
		t.Fatalf("the SDK refused the message: %v", err)
	}
	if got.ID != task.ID.String() || got.Goal != task.Goal || got.Run.MissionRunID != "run-7" {
		t.Errorf("SDK task = %+v", got)
	}
	if got.Job == nil || got.Job.GetGoal() != "fix the bug" {
		t.Errorf("SDK job = %+v, want the job of the run", got.Job)
	}
}

func TestBuildMessage_TheTextFallsBackFromGoalToDescriptionToName(t *testing.T) {
	cases := map[string]struct {
		goal, description, name, want string
	}{
		"goal":        {"the goal", "the description", "the name", "the goal"},
		"description": {"", "the description", "the name", "the description"},
		"name":        {"", "", "the name", "the name"},
	}
	for label, tc := range cases {
		task := agent.NewTask(tc.name, tc.description)
		task.Goal = tc.goal
		raw, err := BuildMessage(task, Run{})
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		var msg a2a.Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if got := msg.Parts[0].Text(); got != tc.want {
			t.Errorf("%s: text = %q, want %q", label, got, tc.want)
		}
	}
}

func TestBuildMessage_ANamedContextIsKept(t *testing.T) {
	raw, err := BuildMessage(testTask(), Run{ContextID: "ctx-9"})
	if err != nil {
		t.Fatalf("BuildMessage: %v", err)
	}
	var msg a2a.Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		t.Fatal(err)
	}
	if msg.ContextID != "ctx-9" {
		t.Errorf("context id = %q, want ctx-9", msg.ContextID)
	}
}

func TestBuildMessage_ATaskWithNoIDIsRefused(t *testing.T) {
	task := testTask()
	task.ID = types.ID("")

	if _, err := BuildMessage(task, Run{}); err == nil {
		t.Fatal("a task with no id was accepted")
	}
}

func TestBuildMessage_ABadJobIsRefused(t *testing.T) {
	if _, err := BuildMessage(testTask(), Run{Job: json.RawMessage(`{not json`)}); err == nil {
		t.Fatal("a job that is not JSON was accepted")
	}
}

// taskJSON builds the JSON of a Task in the given state.
func taskJSON(t *testing.T, state a2a.TaskState, mutate func(*a2a.Task)) []byte {
	t.Helper()
	task := &a2a.Task{ID: a2a.NewTaskID(), ContextID: "ctx", Status: a2a.TaskStatus{State: state}}
	if mutate != nil {
		mutate(task)
	}
	b, err := json.Marshal(task)
	if err != nil {
		t.Fatalf("encode the task: %v", err)
	}
	return b
}

func TestParseTask_EachStateGivesItsResultStatusAndWorkState(t *testing.T) {
	cases := []struct {
		state    a2a.TaskState
		status   agent.ResultStatus
		work     brain.WorkState
		hasError bool
	}{
		{a2a.TaskStateCompleted, agent.ResultStatusCompleted, brain.WorkDone, false},
		{a2a.TaskStateCanceled, agent.ResultStatusCancelled, brain.WorkCanceled, true},
		{a2a.TaskStateFailed, agent.ResultStatusFailed, brain.WorkFailed, true},
		{a2a.TaskStateRejected, agent.ResultStatusFailed, brain.WorkFailed, true},
		{a2a.TaskStateInputRequired, agent.ResultStatusFailed, brain.WorkInputRequired, true},
		{a2a.TaskStateAuthRequired, agent.ResultStatusFailed, brain.WorkInputRequired, true},
	}
	for _, tc := range cases {
		t.Run(string(tc.state), func(t *testing.T) {
			out, err := ParseTask(taskJSON(t, tc.state, nil))
			if err != nil {
				t.Fatalf("ParseTask: %v", err)
			}
			if out.State != tc.state {
				t.Errorf("state = %q", out.State)
			}
			if out.Result.Status != tc.status {
				t.Errorf("result status = %q, want %q", out.Result.Status, tc.status)
			}
			if got := brain.WorkStateFromTask(out.State); got != tc.work {
				t.Errorf("work state = %v, want %v", got, tc.work)
			}
			if (out.Result.Error != nil) != tc.hasError {
				t.Errorf("result error = %+v, want error: %v", out.Result.Error, tc.hasError)
			}
		})
	}
}

func TestParseTask_AFailedTaskCarriesTheStructuredErrorOfTheExtension(t *testing.T) {
	raw := taskJSON(t, a2a.TaskStateFailed, func(task *a2a.Task) {
		task.Status.Message = a2a.NewMessageForTask(a2a.MessageRoleAgent, task, a2a.NewTextPart("the text of the status"))
		task.SetMeta(sdkagent.ExtensionKey, sdkagent.ResultEnvelope{
			Error:           &sdkagent.ResultError{Code: "TOOL_MISSING", Message: "no http tool"},
			ClaudeSessionID: "sess-1",
			FindingIDs:      []string{"f1", "f2"},
			Metadata:        map[string]any{"turns": 3},
			Deliverables:    []json.RawMessage{json.RawMessage(`{"name":"report"}`)},
		})
	})

	out, err := ParseTask(raw)
	if err != nil {
		t.Fatalf("ParseTask: %v", err)
	}

	if out.Error == nil || out.Error.Code != "TOOL_MISSING" {
		t.Errorf("error = %+v", out.Error)
	}
	if out.Result.Error == nil || out.Result.Error.Code != "TOOL_MISSING" || out.Result.Error.Message != "no http tool" {
		t.Errorf("result error = %+v, want the structured error to win over the status text", out.Result.Error)
	}
	if out.Message != "the text of the status" {
		t.Errorf("message = %q", out.Message)
	}
	if out.ClaudeSessionID != "sess-1" || len(out.FindingIDs) != 2 || len(out.Deliverables) != 1 {
		t.Errorf("extension fields = %+v", out)
	}
	if out.Result.Output["turns"] != float64(3) {
		t.Errorf("output = %v, want the metadata of the extension", out.Result.Output)
	}
}

func TestParseTask_AFailedTaskWithNoTextGetsAStateMessage(t *testing.T) {
	out, err := ParseTask(taskJSON(t, a2a.TaskStateCanceled, nil))
	if err != nil {
		t.Fatalf("ParseTask: %v", err)
	}
	if out.Result.Error == nil || !strings.Contains(out.Result.Error.Message, string(a2a.TaskStateCanceled)) {
		t.Errorf("error = %+v, want a message that names the state", out.Result.Error)
	}
}

func TestParseTask_ArtifactsGiveTheOutput(t *testing.T) {
	raw := taskJSON(t, a2a.TaskStateCompleted, func(task *a2a.Task) {
		task.Artifacts = []*a2a.Artifact{
			{ID: "a1", Name: "report", Parts: a2a.ContentParts{a2a.NewTextPart("line one"), a2a.NewTextPart("line two")}},
			{ID: "a2", Parts: a2a.ContentParts{a2a.NewTextPart("unnamed")}},
			nil,
		}
	})

	out, err := ParseTask(raw)
	if err != nil {
		t.Fatalf("ParseTask: %v", err)
	}
	if out.Result.Output["report"] != "line one\nline two" {
		t.Errorf("output[report] = %v", out.Result.Output["report"])
	}
	if out.Result.Output["a2"] != "unnamed" {
		t.Errorf("output[a2] = %v, want the artifact id for an artifact with no name", out.Result.Output["a2"])
	}
}

// withExtension builds the JSON of a completed Task that holds the given value
// under the Gibson extension key.
func withExtension(value string) string {
	return `{"id":"t","contextId":"c","status":{"state":"completed"},"metadata":{"` +
		sdkagent.ExtensionKey + `":` + value + `}}`
}

func TestParseTask_BadPayloads(t *testing.T) {
	cases := map[string]string{
		"not json":           `{"id": `,
		"an array":           `[1,2]`,
		"a bad extension":    withExtension(`"text"`),
		"a bad finding list": withExtension(`{"finding_ids":"x"}`),
	}
	for name, raw := range cases {
		if _, err := ParseTask([]byte(raw)); err == nil {
			t.Errorf("%s: a bad payload was accepted", name)
		}
	}
}

func TestParseTask_ATaskWithNoStateIsAFailure(t *testing.T) {
	out, err := ParseTask([]byte(`{"id":"t","contextId":"c","status":{}}`))
	if err != nil {
		t.Fatalf("ParseTask: %v", err)
	}
	if out.Result.Status != agent.ResultStatusFailed {
		t.Errorf("status = %q, want failed for a task with no state", out.Result.Status)
	}
	if got := brain.WorkStateFromTask(out.State); got != brain.WorkFailed {
		t.Errorf("work state = %v, want failed", got)
	}
}

func TestBuildMessage_CarriesThePinnedSkills(t *testing.T) {
	raw, err := BuildMessage(testTask(), Run{PinnedSkills: []string{"skill:triage", "skill:review"}})
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
}

func TestBuildMessage_NoPinnedSkillsLeavesTheKeyOut(t *testing.T) {
	raw, err := BuildMessage(testTask(), Run{})
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
