// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package agentwire is the wire of agent work. The payload of an agent work
// item is one A2A v1.0 Message. The result is one A2A Task. The Gibson context
// that A2A has no field for rides under one metadata key (sdkagent.ExtensionKey).
package agentwire

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	sdkagent "github.com/zeroroot-ai/sdk/agent"
)

// WorkType is the work type of agent work on the component work queue.
const WorkType = "execute"

// Run is the run context of one agent work item.
type Run struct {
	MissionRunID string
	AgentRunID   string
	RunNumber    int
	JobID        string
	TraceID      string
	ParentSpanID string
	// ContextID is the A2A context id. Empty means the task id.
	ContextID string
	// PinnedSkills are the Agent Skill ids that the mission pins.
	PinnedSkills []string
	// Job is the protojson of the job spec. Empty means no job.
	Job json.RawMessage
}

// BuildMessage builds the A2A message of a work item and returns its JSON.
func BuildMessage(task agent.Task, run Run) ([]byte, error) {
	taskID := task.ID.String()
	if taskID == "" {
		return nil, errors.New("agent task has no id")
	}
	contextID := run.ContextID
	if contextID == "" {
		contextID = taskID
	}
	text := task.Goal
	if text == "" {
		text = task.Description
	}
	if text == "" {
		text = task.Name
	}
	msg := a2a.NewMessage(a2a.MessageRoleUser, a2a.NewTextPart(text))
	msg.TaskID = a2a.TaskID(taskID)
	msg.ContextID = contextID

	meta := map[string]any{"name": task.Name, "description": task.Description}
	if task.Timeout > 0 {
		meta["timeout_ms"] = task.Timeout.Milliseconds()
	}
	if task.MissionID != nil {
		meta["mission_id"] = task.MissionID.String()
	}
	if task.ParentTaskID != nil {
		meta["parent_task_id"] = task.ParentTaskID.String()
	}
	if task.TargetID != nil {
		meta["target_id"] = task.TargetID.String()
	}
	env := sdkagent.Envelope{
		RunContext: sdkagent.RunContext{
			MissionRunID: run.MissionRunID, AgentRunID: run.AgentRunID, RunNumber: run.RunNumber,
			JobID: run.JobID, TraceID: run.TraceID, ParentSpanID: run.ParentSpanID,
		},
		PinnedSkills: run.PinnedSkills,
		Context:      task.Context,
		Metadata:     meta,
		Job:          run.Job,
	}
	msg.SetMeta(sdkagent.ExtensionKey, env)
	out, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("encode the a2a message of the work item: %w", err)
	}
	return out, nil
}

// Outcome is what the daemon reads from the A2A Task that an agent returned.
type Outcome struct {
	// State is the A2A state of the Task.
	State a2a.TaskState
	// Result is the agent result in the internal form.
	Result agent.Result
	// Error is the structured error of a failed run. Nil for no error.
	Error *sdkagent.ResultError
	// Deliverables are the protojson messages of what left the sandbox.
	Deliverables []json.RawMessage
	// ClaudeSessionID is the coding agent session of the run.
	ClaudeSessionID string
	// FindingIDs are the ids of the findings that the run submitted.
	FindingIDs []string
	// Metadata is the metadata of the result.
	Metadata map[string]any
	// Message is the text of the status message of the Task, if any.
	Message string
}

// StateError reports that an agent ended its Task in a state that is neither
// completed nor failed. The state is canceled, input-required or auth-required.
// The daemon maps it to the work state with brain.WorkStateFromTask.
type StateError struct {
	// State is the A2A state of the Task.
	State a2a.TaskState
	// Message is the text of the status message of the Task.
	Message string
}

// Error returns the state and the message.
func (e *StateError) Error() string {
	return fmt.Sprintf("the agent ended the task in the state %s: %s", e.State, e.Message)
}

// ParseTask reads the A2A Task of a work result. The state of the Task is the
// state of the run.
func ParseTask(raw []byte) (Outcome, error) {
	var t a2a.Task
	if err := json.Unmarshal(raw, &t); err != nil {
		return Outcome{}, fmt.Errorf("decode the a2a task of the work result: %w", err)
	}
	out := Outcome{State: t.Status.State}
	if t.Status.Message != nil {
		out.Message = textOf(t.Status.Message.Parts)
	}
	if v, ok := t.Metadata[sdkagent.ExtensionKey]; ok {
		b, err := json.Marshal(v)
		if err != nil {
			return Outcome{}, fmt.Errorf("encode the gibson extension of the task: %w", err)
		}
		var env sdkagent.ResultEnvelope
		if err := json.Unmarshal(b, &env); err != nil {
			return Outcome{}, fmt.Errorf("decode the gibson extension of the task: %w", err)
		}
		out.Error = env.Error
		out.Deliverables = env.Deliverables
		out.ClaudeSessionID = env.ClaudeSessionID
		out.FindingIDs = env.FindingIDs
		out.Metadata = env.Metadata
	}
	out.Result = resultOf(&t, out)
	return out, nil
}

func resultOf(t *a2a.Task, o Outcome) agent.Result {
	r := agent.Result{Status: agent.ResultStatusCompleted, Output: map[string]any{}, Findings: []agent.Finding{},
		CompletedAt: time.Now(), Deliverables: o.Deliverables, ClaudeSessionID: o.ClaudeSessionID}
	switch o.State {
	case a2a.TaskStateCompleted:
	case a2a.TaskStateCanceled:
		r.Status = agent.ResultStatusCancelled
	default:
		r.Status = agent.ResultStatusFailed
	}
	for _, art := range t.Artifacts {
		if art == nil {
			continue
		}
		name := art.Name
		if name == "" {
			name = string(art.ID)
		}
		if txt := textOf(art.Parts); txt != "" {
			r.Output[name] = txt
		}
	}
	for k, v := range o.Metadata {
		if _, ok := r.Output[k]; !ok {
			r.Output[k] = v
		}
	}
	if r.Status != agent.ResultStatusCompleted {
		msg := o.Message
		code := ""
		if o.Error != nil {
			msg, code = o.Error.Message, o.Error.Code
		}
		if msg == "" {
			msg = "the agent ended the task in the state " + o.State.String()
		}
		r.Error = &agent.ResultError{Message: msg, Code: code}
	}
	return r
}

func textOf(parts a2a.ContentParts) string {
	var out string
	for _, p := range parts {
		if p == nil {
			continue
		}
		if t := p.Text(); t != "" {
			if out != "" {
				out += "\n"
			}
			out += t
		}
	}
	return out
}
