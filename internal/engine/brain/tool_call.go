// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// AgentToolCall is a single tool invocation made by a fleet agent — the
// tool-I/O half of the flight recorder (ADR-0020, gibson#271), alongside
// LlmCall's transcript half. Capture is ALWAYS ON: the arguments an agent sent
// a tool and the result it got back are folded in here in full, every time,
// so `World = fold(Timeline)` reconstructs the complete agent record. Only the
// metadata (tool name, ids, error) projects to the graph; the full I/O text
// stays here on the Timeline/component.
//
// Identity is ToolExecutionID — the id the calling agent's SDK already stamps
// on the callback ContextInfo for provenance (it is the same id discovery
// ingest uses to attach PRODUCED edges), so a tool call and the graph nodes it
// produced share one key: "each attached to the event it caused"
// (ADR-0020/#271). This is distinct from WorkItem (work.go), which models an
// entire CUE-projected mission node's dispatch lifecycle — a single mission
// node can make many AgentToolCalls as an agent loops over a tool.
type AgentToolCall struct {
	ToolCallID string // identity + stable projection key (ToolExecutionId)
	MissionID  string
	RunID      string // the AgentRun that made this call ("" for a mission-level call)
	ScopeID    string
	ToolName   string
	// Arguments/Result: the full JSON the agent sent and the tool returned.
	// Set once on first observation, like an LlmCall transcript — a completed
	// tool call is immutable.
	Arguments string
	Result    string
	Err       string
	// RecordedAtUnixNano stamps when the daemon observed this call, carried on
	// the event rather than read from time.Now() during Reduce, so a
	// retention sweep replays deterministically (gibson#271).
	RecordedAtUnixNano int64
}

// AgentToolCallObserved records that a fleet agent made a tool call, with its
// full arguments and result. Emitted from the harness's canonical synchronous
// tool-call RPC (CallToolProto) — the flight-recorder capture point the
// mission-graph's WorkDispatched/WorkCompleted did not cover (those model the
// dispatched *node*'s lifecycle, not the agent's own tool-call I/O).
type AgentToolCallObserved struct {
	ToolCallID         string
	MissionID          string
	RunID              string
	ScopeID            string
	ToolName           string
	Arguments          string
	Result             string
	Err                string
	RecordedAtUnixNano int64
}

// Kind identifies this event on the Timeline.
func (AgentToolCallObserved) Kind() string { return "agent_tool_call.observed" }

// applyAgentToolCallObserved resolves a tool call by ToolCallID (idempotent) or
// creates one, enriching fields that were not yet known — the same
// progressive-enrichment contract as applyLlmCallObserved. Arguments/Result
// are redacted per the tenant's current FlightRecorderPolicy at fold time.
func applyAgentToolCallObserved(w *World, e AgentToolCallObserved) {
	if e.ToolCallID == "" {
		return
	}
	q := ecs.NewFilter1[AgentToolCall](w.ecs).Query()
	for q.Next() {
		c := q.Get()
		if c.ToolCallID == e.ToolCallID {
			if c.MissionID == "" && e.MissionID != "" {
				c.MissionID = e.MissionID
			}
			if c.RunID == "" && e.RunID != "" {
				c.RunID = e.RunID
			}
			if c.ScopeID == "" && e.ScopeID != "" {
				c.ScopeID = e.ScopeID
			}
			if c.ToolName == "" && e.ToolName != "" {
				c.ToolName = e.ToolName
			}
			if c.Arguments == "" && e.Arguments != "" {
				c.Arguments = redactForTenant(w, e.Arguments)
			}
			if c.Result == "" && e.Result != "" {
				c.Result = redactForTenant(w, e.Result)
			}
			if c.Err == "" && e.Err != "" {
				c.Err = e.Err
			}
			if c.RecordedAtUnixNano == 0 && e.RecordedAtUnixNano != 0 {
				c.RecordedAtUnixNano = e.RecordedAtUnixNano
			}
			q.Close()
			return
		}
	}
	w.agentToolCalls.NewEntity(&AgentToolCall{
		ToolCallID:         e.ToolCallID,
		MissionID:          e.MissionID,
		RunID:              e.RunID,
		ScopeID:            e.ScopeID,
		ToolName:           e.ToolName,
		Arguments:          redactForTenant(w, e.Arguments),
		Result:             redactForTenant(w, e.Result),
		Err:                e.Err,
		RecordedAtUnixNano: e.RecordedAtUnixNano,
	})
}

// AgentToolCallSnapshot is a stable, comparable view of an AgentToolCall.
type AgentToolCallSnapshot struct {
	ToolCallID         string
	MissionID          string
	RunID              string
	ScopeID            string
	ToolName           string
	Arguments          string
	Result             string
	Err                string
	RecordedAtUnixNano int64
}

// AgentToolCallSnapshot returns tool calls in deterministic (ToolCallID) order.
func (w *World) AgentToolCallSnapshot() []AgentToolCallSnapshot {
	var out []AgentToolCallSnapshot
	q := ecs.NewFilter1[AgentToolCall](w.ecs).Query()
	for q.Next() {
		c := q.Get()
		out = append(out, AgentToolCallSnapshot{
			ToolCallID:         c.ToolCallID,
			MissionID:          c.MissionID,
			RunID:              c.RunID,
			ScopeID:            c.ScopeID,
			ToolName:           c.ToolName,
			Arguments:          c.Arguments,
			Result:             c.Result,
			Err:                c.Err,
			RecordedAtUnixNano: c.RecordedAtUnixNano,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ToolCallID < out[j].ToolCallID })
	return out
}
