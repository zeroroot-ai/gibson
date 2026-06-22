package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// AgentRun is a single agent execution within a mission — a unit of run-provenance
// (ADR-0007). Identity is the globally-unique RunID assigned by the harness, so it
// needs no scope-relative resolution: RunID is the stable graph-projection key.
// ParentRunID links a delegated run to the run that spawned it (the DELEGATED_TO
// edge in the projected graph); it is empty for a root agent run.
type AgentRun struct {
	RunID       string // identity + stable projection key
	ParentRunID string // the run that delegated to this one ("" for a root run)
	AgentName   string
	ScopeID     string
}

// AgentRunObserved records that an agent run exists, optionally as a delegation of
// a parent run. Emitted from the harness delegation path: both the parent and the
// child run are observed so the DELEGATED_TO edge has both endpoints (the parent
// observation also covers the root run, which is never itself delegated-to).
type AgentRunObserved struct {
	RunID       string
	ParentRunID string
	AgentName   string
	ScopeID     string
}

func (AgentRunObserved) Kind() string { return "agent_run.observed" }

// applyAgentRunObserved resolves an agent run by RunID (idempotent) or creates one,
// enriching the parent link and agent name when they were not yet known.
func applyAgentRunObserved(w *World, e AgentRunObserved) {
	if e.RunID == "" {
		return
	}
	q := ecs.NewFilter1[AgentRun](w.ecs).Query()
	for q.Next() {
		r := q.Get()
		if r.RunID == e.RunID {
			if r.ParentRunID == "" && e.ParentRunID != "" {
				r.ParentRunID = e.ParentRunID
			}
			if r.AgentName == "" && e.AgentName != "" {
				r.AgentName = e.AgentName
			}
			if r.ScopeID == "" && e.ScopeID != "" {
				r.ScopeID = e.ScopeID
			}
			q.Close()
			return
		}
	}
	w.agentRuns.NewEntity(&AgentRun{
		RunID: e.RunID, ParentRunID: e.ParentRunID, AgentName: e.AgentName, ScopeID: e.ScopeID,
	})
}

// AgentRunSnapshot is a stable, comparable view of an AgentRun.
type AgentRunSnapshot struct {
	RunID       string
	ParentRunID string
	AgentName   string
	ScopeID     string
}

// AgentRunSnapshot returns agent runs in deterministic (RunID) order.
func (w *World) AgentRunSnapshot() []AgentRunSnapshot {
	var out []AgentRunSnapshot
	q := ecs.NewFilter1[AgentRun](w.ecs).Query()
	for q.Next() {
		r := q.Get()
		out = append(out, AgentRunSnapshot{
			RunID: r.RunID, ParentRunID: r.ParentRunID, AgentName: r.AgentName, ScopeID: r.ScopeID,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID < out[j].RunID })
	return out
}
