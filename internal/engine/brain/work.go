// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"sort"
	"time"

	"github.com/mlange-42/ark/ecs"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// WorkState is the lifecycle state of a unit of work.
type WorkState string

const (
	// WorkPending: projected into the World (e.g. from a CUE node) but not yet
	// dispatched — the Scheduler dispatches it once its DependsOn are all done.
	WorkPending WorkState = "pending"
	WorkRunning WorkState = "running"
	WorkDone    WorkState = "done"
	WorkFailed  WorkState = "failed"
	// WorkSkipped: a node on a condition's not-taken branch — terminal, never
	// executed, and (unlike failed) not a mission failure. Its dependents become
	// dead (their dep never reaches `done`) and are ignored by completion.
	WorkSkipped WorkState = "skipped"
)

// WorkItem is a unit of work tracked as an entity — a tool call, agent run, or
// plugin invocation (ADR-0104: capability vs. execution; this is the execution
// side, e.g. a ToolExecution). Modeling work as an entity is what lets
// long-running operations be async: the engine never blocks on them; their
// completion arrives as an event whenever it lands (decided-by-observation — no
// duration is declared or tracked; a 3-second tool and a 3-day callback are the
// same path).
//
// A WorkItem may be born `pending` (projected from a CUE mission node, with its
// DependsOn ordering, by the Scheduler's deferred-ordering model) or born
// `running` (dispatched directly). DependsOn references other WorkItem IDs that
// must reach `done` before this one is dispatchable.
type WorkItem struct {
	ID         string
	MissionID  string   // owning mission (empty for free-standing work)
	Kind       string   // "tool" | "agent" | "plugin"
	Target     string   // the capability being executed
	Input      string   // opaque dispatch input (e.g. the CUE node config), carried for dispatch
	DependsOn  []string // WorkItem IDs that must be `done` before this is dispatchable
	State      WorkState
	Result     string
	Err        string
	MaxRetries int // CUE RetryPolicy.max_retries; the retry System re-dispatches on failure up to this
	Attempts   int // dispatch attempts so far (count-based, deterministic for replay)

	// DependentsRunOnFailure means a terminal failure of this item satisfies the
	// items that depend on it, rather than stranding them. See
	// MissionProjected.WorkNode for why it lives on the dependency and which
	// nodes set it (gibson#527).
	DependentsRunOnFailure bool

	// CompletedSeq orders completions on the Timeline: the n-th WorkCompleted
	// the World folded, done or failed, carries n. Zero means not completed.
	// A join's FIRST and LAST strategies read it, so "first to complete" is a
	// fact of the fold and replays the same (gibson#543).
	CompletedSeq uint64

	// Timeout is the node's own execution bound, from MissionNode.timeout.
	// Zero means the node declared none, which is NOT the same as "expire
	// immediately": what a zero means is decided at the dispatch boundary, per
	// kind. A live agent node with no declared timeout runs until it submits a
	// result or its worker stops heartbeating (gibson#1602); every other kind
	// falls back to the harness-wide work-queue default.
	//
	// It lives on the WorkItem rather than only on the dispatch event because
	// the World is the single source of truth for what a mission is doing, and
	// a snapshot restore has to hand the same bound back to the dispatcher.
	Timeout time.Duration

	// Group and Limit are the concurrency ceiling this item is scheduled under:
	// at most Limit items of the same Group run at once. See
	// MissionProjected.WorkNode (gibson#538). Empty Group or zero Limit means
	// no ceiling.
	Group string
	Limit int

	// Network is the network scope of the node (gibson#865). It lives on the
	// WorkItem for the same reason Timeout does: a snapshot restore and a
	// retry hand the same scope back to the dispatcher.
	Network *agent.NodeNetwork
}

// WorkDispatched records that a unit of work was launched. It does not block;
// the work runs out-of-process and reports back via WorkCompleted. It carries the
// MissionID + Input so the live dispatch effect-handler (ADR-0109) can actuate the
// launch without reading the World back inside the locked tick.
type WorkDispatched struct {
	ID        string
	MissionID string
	ItemKind  string // tool | agent | plugin
	Target    string
	Input     string
	// Timeout carries the node's execution bound to the dispatch effect-handler
	// so it does not have to read the World back inside the locked tick — the
	// same reason MissionID and Input are carried here (gibson#1602).
	Timeout time.Duration
	// Group and Limit travel with the dispatch for the same reason Timeout
	// does: a snapshot restore re-creates the item through this event and
	// must hand the scheduler the same ceiling (gibson#538).
	Group string
	Limit int
	// Network carries the network scope of the node to the dispatch
	// effect-handler, for the same reason Timeout does (gibson#865).
	Network *agent.NodeNetwork
}

func (WorkDispatched) Kind() string { return "work.dispatched" }

// WorkRetried re-arms a failed WorkItem for another dispatch attempt (count-based,
// deterministic). The reducer increments Attempts and returns it to `pending` so
// the Scheduler re-dispatches it.
type WorkRetried struct {
	ID string
}

func (WorkRetried) Kind() string { return "work.retried" }

// WorkCompleted records that a previously-dispatched unit of work finished —
// whenever that is. Err non-empty means failure.
type WorkCompleted struct {
	ID     string
	Result string
	Err    string
}

func (WorkCompleted) Kind() string { return "work.completed" }

// findWork returns the entity for the work item with the given ID, if present.
func findWork(w *World, id string) (ecs.Entity, bool) {
	q := ecs.NewFilter1[WorkItem](w.ecs).Query()
	for q.Next() {
		if q.Get().ID == id {
			e := q.Entity()
			q.Close()
			return e, true
		}
	}
	return ecs.Entity{}, false
}

func applyWorkDispatched(w *World, e WorkDispatched) {
	if ent, ok := findWork(w, e.ID); ok {
		wi := w.work.Get(ent)
		if wi.State == WorkRunning {
			return // idempotent: already running
		}
		wi.State = WorkRunning
		wi.Attempts++
		// A re-dispatch (retry, or a snapshot restore that re-creates the item
		// through this event) must not silently drop the node's bound. The
		// projection is the only place a timeout is authored, so an event that
		// carries one always wins over a zero already on the item.
		if e.Timeout > 0 {
			wi.Timeout = e.Timeout
		}
		if e.Limit > 0 {
			wi.Group, wi.Limit = e.Group, e.Limit
		}
		if e.Network != nil {
			wi.Network = e.Network
		}
		return
	}
	w.work.NewEntity(&WorkItem{
		ID:        e.ID,
		MissionID: e.MissionID,
		Kind:      e.ItemKind,
		Target:    e.Target,
		Input:     e.Input,
		State:     WorkRunning,
		Attempts:  1,
		Timeout:   e.Timeout,
		Group:     e.Group,
		Limit:     e.Limit,
		Network:   e.Network,
	})
	// A fresh dispatch under an open Decider decision is one of that decision's
	// chosen actions (gibson#1062). Only first dispatches link — a retry re-arms an
	// existing WorkItem and reaches the idempotent branch above.
	recordDecisionDispatch(w, e.MissionID, DecisionDispatch{WorkID: e.ID, Kind: e.ItemKind, Target: e.Target})
}

func applyWorkRetried(w *World, e WorkRetried) {
	ent, ok := findWork(w, e.ID)
	if !ok {
		return
	}
	wi := w.work.Get(ent)
	if wi.State != WorkFailed {
		return // only failed work can be re-armed
	}
	wi.State = WorkPending
	wi.Err = ""
}

func applyWorkCompleted(w *World, e WorkCompleted) {
	ent, ok := findWork(w, e.ID)
	if !ok {
		return // completion for unknown work: ignore (out-of-order/duplicate)
	}
	wi := w.work.Get(ent)
	// Idempotent: a late WorkCompleted arriving for work that is already in a
	// terminal state (failed, done, skipped — including one already failed by
	// ResumeFailInFlight) is a no-op. This prevents a worker that outlived the
	// daemon from corrupting the World after a restart (ADR-0163).
	switch wi.State {
	case WorkFailed, WorkDone, WorkSkipped:
		return
	}
	w.nextCompletedSeq++
	wi.CompletedSeq = w.nextCompletedSeq
	if e.Err != "" {
		wi.State, wi.Err = WorkFailed, e.Err
		return
	}
	wi.State, wi.Result = WorkDone, e.Result
}

// WorkSnapshot is a stable, comparable view of a WorkItem.
type WorkSnapshot struct {
	ID         string
	MissionID  string
	Kind       string
	Target     string
	Input      string
	DependsOn  []string
	State      WorkState
	Result     string
	Err        string
	MaxRetries int
	Attempts   int
	Timeout    time.Duration
	// DependentsRunOnFailure mirrors WorkItem.DependentsRunOnFailure. The
	// scheduler reads dependency satisfaction off this snapshot, so the flag has
	// to travel with it (gibson#527).
	DependentsRunOnFailure bool
	// Group and Limit mirror WorkItem's; the scheduler counts a Group's running
	// members off this snapshot (gibson#538).
	Group string
	Limit int
	// Network mirrors WorkItem.Network; the scheduler hands it to the
	// dispatch (gibson#865).
	Network *agent.NodeNetwork
	// CompletedSeq mirrors WorkItem.CompletedSeq (gibson#543).
	CompletedSeq uint64
}

// WorkSnapshot returns the current work items in deterministic (ID) order.
func (w *World) WorkSnapshot() []WorkSnapshot {
	var out []WorkSnapshot
	q := ecs.NewFilter1[WorkItem](w.ecs).Query()
	for q.Next() {
		wi := q.Get()
		out = append(out, WorkSnapshot{
			ID:                     wi.ID,
			MissionID:              wi.MissionID,
			Kind:                   wi.Kind,
			Target:                 wi.Target,
			Input:                  wi.Input,
			DependsOn:              append([]string(nil), wi.DependsOn...),
			State:                  wi.State,
			Result:                 wi.Result,
			Err:                    wi.Err,
			MaxRetries:             wi.MaxRetries,
			Attempts:               wi.Attempts,
			Timeout:                wi.Timeout,
			DependentsRunOnFailure: wi.DependentsRunOnFailure,
			Group:                  wi.Group,
			Limit:                  wi.Limit,
			Network:                wi.Network,
			CompletedSeq:           wi.CompletedSeq,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
