// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"time"

	"github.com/mlange-42/ark/ecs"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
)

// WorkNode is one node of a CUE mission's work-graph, in brain-native form (the
// daemon translates a gibson.mission.v1.MissionDefinition into these — the brain
// stays proto-free, like the observation ingest path). Edges are carried as each
// node's DependsOn; CUE `parallel`/`join` collapse into DependsOn topology and
// need no node kind here (gibson#846), so Kind is one of "agent"|"tool"|"plugin"
// (plus "condition" once gibson#846 lands).
type WorkNode struct {
	ID        string
	Kind      string
	Target    string   // capability name (agent/tool/plugin)
	Input     string   // opaque dispatch input (the node config), carried for dispatch
	DependsOn []string // node IDs this one depends on

	// DependentsRunOnFailure lets this node's terminal failure satisfy the nodes
	// that wait on it, instead of stranding them.
	//
	// It is false for every ordinary node: a step whose dependency failed must
	// not run. It is true for a for_each instance, by the fan-out decision
	// (gibson#524) that every instance runs and the fan-out as a whole fails if
	// any instance failed. A mission that scans ten targets and finds one
	// unreachable still has nine targets' worth of findings, and a join that
	// cannot run leaves them unreported — the mission would record a failure and
	// throw away the work that succeeded.
	//
	// The flag lives on the dependency rather than the dependent because that is
	// where the fact lives. An instance is one of N over a target set whatever
	// waits on it, so every dependent gets the same answer and no two can
	// disagree.
	DependentsRunOnFailure bool
	MaxRetries             int // CUE RetryPolicy.max_retries (0 = no retry)
	// Timeout is MissionNode.timeout. Zero means the node declared none; the
	// dispatch boundary decides what that means per kind (gibson#1602).
	Timeout time.Duration

	// Group names the parallel or for_each node this one belongs to, and Limit
	// is that node's max_concurrency: the scheduler dispatches at most Limit
	// members of a Group at once (gibson#538). A zero Limit means unlimited,
	// which is the documented meaning of an unset max_concurrency. Both are
	// empty for a node that belongs to no container.
	//
	// The ceiling lives in the scheduler rather than in DependsOn because a
	// dependency is an ordering and a ceiling is not: chaining instance k
	// behind instance k-limit (the gibson#525 stopgap) bounded the count but
	// also forced an order the author never asked for, and parallel's own
	// max_concurrency bounded nothing at all.
	Group string
	Limit int

	// Network is the network scope of the node (owner decision S6,
	// gibson#865): its research flag and the targets bound to it. The daemon
	// sets it for each node it projects. Nil keeps the egress of the catalog
	// manifest.
	Network *agent.NodeNetwork
	// SlotPins are the LLM slot pins of an agent node
	// (AgentNodeConfig.llm_slots): slot name to provider and model. They
	// travel with Network to the dispatch (gibson#1203). Nil pins nothing.
	SlotPins map[string]agent.SlotConfig
	// StartsFrom names the earlier node whose parked sandbox this node forks,
	// and Forkable marks a node that a later node names (ADR-0169,
	// gibson#802). They travel with Network to the dispatch.
	StartsFrom string
	Forkable   bool
	// Checkpoint marks an agent node of a mission in the sandbox checkpoint
	// mode: its sandbox leaves a snapshot when the node ends. FromSnapshot
	// names the snapshot that the node of a rewind starts from (ADR-0170).
	Checkpoint   bool
	FromSnapshot string
}

// MissionProjected is the launch event for a scripted CUE mission (ADR-0101): the
// mission definition projected into the World. The reducer seeds the Mission
// (goal + budget) and one `pending` WorkItem per node, wired with DependsOn. A
// mission with an empty Goal is a no-goal mission — it runs deterministically to
// quiescence with the Decider never firing (CONTEXT.md). Distinct from the
// minimal MissionStarted, which only seeds an observed mission.
type MissionProjected struct {
	ID          string
	Goal        string
	Budget      Budget
	Nodes       []WorkNode
	DeciderSlot DeciderSlot // mission-level Decider LLM (gibson#850); empty → tenant default
	// BeliefModel pins the belief-model version this mission ran under (ADR-0134):
	// the daemon stamps the provider's current artifact at launch so replay
	// re-loads the exact model. Empty → no pinned model (placeholder / OSS).
	BeliefModel string

	// Display metadata (ADR-0163/gibson#1118): carried from the CUE definition and
	// target so the World is the single source of truth — no secondary store.
	Name        string
	Description string
	TargetID    string
	TenantID    string

	// RunID names this run of the mission. The daemon mints it when the run
	// starts. A mission ID is the stable record ID, so the RunID is what makes
	// the second run of a mission a new run and not a repeat of the first
	// (gibson#1217).
	RunID string
}

func (MissionProjected) Kind() string { return "mission.projected" }

func applyMissionProjected(w *World, e MissionProjected) {
	if ent, ok := findMission(w, e.ID); ok {
		m := w.missions.Get(ent)
		switch {
		case m.Status == MissionPending:
			// A mission that a person created and that has not run yet. Keep
			// the entity, which holds the creator, and start its first run.
			startRun(m, e)
			projectWork(w, e)
			return
		case m.RunID == e.RunID:
			return // idempotent: the same run, projected again
		}
		// A new run of a mission that ran before. The mission ID is the
		// stable record ID, so the new run finds the entity of the old run.
		// Retire everything of the old run first, or the new run finds the
		// old terminal status and the old work and does nothing
		// (gibson#1217). The Timeline keeps the history of the old run.
		retireMissionRun(w, e.ID)
	}
	w.missions.NewEntity(&Mission{
		ID:             e.ID,
		RunID:          e.RunID,
		Goal:           e.Goal,
		Status:         MissionRunning,
		Budget:         e.Budget,
		DecisionCursor: -1,
		DeciderSlot:    e.DeciderSlot,
		BeliefModel:    e.BeliefModel,
		Name:           e.Name,
		Description:    e.Description,
		TargetID:       e.TargetID,
		TenantID:       e.TenantID,
	})
	projectWork(w, e)
}

// projectWork adds the work items of a projected run to the World.
func projectWork(w *World, e MissionProjected) {
	// The node of a rewound checkpoint starts from the snapshot of that
	// checkpoint (ADR-0170). The rewind event comes before the projection.
	rewind, rewound := w.missionRewinds[e.ID]
	for _, n := range e.Nodes {
		id := WorkID(e.ID, n.ID)
		if rewound && rewind.StartSnapshot != "" && n.ID == rewind.ParentCheckpointID {
			n.FromSnapshot = rewind.StartSnapshot
		}
		if _, ok := findWork(w, id); ok {
			continue // idempotent
		}
		deps := make([]string, 0, len(n.DependsOn))
		for _, d := range n.DependsOn {
			deps = append(deps, WorkID(e.ID, d))
		}
		w.work.NewEntity(&WorkItem{
			ID:                     id,
			MissionID:              e.ID,
			RunID:                  e.RunID,
			Kind:                   n.Kind,
			Target:                 n.Target,
			Input:                  n.Input,
			DependsOn:              deps,
			State:                  WorkPending,
			MaxRetries:             n.MaxRetries,
			Timeout:                n.Timeout,
			DependentsRunOnFailure: n.DependentsRunOnFailure,
			Group:                  n.Group,
			Limit:                  n.Limit,
			Network:                n.Network,
			SlotPins:               n.SlotPins,
			StartsFrom:             n.StartsFrom,
			Forkable:               n.Forkable,
			Checkpoint:             n.Checkpoint,
			FromSnapshot:           n.FromSnapshot,
		})
	}
}

// WorkID is a work item's identity in the per-tenant World: the mission it
// belongs to, then the node id from its CUE definition.
//
// The node id alone is NOT unique. It is unique within one mission definition,
// but the World is per-tenant and long-lived, so two missions that both name a
// node "fetch" — the normal case, since node names describe steps — collide.
// The reducer is idempotent by work id, so the second mission's nodes were
// silently skipped as already-projected; the mission then had zero work items,
// and MissionCompletionSystem read "nothing running, nothing ready" as "all
// work complete" and reported SUCCESS for a mission that did nothing.
//
// This is the same scoping brain_ingest.go already used for the ids it submits,
// so the two paths now agree instead of only appearing to.
func WorkID(missionID, nodeID string) string {
	if missionID == "" {
		return nodeID
	}
	return missionID + "/" + nodeID
}

// nodeName is WorkID's inverse: the node id a work item came from. Used where a
// mission author's own vocabulary is what matters — CEL condition expressions
// name nodes, not work items.
func nodeName(workID string) string {
	for i := len(workID) - 1; i >= 0; i-- {
		if workID[i] == '/' {
			return workID[i+1:]
		}
	}
	return workID
}

// startRun turns a pending mission into a running one, with the first run of
// the projection. The entity keeps what creation recorded, such as the creator.
func startRun(m *Mission, e MissionProjected) {
	m.RunID = e.RunID
	m.Goal = e.Goal
	m.Status = MissionRunning
	m.Budget = e.Budget
	m.DecisionCursor = -1
	m.DeciderSlot = e.DeciderSlot
	m.BeliefModel = e.BeliefModel
	// What creation recorded stays when the projection carries none.
	if e.Name != "" {
		m.Name = e.Name
	}
	if e.Description != "" {
		m.Description = e.Description
	}
	if e.TargetID != "" {
		m.TargetID = e.TargetID
	}
	if e.TenantID != "" {
		m.TenantID = e.TenantID
	}
}

// retireMissionRun removes the state of the last run of a mission: the mission
// entity, its work items, its decisions and its VoI plan. The next projection
// of the mission ID then starts from a clean state.
func retireMissionRun(w *World, missionID string) {
	var stale []ecs.Entity
	mq := ecs.NewFilter1[Mission](w.ecs).Query()
	for mq.Next() {
		if mq.Get().ID == missionID {
			stale = append(stale, mq.Entity())
		}
	}
	wq := ecs.NewFilter1[WorkItem](w.ecs).Query()
	for wq.Next() {
		if wq.Get().MissionID == missionID {
			stale = append(stale, wq.Entity())
		}
	}
	dq := ecs.NewFilter1[DecisionRecord](w.ecs).Query()
	for dq.Next() {
		if dq.Get().MissionID == missionID {
			stale = append(stale, dq.Entity())
		}
	}
	vq := ecs.NewFilter1[VoIPlanState](w.ecs).Query()
	for vq.Next() {
		if vq.Get().MissionID == missionID {
			stale = append(stale, vq.Entity())
		}
	}
	for _, ent := range stale {
		w.ecs.RemoveEntity(ent)
	}
}

// runVerdict is what the reducer does with an event of a run that is not the
// current run of its mission.
type runVerdict int

const (
	// runCurrent: the event is of the current run, or it is not run-scoped.
	runCurrent runVerdict = iota
	// runDropped: the event is control state of an older run (work, mission,
	// decision, plan). It must not change the current run, so the reducer
	// ignores it.
	runDropped
	// runDetached: the event is evidence of an older run (a finding, a host,
	// a call). The fact is true and stays in the World, but it has no link to
	// the current run, so it is not counted as seen by that run.
	runDetached
)

// runCheck is the result of checkRun, with what a log line needs.
type runCheck struct {
	verdict    runVerdict
	kind       string
	missionID  string
	eventRun   string
	currentRun string
}

// checkRun compares the run of ev with the current run of its mission. It is a
// pure function of the World, so a replay of the Timeline reaches the same
// verdict for the same event (gibson#1217). An event with no RunID is not
// run-scoped and is current.
func checkRun(w *World, ev Event) runCheck {
	switch e := ev.(type) {
	case WorkCompleted:
		return workRunCheck(w, ev, e.ID, e.RunID)
	case WorkDispatched:
		if chk := workRunCheck(w, ev, e.ID, e.RunID); chk.verdict != runCurrent {
			return chk
		}
		if _, ok := findWork(w, e.ID); ok {
			return runCheck{}
		}
		return missionRunCheck(w, ev, e.MissionID, e.RunID, runDropped)
	case MissionDone:
		return missionRunCheck(w, ev, e.ID, e.RunID, runDropped)
	case MissionPauseRequested:
		return missionRunCheck(w, ev, e.ID, e.RunID, runDropped)
	case MissionResumed:
		return missionRunCheck(w, ev, e.ID, e.RunID, runDropped)
	case DecisionCompleted:
		return missionRunCheck(w, ev, e.MissionID, e.RunID, runDropped)
	case VoIPlanned:
		return missionRunCheck(w, ev, e.MissionID, e.RunID, runDropped)
	case FindingRaised:
		return missionRunCheck(w, ev, e.MissionID, e.MissionRunID, runDetached)
	case HostObserved:
		return missionRunCheck(w, ev, e.MissionID, e.MissionRunID, runDetached)
	case EntityObserved:
		return missionRunCheck(w, ev, e.MissionID, e.MissionRunID, runDetached)
	case ObservationRecorded:
		return missionRunCheck(w, ev, e.MissionID, e.MissionRunID, runDetached)
	case HypothesisObserved:
		return missionRunCheck(w, ev, e.MissionID, e.MissionRunID, runDetached)
	case LlmCallObserved:
		return missionRunCheck(w, ev, e.MissionID, e.MissionRunID, runDetached)
	case AgentToolCallObserved:
		return missionRunCheck(w, ev, e.MissionID, e.MissionRunID, runDetached)
	}
	return runCheck{}
}

func missionRunCheck(w *World, ev Event, missionID, runID string, mismatch runVerdict) runCheck {
	if runID == "" {
		return runCheck{}
	}
	ent, ok := findMission(w, missionID)
	if !ok {
		return runCheck{}
	}
	current := w.missions.Get(ent).RunID
	if current == runID {
		return runCheck{}
	}
	return runCheck{verdict: mismatch, kind: ev.Kind(), missionID: missionID, eventRun: runID, currentRun: current}
}

func workRunCheck(w *World, ev Event, workID, runID string) runCheck {
	if runID == "" {
		return runCheck{}
	}
	ent, ok := findWork(w, workID)
	if !ok {
		return runCheck{}
	}
	wi := w.work.Get(ent)
	if wi.RunID == runID {
		return runCheck{}
	}
	return runCheck{verdict: runDropped, kind: ev.Kind(), missionID: wi.MissionID, eventRun: runID, currentRun: wi.RunID}
}

// detachEvidence returns ev without its link to a mission. The evidence of a
// finished run stays in the World as a fact with no mission frame, so it is
// not attributed to the current run (gibson#1217). The Timeline keeps the
// event as it came.
func detachEvidence(ev Event) Event {
	switch e := ev.(type) {
	case FindingRaised:
		e.MissionID = ""
		return e
	case HostObserved:
		e.MissionID = ""
		return e
	case EntityObserved:
		e.MissionID = ""
		return e
	case ObservationRecorded:
		e.MissionID = ""
		return e
	case HypothesisObserved:
		e.MissionID = ""
		return e
	case LlmCallObserved:
		e.MissionID = ""
		return e
	case AgentToolCallObserved:
		e.MissionID = ""
		return e
	}
	return ev
}
