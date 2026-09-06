// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "time"

// WorkNode is one node of a CUE mission's work-graph, in brain-native form (the
// daemon translates a gibson.mission.v1.MissionDefinition into these — the brain
// stays proto-free, like the observation ingest path). Edges are carried as each
// node's DependsOn; CUE `parallel`/`join` collapse into DependsOn topology and
// need no node kind here (gibson#846), so Kind is one of "agent"|"tool"|"plugin"
// (plus "condition" once gibson#846 lands).
type WorkNode struct {
	ID         string
	Kind       string
	Target     string   // capability name (agent/tool/plugin)
	Input      string   // opaque dispatch input (the node config), carried for dispatch
	DependsOn  []string // node IDs this one depends on
	MaxRetries int      // CUE RetryPolicy.max_retries (0 = no retry)
	// Timeout is MissionNode.timeout. Zero means the node declared none; the
	// dispatch boundary decides what that means per kind (gibson#1602).
	Timeout time.Duration
}

// MissionProjected is the launch event for a scripted CUE mission (ADR-0001): the
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
	// BeliefModel pins the belief-model version this mission ran under (ADR-0005
	// §5): the daemon stamps the provider's current artifact at launch so replay
	// re-loads the exact model. Empty → no pinned model (placeholder / OSS).
	BeliefModel string

	// Display metadata (ADR-0011/gibson#1118): carried from the CUE definition and
	// target so the World is the single source of truth — no secondary store.
	Name        string
	Description string
	TargetID    string
	TenantID    string
}

func (MissionProjected) Kind() string { return "mission.projected" }

func applyMissionProjected(w *World, e MissionProjected) {
	if _, ok := findMission(w, e.ID); ok {
		return // idempotent: already projected
	}
	w.missions.NewEntity(&Mission{
		ID:             e.ID,
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
	for _, n := range e.Nodes {
		id := WorkID(e.ID, n.ID)
		if _, ok := findWork(w, id); ok {
			continue // idempotent
		}
		deps := make([]string, 0, len(n.DependsOn))
		for _, d := range n.DependsOn {
			deps = append(deps, WorkID(e.ID, d))
		}
		w.work.NewEntity(&WorkItem{
			ID:         id,
			MissionID:  e.ID,
			Kind:       n.Kind,
			Target:     n.Target,
			Input:      n.Input,
			DependsOn:  deps,
			State:      WorkPending,
			MaxRetries: n.MaxRetries,
			Timeout:    n.Timeout,
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
