// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "sort"

// mission_lineage.go holds the lineage of a mission that a component
// originated (ADR-0063, ADR-0163, gibson#734): which mission started it, from
// which work item, by which component, under which capability grant.
//
// The lineage is a Timeline event, so a replay of the Timeline rebuilds which
// mission started which. It was four keys in Mission.Metadata before, and a
// replay could not see them.

// MissionOriginated records that a component originated a mission from inside
// a parent mission. The daemon submits it after it saved the child mission.
// Each field comes from the verified identity of the caller and from the work
// item that the daemon resolved, never from the request payload.
type MissionOriginated struct {
	// MissionID is the new mission, the child.
	MissionID string
	// ParentMissionID is the mission that the caller was dispatched in.
	ParentMissionID string
	// ParentWorkID is the work item that the caller executed when it asked.
	ParentWorkID string
	// OriginatingComponent is the FGA principal ref of the caller.
	OriginatingComponent string
	// CapabilityGrantID is the id of the active capability grant that carried
	// mission:originate at the moment of the call. It stays the answer to
	// "which grant authorized this mission" after a revocation.
	CapabilityGrantID string
}

// Kind identifies this event on the Timeline.
func (MissionOriginated) Kind() string { return "mission.originated" }

// MissionLineage is the folded lineage of one originated mission.
type MissionLineage struct {
	MissionID            string
	ParentMissionID      string
	ParentWorkID         string
	OriginatingComponent string
	CapabilityGrantID    string
}

// applyMissionOriginated folds the lineage of one mission. Lineage is a fact
// about the creation of the mission, so the first event for a mission wins and
// a later one changes nothing.
func applyMissionOriginated(w *World, e MissionOriginated) {
	if e.MissionID == "" {
		return
	}
	if _, ok := w.missionLineage[e.MissionID]; ok {
		return
	}
	w.missionLineage[e.MissionID] = MissionLineage(e)
}

// MissionLineage returns the lineage of the mission, and false for a mission
// that no component originated.
func (w *World) MissionLineage(missionID string) (MissionLineage, bool) {
	l, ok := w.missionLineage[missionID]
	return l, ok
}

// MissionLineageSnapshot returns the lineage of each originated mission, in
// deterministic (MissionID) order.
func (w *World) MissionLineageSnapshot() []MissionLineage {
	if len(w.missionLineage) == 0 {
		return nil
	}
	out := make([]MissionLineage, 0, len(w.missionLineage))
	for _, l := range w.missionLineage {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MissionID < out[j].MissionID })
	return out
}

// MissionLineage returns the lineage of the mission from the tenant World, and
// false for a mission that no component originated. Read-locked.
func (e *Engine) MissionLineage(missionID string) (MissionLineage, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.MissionLineage(missionID)
}
