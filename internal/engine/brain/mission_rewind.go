// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "sort"

// mission_rewind.go holds the parent of a mission that a rewind started
// (ADR-0170, gibson#804).
//
// A rewind deletes nothing. It starts a new mission at the node of a
// checkpoint, and the earlier run stays in the World as it was. The link from
// the new mission to the earlier run and its checkpoint is a Timeline event,
// so a replay of the Timeline rebuilds which run each rewind came from.

// MissionRewound records that a mission was started by a rewind of an earlier
// run. The daemon submits it before it starts the new mission.
type MissionRewound struct {
	// MissionID is the new mission.
	MissionID string
	// ParentMissionID is the earlier run that the caller rewound.
	ParentMissionID string
	// ParentCheckpointID is the checkpoint of the earlier run that the new
	// mission starts at.
	ParentCheckpointID string
	// StartSnapshot is the sandbox snapshot of the checkpoint, when the
	// earlier run kept one (ADR-0170). The node of the checkpoint then
	// starts from it.
	StartSnapshot string `json:",omitempty"`
}

// Kind identifies this event on the Timeline.
func (MissionRewound) Kind() string { return "mission.rewound" }

// MissionRewind is the folded parent of one rewound mission.
type MissionRewind struct {
	MissionID          string
	ParentMissionID    string
	ParentCheckpointID string
	StartSnapshot      string
}

// applyMissionRewound folds the parent of one mission. The parent is a fact
// about the start of the mission, so the first event for a mission wins and a
// later one changes nothing.
func applyMissionRewound(w *World, e MissionRewound) {
	if e.MissionID == "" {
		return
	}
	if _, ok := w.missionRewinds[e.MissionID]; ok {
		return
	}
	w.missionRewinds[e.MissionID] = MissionRewind(e)
}

// MissionRewind returns the parent of the mission, and false for a mission
// that no rewind started.
func (w *World) MissionRewind(missionID string) (MissionRewind, bool) {
	r, ok := w.missionRewinds[missionID]
	return r, ok
}

// MissionRewindSnapshot returns the parent of each rewound mission, in
// deterministic (MissionID) order.
func (w *World) MissionRewindSnapshot() []MissionRewind {
	if len(w.missionRewinds) == 0 {
		return nil
	}
	out := make([]MissionRewind, 0, len(w.missionRewinds))
	for _, r := range w.missionRewinds {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MissionID < out[j].MissionID })
	return out
}

// MissionRewind returns the parent of the mission from the tenant World, and
// false for a mission that no rewind started. Read-locked.
func (e *Engine) MissionRewind(missionID string) (MissionRewind, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.MissionRewind(missionID)
}
