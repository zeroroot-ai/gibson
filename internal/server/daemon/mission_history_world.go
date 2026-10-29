// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
)

// overlayRunsFromWorld sets the live fields of each run from the World, the one
// source of mission state (ADR-0163, gibson#1118). The run store holds a run
// once, at its start, with the status "running". Nothing writes it again, so the
// history of a finished run read "running" for ever while ListMissions showed it
// completed or failed (gibson#1340). A snapshot is matched on the run id. A run
// that the World does not hold keeps what the store has.
//
// Status, Error, Progress and FindingsCount come from the snapshot. The error
// is the reason of a failed run only. A run that did not fail has none.
//
// The World holds one snapshot for each mission, and it is the snapshot of the
// newest run. An earlier run of the same mission has no snapshot. Only one run
// of a mission is active at a time, so an earlier run that the store still holds
// as not ended has ended, and its outcome is not in the World. It reads
// StatusRunUnknown and not "running".
// StatusRunUnknown is the status of a run that has ended and whose outcome the
// World does not hold: an earlier run of a mission that has run again.
const StatusRunUnknown = "unknown"

// isEndedRunStatus reports whether a stored run status is an end state.
func isEndedRunStatus(status string) bool {
	switch status {
	case "completed", "failed", "cancelled", StatusRunUnknown:
		return true
	}
	return false
}

func overlayRunsFromWorld(runs []api.MissionRunData, snapshots []brain.MissionSnapshot) {
	byRun := make(map[string]brain.MissionSnapshot, len(snapshots))
	newestOf := make(map[string]string, len(snapshots)) // mission id -> run id of its snapshot
	for _, ms := range snapshots {
		if ms.RunID != "" {
			byRun[ms.RunID] = ms
			newestOf[ms.ID] = ms.RunID
		}
	}
	for i := range runs {
		ms, ok := byRun[runs[i].RunID]
		if !ok {
			if newest, held := newestOf[runs[i].MissionID]; held && newest != runs[i].RunID && !isEndedRunStatus(runs[i].Status) {
				runs[i].Status = StatusRunUnknown
			}
			continue
		}
		runs[i].Status = string(ms.Status)
		runs[i].Progress = ms.Progress
		runs[i].FindingsCount = int(ms.FindingsCount)
		if ms.Status == brain.MissionFailed {
			runs[i].Error = ms.Reason
		} else {
			runs[i].Error = ""
		}
	}
}
