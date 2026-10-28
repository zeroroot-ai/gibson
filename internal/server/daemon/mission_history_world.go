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
func overlayRunsFromWorld(runs []api.MissionRunData, snapshots []brain.MissionSnapshot) {
	byRun := make(map[string]brain.MissionSnapshot, len(snapshots))
	for _, ms := range snapshots {
		if ms.RunID != "" {
			byRun[ms.RunID] = ms
		}
	}
	for i := range runs {
		ms, ok := byRun[runs[i].RunID]
		if !ok {
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
