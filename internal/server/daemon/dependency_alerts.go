// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
)

// ingestDependencyAlerts maps the result of the connector tool
// list_dependency_alerts to events of the World of the tenant of the mission
// (gibson#1469). It is the one typed mapping of that result. It submits the same
// events that a scan discovery does, so the Findings take their provenance from
// the scan mission through the same Reduce path, and it never writes to the graph.
//
// The Repository is the one that the anchors of the scan wrote for this mission
// (ingest.ScanAnchorEvents). A mission with none has no place for the Findings,
// and the node fails with that reason.
func ingestDependencyAlerts(bind *missionBinding, missionID string, result any, logger *slog.Logger) error {
	if bind == nil || bind.eng == nil {
		return fmt.Errorf("the mission has no World to write the alerts to")
	}
	repo := ""
	bind.eng.ReadWorld(func(w *brain.World) {
		for _, e := range w.EntitySnapshot() {
			if e.Label == "Repository" && e.MissionID == missionID {
				repo = e.Key
			}
		}
	})
	out, err := ingest.DependencyAlertEvents(result, repo, missionID, bind.runID, time.Now().UTC())
	if err != nil {
		return err
	}
	for _, ev := range out.Events {
		bind.eng.Submit(ev)
	}
	if logger != nil {
		for _, n := range out.Notes {
			logger.Warn("dependency alerts", "mission_id", missionID, "tenant", bind.tenant, "note", n)
		}
	}
	return nil
}
