// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

// scanAlertsNodeID is the id of the alerts node of the scan mission
// (internal/platform/missioncatalog/missions/scan.cue).
const scanAlertsNodeID = "alerts"

// alertConnectors are the connectors whose list_dependency_alerts the scan ingests.
// The mission declares the same set as an enum.
var alertConnectors = map[string]bool{"github-fixloop": true, "gitlab-fixloop": true}

// isScanAlertsNode reports whether a dispatched node is the alerts node of a scan
// mission. Only that node is ingested: a TOOL node of any other mission that calls
// the same tool gets the result and no finding (gibson#1469).
func isScanAlertsNode(bind *missionBinding, req brain.DispatchRequest, tid toolid.ID) bool {
	if req.WorkID != scanAlertsNodeID || tid.Tool != ingest.DependencyAlertsTool || !alertConnectors[tid.Connector] || bind.eng == nil {
		return false
	}
	isScan := false
	bind.eng.ReadWorld(func(w *brain.World) {
		for _, m := range w.MissionSnapshot() {
			if m.ID == req.MissionID && m.Name == brain.ScanMissionName {
				isScan = true
			}
		}
	})
	return isScan
}

// dispatchScanAlerts runs the alerts node of a scan mission (gibson#1469).
//
// The input of the node is the repositoryUrl of the scan and the state. The
// daemon derives the repository key and the project from that URL with the parsing
// of the scan anchors, so the Repository is the one that the scan names and no
// race with the anchors can change it. It calls the connector on the governed
// path with the project, maps the result with ingest.DependencyAlertEvents, and
// submits the events to the World of the tenant of the mission.
//
// The branch is optional. If the call or the mapping fails (the tool is not in the
// connector, a refusal, a plan with no alerts), the node does not fail: the reason
// is the result of the node and the log, and the join goes on, so the other
// branches of the scan still finish and verify.
func (b *brainExecutor) dispatchScanAlerts(bind *missionBinding, req brain.DispatchRequest, tid toolid.ID) (string, error) {
	out, err := b.scanAlerts(bind, req, tid)
	if err != nil {
		b.logger.Warn("the dependency alerts of the scan were not read, and the scan goes on",
			"mission_id", req.MissionID, "tenant", bind.tenant, "connector", tid.Connector, "error", err)
		raw, _ := json.Marshal(map[string]string{"skipped": err.Error()})
		return string(raw), nil
	}
	return out, nil
}

func (b *brainExecutor) scanAlerts(bind *missionBinding, req brain.DispatchRequest, tid toolid.ID) (string, error) {
	var in struct {
		RepositoryURL string `json:"repositoryUrl"`
		State         string `json:"state"`
	}
	if err := json.Unmarshal([]byte(req.Input), &in); err != nil {
		return "", fmt.Errorf("the input of the node is not a JSON object: %w", err)
	}
	repoKey := ingest.RepositoryKey(in.RepositoryURL)
	project := ingest.RepositoryProject(in.RepositoryURL)
	if repoKey == "" || project == "" {
		return "", errors.New("the repository URL of the scan names no project")
	}
	state := strings.TrimSpace(in.State)
	if state == "" {
		state = "all"
	}
	res, err := b.callConnectorNode(bind, req.MissionID, req.WorkID, tid, map[string]any{"project": project, "state": state})
	if err != nil {
		return "", err
	}
	if res == nil {
		return "", errors.New("the connector returned no result")
	}
	out, err := ingest.DependencyAlertEvents(res, repoKey, project, req.MissionID, bind.runID, time.Now().UTC())
	if err != nil {
		return "", err
	}
	for _, n := range out.Notes {
		b.logger.Warn("dependency alerts", "mission_id", req.MissionID, "tenant", bind.tenant, "note", n)
	}
	for _, ev := range out.Events {
		bind.eng.Submit(ev)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return "", fmt.Errorf("encode the result: %w", err)
	}
	return string(raw), nil
}
