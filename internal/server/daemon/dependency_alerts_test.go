// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/braintest"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
)

func alertResult() map[string]any {
	return map[string]any{"project": "acme/shop", "state": "all", "truncated": false, "alerts": []any{map[string]any{
		"id": "dependabot:1", "state": "open", "package": "github.com/acme/lib", "ecosystem": "go", "manifest_path": "go.mod",
		"purl": "pkg:golang/github.com/acme/lib@v1.2.0", "version": "v1.2.0", "advisory_ids": []any{"GHSA-2222-3333-4444"}, "severity": "high",
	}}}
}

// scanWorld starts a scan mission and a mission of another name in the World of
// tenant acme, and returns the engine.
func scanWorld(t *testing.T) (*brain.Registry, *brain.Engine, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := brain.NewRegistry(ctx, braintest.StoreFactory())
	eng := reg.For("acme")
	eng.Submit(brain.MissionStarted{ID: "scan-1", RunID: "run-1", Name: brain.ScanMissionName, Catalog: brain.ScanMissionName})
	eng.Submit(brain.MissionStarted{ID: "other-1", RunID: "run-2", Name: "something-else"})
	waitFor(t, func() bool {
		n := 0
		eng.ReadWorld(func(w *brain.World) { n = len(w.MissionSnapshot()) })
		return n == 2
	})
	return reg, eng, ctx
}

const scanAlertsInput = `{"repositoryUrl":"https://github.com/acme/shop.git","state":"all"}`

// Only the alerts node of a scan mission is ingested.
func TestIsScanAlertsNode_OnlyTheAlertsNodeOfAScan(t *testing.T) {
	_, eng, ctx := scanWorld(t)
	bind := &missionBinding{ctx: ctx, tenant: "acme", runID: "run-1", eng: eng}
	ok := func(node, mission, connector string) bool {
		return isScanAlertsNode(bind, brain.DispatchRequest{WorkID: brain.WorkID(mission, node), MissionID: mission}, mustToolID(t, "mcp:"+connector+":list_dependency_alerts"))
	}
	if !ok("alerts", "scan-1", "github-fixloop") || !ok("alerts", "scan-1", "gitlab-fixloop") {
		t.Fatal("the alerts node of a scan must be ingested")
	}
	if isScanAlertsNode(bind, brain.DispatchRequest{WorkID: "alerts", MissionID: "scan-1"}, mustToolID(t, "mcp:github-fixloop:list_dependency_alerts")) {
		t.Error("a bare node id is not the work id of a node")
	}
	if ok("alerts", "other-1", "github-fixloop") {
		t.Error("a mission that is not a scan must not be ingested")
	}
	if ok("some-other-node", "scan-1", "github-fixloop") {
		t.Error("another node of the scan must not be ingested")
	}
	if ok("alerts", "scan-1", "okta") {
		t.Error("a connector outside the enum must not be ingested")
	}
}

// The node derives the project from the repository URL, calls the connector with
// it, and submits the Findings, placed at the Repository of that URL, to the World
// of the tenant of the mission. Another tenant sees nothing.
func TestDispatchScanAlerts_RaisesFindingsAtTheRepositoryOfTheURL(t *testing.T) {
	reg, eng, ctx := scanWorld(t)
	conn := &fakeMissionConnector{result: alertResult()}
	b := newBrainExecutor(nil, slog.Default())
	b.connectors = conn
	bind := &missionBinding{ctx: ctx, tenant: "acme", runID: "run-1", eng: eng}
	out, err := b.dispatchTool(bind, brain.DispatchRequest{
		WorkID: brain.WorkID("scan-1", "alerts"), MissionID: "scan-1", Target: "mcp:github-fixloop:list_dependency_alerts", Input: scanAlertsInput,
	})
	if err != nil || !strings.Contains(out, "dependabot:1") {
		t.Fatalf("out = %q, err = %v", out, err)
	}
	if conn.args["project"] != "acme/shop" || conn.args["state"] != "all" {
		t.Errorf("the connector was called with %v, want the project of the URL", conn.args)
	}
	if _, has := conn.args["repositoryUrl"]; has {
		t.Error("the URL must not reach the connector")
	}
	waitFor(t, func() bool { return len(eng.Findings()) == 1 })
	f := eng.Findings()[0]
	if len(f.Places) != 1 || f.Places[0].Label != "Repository" || f.Places[0].Key != "github.com/acme/shop" {
		t.Errorf("places = %+v, want the Repository of the URL", f.Places)
	}
	if f.CheckKind != "tool" {
		t.Errorf("finding = %+v", f)
	}
	if n := len(reg.For("other").Findings()); n != 0 {
		t.Errorf("another tenant holds %d findings", n)
	}
}

// The branch is optional: a refusal, a missing tool, a result of another project
// or a result of another shape does not fail the node. The reason is its result.
func TestDispatchScanAlerts_AFailureDoesNotFailTheNode(t *testing.T) {
	_, eng, ctx := scanWorld(t)
	wrongProject := alertResult()
	wrongProject["project"] = "acme/other"
	for name, conn := range map[string]*fakeMissionConnector{
		"a refusal":       {err: errors.New("403 forbidden")},
		"another project": {result: wrongProject},
		"no alerts field": {result: map[string]any{"project": "acme/shop", "state": "all"}},
		"no result":       {},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBrainExecutor(nil, slog.Default())
			b.connectors = conn
			bind := &missionBinding{ctx: ctx, tenant: "acme", runID: "run-1", eng: eng}
			out, err := b.dispatchTool(bind, brain.DispatchRequest{ //nolint:contextcheck // the node uses the context of its binding
				WorkID: brain.WorkID("scan-1", "alerts"), MissionID: "scan-1", Target: "mcp:gitlab-fixloop:list_dependency_alerts", Input: scanAlertsInput,
			})
			if err != nil {
				t.Fatalf("the node failed: %v", err)
			}
			if !strings.Contains(out, `"skipped"`) {
				t.Errorf("the result of the node must hold the reason: %q", out)
			}
		})
	}
	if n := len(eng.Findings()); n != 0 {
		t.Errorf("a failed read raised %d findings", n)
	}
}

func mustToolID(t *testing.T, name string) toolid.ID {
	t.Helper()
	tid, err := toolid.Parse(name)
	if err != nil {
		t.Fatal(err)
	}
	return tid
}
