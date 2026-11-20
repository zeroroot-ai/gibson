// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package missioncatalog

import (
	"context"
	"slices"
	"strings"
	"testing"

	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// incidentAgent is the agent that the incident response mission names. It is
// not in the component catalog (gibson#1478), so a dispatch of an agent node
// fails until the manifest exists. The catalog test does not check the name of
// an agent.
const incidentAgent = "incident-response"

func renderIncident(t *testing.T) *missionv1.MissionDefinition {
	t.Helper()
	def, err := Render(context.Background(), "incident-response", paramsFor(t, "incident-response"))
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return def
}

// The mission runs in the order of the issue: read the alert, reach, contain,
// cause, fix, release, report. The release is after the fix, and the report is
// the one exit.
func TestRender_IncidentResponseRunsInOrder(t *testing.T) {
	def := renderIncident(t)
	nodes := def.GetNodes()
	for _, id := range []string{"triage", "reach", "contain", "isolate", "cause", "fix", "release", "releaseWorkloads", "report"} {
		if nodes[id] == nil {
			t.Fatalf("node %q is missing", id)
		}
	}
	wantDeps := map[string][]string{
		"reach":            {"triage"},
		"contain":          {"reach"},
		"isolate":          {"reach"},
		"cause":            {"contain", "isolate"},
		"fix":              {"cause"},
		"release":          {"fix"},
		"releaseWorkloads": {"fix"},
		"report":           {"release", "releaseWorkloads"},
	}
	for id, want := range wantDeps {
		got := append([]string(nil), nodes[id].GetDependencies()...)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("node %q depends on %v, want %v", id, got, want)
		}
	}
	if got := def.GetEntryPoints(); len(got) != 1 || got[0] != "triage" {
		t.Errorf("entryPoints = %v, want [triage]", got)
	}
	if got := def.GetExitPoints(); len(got) != 1 || got[0] != "report" {
		t.Errorf("exitPoints = %v, want [report]", got)
	}
	if got := nodes["report"].GetType(); got != missionv1.NodeType_NODE_TYPE_JOIN {
		t.Errorf("report type = %v, want JOIN", got)
	}
}

// The mission has no schedule and no trigger (ADR-0177), and it names no host.
// The five parameters are the whole input.
func TestRender_IncidentResponseTakesOnlyItsFiveParameters(t *testing.T) {
	got := declaredParams(t, "incident-response")
	want := []string{"alertId", "bank", "forgeConnector", "manifestsProject", "observabilityConnector"}
	if !slices.Equal(got, want) {
		t.Errorf("declared parameters = %v, want %v", got, want)
	}
	bad := paramsFor(t, "incident-response")
	bad["host"] = "evil.example.com"
	if _, err := Render(context.Background(), "incident-response", bad); err == nil {
		t.Error("a host parameter must be refused")
	}
}

// The alert reaches the nodes that read it, and no node raises a finding for
// the alert (ADR-0177: an alert is never a finding).
func TestRender_IncidentResponseNeverMakesAFindingOfAnAlert(t *testing.T) {
	def := renderIncident(t)
	params := paramsFor(t, "incident-response")
	triage := def.GetNodes()["triage"].GetAgentConfig().GetTask()
	if !strings.Contains(triage.GetGoal(), params["alertId"]) {
		t.Errorf("the triage goal does not name the alert: %q", triage.GetGoal())
	}
	if got := triage.GetContext()["alert.id"].GetStringValue(); got != params["alertId"] {
		t.Errorf("alert.id = %q, want %q", got, params["alertId"])
	}
	if !strings.Contains(triage.GetGoal(), "Do not raise a finding for the alert") {
		t.Errorf("the triage goal must forbid a finding for the alert: %q", triage.GetGoal())
	}
	// Only the cause step raises a finding.
	for id, n := range def.GetNodes() {
		if id == "cause" || n.GetType() != missionv1.NodeType_NODE_TYPE_AGENT {
			continue
		}
		if strings.Contains(n.GetAgentConfig().GetTask().GetGoal(), "Raise one finding") {
			t.Errorf("node %q raises a finding. Only the cause step does", id)
		}
	}
	cause := def.GetNodes()["cause"].GetAgentConfig().GetTask().GetGoal()
	if !strings.Contains(cause, "CAUSED_BY") {
		t.Errorf("the cause goal must link the Incident node with CAUSED_BY: %q", cause)
	}
}

// A response action outside the grant is refused by the daemon, and the
// mission records it. The goal says so, and it says not to retry.
func TestRender_IncidentResponseRecordsARefusedAction(t *testing.T) {
	def := renderIncident(t)
	contain := def.GetNodes()["contain"].GetAgentConfig().GetTask()
	for _, phrase := range []string{
		"refuses a call that your grant does not allow",
		"pending authorization",
		"do not retry it",
		"refused.<tool id>",
		"Go on with the next action",
	} {
		if !strings.Contains(contain.GetGoal(), phrase) {
			t.Errorf("the contain goal does not say %q: %q", phrase, contain.GetGoal())
		}
	}
	tools := contain.GetContext()["response.tools.identity"].GetStringValue() + "," +
		contain.GetContext()["response.tools.host"].GetStringValue()
	for _, id := range []string{
		"mcp:okta:revoke_user_sessions", "mcp:entra-id:disable_account",
		"mcp:crowdstrike:contain_host", "mcp:defender-endpoint:isolate_device",
		"mcp:sentinelone:disconnect_from_network",
	} {
		if !strings.Contains(tools, id) {
			t.Errorf("the contain context does not name %q", id)
		}
	}
}

// Each containment has its release, and the release runs only after the fix and
// only for a verified finding. The health signal rule does not apply to a
// containment (ADR-0180).
func TestRender_IncidentResponseReleasesOnlyAfterTheCauseIsVerified(t *testing.T) {
	def := renderIncident(t)
	for _, id := range []string{"release", "releaseWorkloads"} {
		n := def.GetNodes()[id]
		var goal string
		if n.GetType() == missionv1.NodeType_NODE_TYPE_AGENT {
			goal = n.GetAgentConfig().GetTask().GetGoal()
		} else {
			goal = n.GetJobConfig().GetSpec().GetGoal()
		}
		if !strings.Contains(goal, "When the status is verified") || !strings.Contains(goal, "not verified") {
			t.Errorf("node %q must act only on a verified finding: %q", id, goal)
		}
		if !strings.Contains(goal, "Do not read the health signal") {
			t.Errorf("node %q must not apply the health signal rule to a containment: %q", id, goal)
		}
	}
	rel := def.GetNodes()["release"].GetAgentConfig().GetTask().GetContext()
	for _, id := range []string{"mcp:crowdstrike:lift_containment", "mcp:defender-endpoint:release_device",
		"mcp:sentinelone:reconnect_to_network", "mcp:okta:unsuspend_user", "mcp:entra-id:enable_account"} {
		joined := rel["release.tools.identity"].GetStringValue() + "," + rel["release.tools.host"].GetStringValue()
		if !strings.Contains(joined, id) {
			t.Errorf("the release context does not name %q", id)
		}
	}
	fix := def.GetNodes()["fix"].GetJobConfig().GetSpec().GetGoal()
	if !strings.Contains(fix, "prometheus-core") || !strings.Contains(fix, "revert your merge") {
		t.Errorf("the fix must read the health signal and revert: %q", fix)
	}
}

// The workload isolation goes through the GitOps repo as a merge request. No
// node of the mission is a tool node, so the mission changes no cluster directly.
func TestRender_IncidentResponseIsolatesAWorkloadOnlyThroughAMergeRequest(t *testing.T) {
	def := renderIncident(t)
	for id, n := range def.GetNodes() {
		if n.GetType() == missionv1.NodeType_NODE_TYPE_TOOL {
			t.Errorf("node %q is a tool node. The mission makes no direct change", id)
		}
	}
	for _, id := range []string{"isolate", "fix", "releaseWorkloads"} {
		spec := def.GetNodes()[id].GetJobConfig().GetSpec()
		if len(spec.GetRepositories()) != 1 {
			t.Fatalf("node %q has %d repositories, want 1", id, len(spec.GetRepositories()))
		}
		repo := spec.GetRepositories()[0]
		if repo.GetConnectorRef() != "connector/gitlab-core" || repo.GetProject() != "examplebank/cluster-manifests" {
			t.Errorf("node %q repository = %v", id, repo)
		}
		if got := def.GetNodes()[id].GetJobConfig().GetBankRef(); got != "bank/blue-team" {
			t.Errorf("node %q bank = %q", id, got)
		}
	}
}

// The agent is the one agent that is not in the catalog yet. Each agent node
// names it, so a dispatch fails with one clear cause.
func TestRender_IncidentResponseNamesOneAgent(t *testing.T) {
	def := renderIncident(t)
	for id, n := range def.GetNodes() {
		if n.GetType() != missionv1.NodeType_NODE_TYPE_AGENT {
			continue
		}
		if got := n.GetAgentConfig().GetAgentName(); got != incidentAgent {
			t.Errorf("node %q agent = %q, want %q", id, got, incidentAgent)
		}
	}
}
