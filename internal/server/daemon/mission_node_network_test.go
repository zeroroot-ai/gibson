// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// The network scope of a mission node (owner decision S6, gibson#865) must
// reach the agent.Task that the harness launches. Before this, no production
// code set Task.Network, so each sandbox took the default of its class.

// projectedNetworks projects def and returns the network scope of each node.
func projectedNetworks(t *testing.T, def *missionpb.MissionDefinition, targets []forEachTarget) map[string]*agent.NodeNetwork {
	t.Helper()
	proj, _, err := missionDefinitionToProjected(def, "", targets)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	out := map[string]*agent.NodeNetwork{}
	for _, n := range proj.Nodes {
		out[n.ID] = n.Network
	}
	return out
}

func TestMissionDefinitionToProjected_CarriesTheNetworkScopeOfEachNode(t *testing.T) {
	research := agentNode("zerocool")
	research.Research = true
	def := &missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"open":  research,
			"plain": agentNode("recon"),
		},
	}
	targets := []forEachTarget{fanTarget("11111111-1111-1111-1111-111111111111", "goat", "https://10.60.0.11:6443")}

	got := projectedNetworks(t, def, targets)
	want := map[string]*agent.NodeNetwork{
		"open":  {Research: true, Targets: []string{"https://10.60.0.11:6443"}},
		"plain": {Targets: []string{"https://10.60.0.11:6443"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("network scopes = %+v, want %+v", got, want)
	}
}

// A node with no research flag and no bound target gets the zero scope: no
// research and no targets. The harness turns that into the mode none.
func TestMissionDefinitionToProjected_NodeWithNoSettingsGetsTheZeroScope(t *testing.T) {
	got := projectedNetworks(t, &missionpb.MissionDefinition{
		Id:    "m1",
		Nodes: map[string]*missionpb.MissionNode{"a": agentNode("recon")},
	}, nil)
	if n := got["a"]; n == nil || n.Research || len(n.Targets) != 0 || len(n.ProviderHosts) != 0 {
		t.Fatalf("network scope = %+v, want the zero scope", n)
	}
}

// A for_each instance is bound to its one target, not to the primary.
func TestMissionDefinitionToProjected_ForEachInstanceGetsItsOwnTarget(t *testing.T) {
	a := fanTarget("11111111-1111-1111-1111-111111111111", "goat-a", "https://10.60.0.11:6443")
	b := fanTarget("22222222-2222-2222-2222-222222222222", "goat-b", "10.60.0.12")

	got := projectedNetworks(t, forEachDef(0), []forEachTarget{a, b})
	if n := got[instanceID("scan", a.ID)]; n == nil || !reflect.DeepEqual(n.Targets, []string{"https://10.60.0.11:6443"}) {
		t.Errorf("instance a scope = %+v, want its own target", n)
	}
	if n := got[instanceID("scan", b.ID)]; n == nil || !reflect.DeepEqual(n.Targets, []string{"10.60.0.12"}) {
		t.Errorf("instance b scope = %+v, want its own target", n)
	}
}

// taskHarness records the agent.Task of each DelegateToAgent call.
type taskHarness struct {
	gibsonharness.AgentHarness
	mu    sync.Mutex
	tasks []agent.Task
}

func (h *taskHarness) DelegateToAgent(_ context.Context, _ string, task agent.Task) (agent.Result, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tasks = append(h.tasks, task)
	return agent.Result{Output: map[string]any{"ok": true}}, nil
}

func TestDispatch_AgentTaskCarriesTheNetworkScopeOfTheNode(t *testing.T) {
	scope := &agent.NodeNetwork{Research: true, Targets: []string{"10.0.0.0/24"}}

	h := &taskHarness{}
	if wc := dispatchOutcome(t, h, brain.DispatchRequest{WorkID: "w1", Kind: "agent", Target: "recon", Network: scope}); wc.Err != "" {
		t.Fatalf("dispatch failed: %s", wc.Err)
	}
	if len(h.tasks) != 1 || !reflect.DeepEqual(h.tasks[0].Network, scope) {
		t.Fatalf("tasks = %+v, want one task with the scope %+v", h.tasks, scope)
	}

	h = &taskHarness{}
	if wc := dispatchOutcome(t, h, brain.DispatchRequest{WorkID: "w2", Kind: "agent", Target: "recon"}); wc.Err != "" {
		t.Fatalf("dispatch failed: %s", wc.Err)
	}
	if len(h.tasks) != 1 || h.tasks[0].Network != nil {
		t.Fatalf("tasks = %+v, want one task with no scope", h.tasks)
	}
}

// The agent verifier of a job node runs inside that node, so its task gets
// the network scope of the node.
func TestDispatchJob_AgentVerifierTaskCarriesTheNetworkScopeOfTheNode(t *testing.T) {
	cfg, err := protojson.Marshal(&missionpb.JobNodeConfig{BankRef: "bank-1", Spec: &jobpb.JobSpec{
		Goal: "fix the build", Acceptance: &jobpb.Acceptance{VerifierComponent: "agent/reviewer", PassingScore: 0.8, MaxPasses: 1},
	}})
	if err != nil {
		t.Fatal(err)
	}
	run := func(scope *agent.NodeNetwork) []agent.Task {
		t.Helper()
		jobs := newFakeJobStore()
		jobs.onOpen = func(j *job.Job) { jobs.appendEvent(j.ID, job.EventState, job.StateWaiting, "", 0) }
		jobs.onSend = func(id string) { jobs.appendEvent(id, job.EventState, job.StateWaiting, "", 0) }
		b := newBrainExecutor(nil, testObsLogger().Slog())
		b.jobs = func() (job.Store, error) { return jobs, nil }
		b.jobClosed = &jobGraphLink{submit: func(string, brain.Event) {}, findings: func(string) map[string]string { return nil }, logger: testObsLogger().Slog()}
		h := &verifierHarness{agentOut: map[string]any{"pass": true, "score": 0.95, "report": "green"}}
		bind := &missionBinding{ctx: context.Background(), tenant: "acme", harness: h}
		if _, err := b.dispatchJob(bind, brain.DispatchRequest{
			WorkID: "run-1/fix", MissionID: "run-1", Kind: "job", Target: "bank-1", Input: string(cfg), Network: scope,
		}); err != nil {
			t.Fatalf("dispatchJob: %v", err)
		}
		return h.tasks
	}

	scope := &agent.NodeNetwork{Targets: []string{"app.example.com:8443"}}
	if tasks := run(scope); len(tasks) != 1 || !reflect.DeepEqual(tasks[0].Network, scope) {
		t.Fatalf("verifier tasks = %+v, want one task with the scope %+v", tasks, scope)
	}
	if tasks := run(nil); len(tasks) != 1 || tasks[0].Network != nil {
		t.Fatalf("verifier tasks = %+v, want one task with no scope", tasks)
	}
}
