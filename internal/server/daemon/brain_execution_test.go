// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/tool"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/sdk/auth"
)

func TestParseDecision(t *testing.T) {
	cases := []struct {
		name string
		in   *deciderDecision
		want brain.DeciderOutput
	}{
		{"dispatch agent", &deciderDecision{Action: "dispatch", Kind: "agent", Target: "exploit", Input: "go"},
			brain.DeciderOutput{Dispatches: []brain.DeciderDispatch{{Kind: "agent", Target: "exploit", Input: "go"}}}},
		{"dispatch defaults kind to agent", &deciderDecision{Action: "DISPATCH", Target: "scan"},
			brain.DeciderOutput{Dispatches: []brain.DeciderDispatch{{Kind: "agent", Target: "scan"}}}},
		{"complete", &deciderDecision{Action: "complete", Outcome: "success", Reason: "done"},
			brain.DeciderOutput{Complete: &brain.DeciderComplete{Outcome: "success", Reason: "done"}}},
		{"wait", &deciderDecision{Action: "wait"}, brain.DeciderOutput{}},
		{"dispatch without target is wait", &deciderDecision{Action: "dispatch"}, brain.DeciderOutput{}},
		{"unknown action is wait", &deciderDecision{Action: "frobnicate"}, brain.DeciderOutput{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseDecision(c.in)
			if (got.Complete == nil) != (c.want.Complete == nil) {
				t.Fatalf("complete mismatch: got %+v want %+v", got, c.want)
			}
			if got.Complete != nil && *got.Complete != *c.want.Complete {
				t.Errorf("complete: got %+v want %+v", *got.Complete, *c.want.Complete)
			}
			if len(got.Dispatches) != len(c.want.Dispatches) {
				t.Fatalf("dispatches: got %+v want %+v", got.Dispatches, c.want.Dispatches)
			}
			for i := range got.Dispatches {
				if got.Dispatches[i] != c.want.Dispatches[i] {
					t.Errorf("dispatch[%d]: got %+v want %+v", i, got.Dispatches[i], c.want.Dispatches[i])
				}
			}
		})
	}
}

func TestParseDecision_NonPointerIsWait(t *testing.T) {
	if got := parseDecision("garbage"); got.Complete != nil || len(got.Dispatches) != 0 {
		t.Errorf("non-schema raw should be a wait, got %+v", got)
	}
}

func TestBuildDeciderPrompt_IncludesGoalCatalogAndWork(t *testing.T) {
	mc := brain.MissionContext{
		MissionID: "m1",
		Goal:      "capture the flag",
		Work: []brain.WorkSnapshot{
			{ID: "a", Kind: "tool", Target: "recon", State: brain.WorkDone, Result: "found 10.0.0.5"},
		},
		Hosts:        []brain.HostSnapshot{{Address: "10.0.0.5", OpenPorts: []int{22, 80}}},
		Capabilities: []brain.Capability{{Kind: "agent", Name: "exploit", Description: "exploit a host"}},
	}
	msgs := buildDeciderPrompt(mc)
	if len(msgs) != 2 {
		t.Fatalf("want system+user messages, got %d", len(msgs))
	}
	user := msgs[1].Content
	for _, want := range []string{"capture the flag", "exploit", "recon", "found 10.0.0.5", "10.0.0.5"} {
		if !strings.Contains(user, want) {
			t.Errorf("prompt missing %q\n---\n%s", want, user)
		}
	}
}

func TestBindingRegistry_RegisterGetUnregister(t *testing.T) {
	b := newBrainExecutor(nil, slog.Default())
	if _, ok := b.get("m1"); ok {
		t.Fatal("expected no binding before register")
	}
	bind := &missionBinding{slot: "primary"}
	b.register("m1", bind)
	got, ok := b.get("m1")
	if !ok || got != bind {
		t.Fatal("register/get failed")
	}
	b.unregister("m1")
	if _, ok := b.get("m1"); ok {
		t.Fatal("expected no binding after unregister")
	}
}

// IsMissionLive is the daemon's liveness source for capability-grant renewal
// (gibson#1602): a grant may be renewed only while the run that owns it is still
// executing. The binding window is that run, so liveness must follow it exactly —
// true from register, false again the moment the mission returns. A mission that
// was never registered is not live, so an unknown id can never buy a renewal.
func TestIsMissionLive_TracksTheBindingWindowExactly(t *testing.T) {
	b := newBrainExecutor(nil, slog.Default())

	if b.IsMissionLive("m1") {
		t.Fatal("a mission that never launched must not be live")
	}
	if b.IsMissionLive("never-existed") {
		t.Fatal("an unknown mission id must not be live")
	}

	b.register("m1", &missionBinding{slot: "primary"})
	if !b.IsMissionLive("m1") {
		t.Fatal("a registered mission must be live")
	}
	if b.IsMissionLive("m2") {
		t.Fatal("liveness must be per-mission, not global")
	}

	b.unregister("m1")
	if b.IsMissionLive("m1") {
		t.Fatal("a returned mission must not stay live — renewal would outlive its run")
	}
}

func TestDispatch_UnknownMissionDoesNotPanic(t *testing.T) {
	b := newBrainExecutor(nil, slog.Default())
	// no binding registered → logs a warning, no panic, no submit.
	b.Dispatch(brain.DispatchRequest{MissionID: "ghost", WorkID: "w1", Kind: "agent", Target: "x"})
}

// fakeDiscovery is a minimal component.ComponentDiscovery for catalog tests.
type fakeDiscovery struct {
	agents  []component.AgentInfo
	tools   []component.ToolInfo
	plugins []component.PluginInfo
}

func (f *fakeDiscovery) DiscoverAgent(context.Context, string) (agent.Agent, error) { return nil, nil }
func (f *fakeDiscovery) DiscoverTool(context.Context, string) (tool.Tool, error)    { return nil, nil }
func (f *fakeDiscovery) ListAgents(context.Context) ([]component.AgentInfo, error) {
	return f.agents, nil
}
func (f *fakeDiscovery) ListTools(context.Context) ([]component.ToolInfo, error) { return f.tools, nil }
func (f *fakeDiscovery) ListPlugins(context.Context) ([]component.PluginInfo, error) {
	return f.plugins, nil
}
func (f *fakeDiscovery) DelegateToAgent(context.Context, string, agent.Task, agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, nil
}

func TestCatalog_MapsAllKinds(t *testing.T) {
	b := newBrainExecutor(&fakeDiscovery{
		agents:  []component.AgentInfo{{Name: "recon", Description: "recon agent"}},
		tools:   []component.ToolInfo{{Name: "nmap", Description: "port scanner"}},
		plugins: []component.PluginInfo{{Name: "gitleaks", Description: "secrets", Methods: []string{"scan"}}},
	}, slog.Default())

	// The catalog is per-mission: it needs a live binding to know whose
	// components it is allowed to list.
	b.register("m1", &missionBinding{ctx: context.Background(), tenant: "acme-corp"})
	caps := b.catalog("m1")
	kinds := map[string]string{}
	for _, c := range caps {
		kinds[c.Kind] = c.Name
	}
	if kinds["agent"] != "recon" || kinds["tool"] != "nmap" || kinds["plugin"] != "gitleaks" {
		t.Fatalf("catalog missing kinds: %+v", caps)
	}
	// plugin description carries methods.
	for _, c := range caps {
		if c.Kind == "plugin" && !strings.Contains(c.Description, "scan") {
			t.Errorf("plugin desc should list methods: %q", c.Description)
		}
	}
}

// The catalog runs in the mission's tenant, not in whatever namespace a
// context-free query happens to land in. fakeTenantDiscovery records the tenant
// its context carried so the test can say which one that was.
type fakeTenantDiscovery struct {
	fakeDiscovery
	sawTenant string
}

func (f *fakeTenantDiscovery) ListAgents(ctx context.Context) ([]component.AgentInfo, error) {
	f.sawTenant = auth.TenantStringFromContext(ctx)
	return f.agents, nil
}

func TestCatalog_RunsInTheMissionTenant(t *testing.T) {
	disc := &fakeTenantDiscovery{fakeDiscovery: fakeDiscovery{
		agents: []component.AgentInfo{{Name: "recon"}},
	}}
	b := newBrainExecutor(disc, slog.Default())
	b.register("m1", &missionBinding{ctx: context.Background(), tenant: "acme-corp"})

	if caps := b.catalog("m1"); len(caps) == 0 {
		t.Fatal("catalog returned nothing for a bound mission")
	}
	if disc.sawTenant != "acme-corp" {
		t.Fatalf("catalog queried tenant %q, want the mission's tenant acme-corp", disc.sawTenant)
	}
}

// No binding, no tenant, no catalog. Falling back would offer the Decider
// capabilities belonging to whoever else is in the shared namespace.
func TestCatalog_UnboundMissionGetsNothing(t *testing.T) {
	disc := &fakeTenantDiscovery{fakeDiscovery: fakeDiscovery{
		agents: []component.AgentInfo{{Name: "recon"}},
	}}
	b := newBrainExecutor(disc, slog.Default())

	if caps := b.catalog("ghost"); len(caps) != 0 {
		t.Fatalf("unbound mission got a catalog: %+v", caps)
	}
	if disc.sawTenant != "" {
		t.Fatalf("unbound mission reached the registry as tenant %q", disc.sawTenant)
	}
}

// A binding that names no tenant is the same situation with a binding attached.
func TestCatalog_BindingWithNoTenantGetsNothing(t *testing.T) {
	disc := &fakeTenantDiscovery{fakeDiscovery: fakeDiscovery{
		agents: []component.AgentInfo{{Name: "recon"}},
	}}
	b := newBrainExecutor(disc, slog.Default())
	b.register("m1", &missionBinding{ctx: context.Background()})

	if caps := b.catalog("m1"); len(caps) != 0 {
		t.Fatalf("tenantless binding got a catalog: %+v", caps)
	}
	if disc.sawTenant != "" {
		t.Fatalf("tenantless binding reached the registry as tenant %q", disc.sawTenant)
	}
}
