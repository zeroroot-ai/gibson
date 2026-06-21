package daemon

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/brain"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/tool"
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

	caps := b.catalog()
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
