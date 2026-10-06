// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"reflect"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
)

// TestNodeNetworkScope_ANodeReachesItsTargetsOnly is the default of S6
// (gibson#865): the bound targets on each port, the model provider and the
// daemon, and nothing else.
func TestNodeNetworkScope_ANodeReachesItsTargetsOnly(t *testing.T) {
	mode, rules := nodeNetworkScope(&agent.NodeNetwork{
		Targets:       []string{"10.0.0.0/24", "https://app.example.com:8443/login", "db.internal:5432", "scanme.example"},
		ProviderHosts: []string{"api.anthropic.com"},
	}, "gibson-daemon.gibson.svc:50051")

	if mode != sandboxed.NetworkModeAllowList {
		t.Fatalf("mode = %q; want %q", mode, sandboxed.NetworkModeAllowList)
	}
	want := []sandboxed.EgressRule{
		{CIDR: "10.0.0.0/24", Ports: allPorts},
		{Host: "app.example.com", Port: 8443},
		{Host: "db.internal", Port: 5432},
		{Host: "scanme.example", Ports: allPorts},
		{Host: "api.anthropic.com", Port: 443},
		{Host: "gibson-daemon.gibson.svc", Port: 50051},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules:\n got %+v\nwant %+v", rules, want)
	}
}

// TestNodeNetworkScope_AResearchNodeIsUnrestricted: a research node gets
// external egress and no allow list.
func TestNodeNetworkScope_AResearchNodeIsUnrestricted(t *testing.T) {
	mode, rules := nodeNetworkScope(&agent.NodeNetwork{Research: true, Targets: []string{"10.0.0.1"}}, "daemon:50051")
	if mode != sandboxed.NetworkModeExternalOnly || rules != nil {
		t.Fatalf("mode = %q, rules = %+v; want external-only and no rules", mode, rules)
	}
}

// TestNodeNetworkScope_AnEmptyListMeansNoEgress: a node with no target and no
// service gets the mode none. A value that cannot be read, and "*", widen
// nothing.
func TestNodeNetworkScope_AnEmptyListMeansNoEgress(t *testing.T) {
	for name, n := range map[string]*agent.NodeNetwork{
		"no targets":          {},
		"a wildcard":          {Targets: []string{"*"}},
		"unreadable values":   {Targets: []string{"", "  ", "host:0", "host:notaport", "a b", "://"}},
		"an unreadable cidr":  {Targets: []string{"10.0.0.0/99"}},
		"a provider wildcard": {ProviderHosts: []string{"*"}},
	} {
		t.Run(name, func(t *testing.T) {
			mode, rules := nodeNetworkScope(n)
			if mode != sandboxed.NetworkModeNone || rules != nil {
				t.Fatalf("mode = %q, rules = %+v; want none and no rules", mode, rules)
			}
		})
	}
}

// TestSplitAddress_Schemes: a URL with no port takes the port of its scheme.
func TestSplitAddress_Schemes(t *testing.T) {
	cases := map[string]struct {
		host string
		port uint32
		ok   bool
	}{
		"https://a.example":       {"a.example", 443, true},
		"http://a.example/x":      {"a.example", 80, true},
		"ssh://a.example":         {"a.example", 0, true},
		"https://a.example:70000": {"", 0, false},
		"https:///nohost":         {"", 0, false},
		"[::1]:22":                {"::1", 22, true},
	}
	for in, want := range cases {
		host, port, ok := splitAddress(in)
		if host != want.host || port != want.port || ok != want.ok {
			t.Errorf("splitAddress(%q) = %q, %d, %v; want %q, %d, %v", in, host, port, ok, want.host, want.port, want.ok)
		}
	}
}

// TestManifestTool_GetsTheNetworkOfItsNode: a tool that runs inside a node
// gets the network of that node, not the ceiling of the catalog.
func TestManifestTool_GetsTheNetworkOfItsNode(t *testing.T) {
	h := &DefaultAgentHarness{missionCtx: MissionContext{
		NodeNetwork: &agent.NodeNetwork{Targets: []string{"10.1.2.3:443"}},
	}}
	spec, ok := h.sandboxedToolSpecFromManifest("nmap")
	if !ok {
		t.Fatal("nmap must be a sandboxed manifest tool")
	}
	if spec.NetworkMode != sandboxed.NetworkModeAllowList {
		t.Fatalf("mode = %q; want %q", spec.NetworkMode, sandboxed.NetworkModeAllowList)
	}
	if want := []sandboxed.EgressRule{{Host: "10.1.2.3", Port: 443}}; !reflect.DeepEqual(spec.Egress, want) {
		t.Fatalf("egress = %+v; want %+v", spec.Egress, want)
	}

	plain := &DefaultAgentHarness{}
	spec, _ = plain.sandboxedToolSpecFromManifest("nmap")
	if spec.NetworkMode != "" {
		t.Fatalf("with no node scope the mode must stay empty, got %q", spec.NetworkMode)
	}
}

// TestDelegateToAgent_SandboxGetsTheScopeOfItsNode: the agent sandbox of a
// node gets the scope of the node with the callback endpoint, and its child
// harness is registered for the run with the same scope.
func TestDelegateToAgent_SandboxGetsTheScopeOfItsNode(t *testing.T) {
	launcher := &recordingLauncher{outcome: sandboxed.AgentRunResult{SandboxID: "sbx-1"}}
	resolver := &stubSpecResolver{spec: sandboxed.AgentLaunchSpec{
		Image: "ghcr.io/zeroroot-ai/zerocool:dev", SandboxClass: "agent",
		Egress: []sandboxed.EgressRule{{Host: "github.com", Port: 443}},
	}}
	h := newSandboxDelegateHarness(launcher, resolver, successResultQueue(t), untrustedAgentInstances(), testMinter(t))
	h.agentCallbackEndpoint = "gibson-daemon:50051"
	reg := &registrarFake{}
	h.callbackManager = reg
	var child MissionContext
	h.factory = func(_ context.Context, mc MissionContext, _ TargetInfo) (AgentHarness, error) {
		child = mc
		return h, nil
	}

	task := agent.NewTask("probe", "goal", nil)
	task.Network = &agent.NodeNetwork{Targets: []string{"10.9.9.9"}}
	_, _ = h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task)

	if launcher.calls != 1 {
		t.Fatalf("launcher calls = %d; want 1", launcher.calls)
	}
	if launcher.gotSpec.NetworkMode != sandboxed.NetworkModeAllowList {
		t.Fatalf("mode = %q; want %q", launcher.gotSpec.NetworkMode, sandboxed.NetworkModeAllowList)
	}
	want := []sandboxed.EgressRule{
		{Host: "10.9.9.9", Ports: allPorts},
		{Host: "gibson-daemon", Port: 50051},
	}
	if !reflect.DeepEqual(launcher.gotSpec.Egress, want) {
		t.Fatalf("egress = %+v; want %+v (the catalog ceiling must not widen the node)", launcher.gotSpec.Egress, want)
	}
	if len(reg.registered) != 1 || len(reg.unregistered) != 1 {
		t.Fatalf("registered = %v, unregistered = %v; want one registration for the run", reg.registered, reg.unregistered)
	}
	if child.NodeNetwork != task.Network || child.CurrentAgent != "zerocool" {
		t.Fatalf("child mission context = %+v; want the node scope and the agent name", child)
	}
}

// TestDelegateToAgent_SandboxChildHarnessFailureIsReported: when the child
// harness cannot be built, nothing launches.
func TestDelegateToAgent_SandboxChildHarnessFailureIsReported(t *testing.T) {
	launcher := &recordingLauncher{outcome: sandboxed.AgentRunResult{SandboxID: "sbx-1"}}
	resolver := &stubSpecResolver{spec: sandboxed.AgentLaunchSpec{Image: "img", SandboxClass: "agent"}}
	h := newSandboxDelegateHarness(launcher, resolver, successResultQueue(t), untrustedAgentInstances(), testMinter(t))
	h.callbackManager = &registrarFake{}
	h.factory = func(context.Context, MissionContext, TargetInfo) (AgentHarness, error) {
		return nil, context.Canceled
	}
	if _, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", agent.NewTask("p", "g", nil)); err == nil {
		t.Fatal("want an error when the child harness cannot be built")
	}
	if launcher.calls != 0 {
		t.Fatalf("launcher calls = %d; want 0", launcher.calls)
	}
}
