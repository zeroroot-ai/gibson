// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
)

func forkSpecResolver() *stubSpecResolver {
	return &stubSpecResolver{spec: sandboxed.AgentLaunchSpec{
		Image: "ghcr.io/zeroroot-ai/zerocool:dev", SandboxClass: "agent", Model: "claude-test",
	}}
}

func forkHarness(t *testing.T, launcher *recordingLauncher) (*DefaultAgentHarness, *memForkLedger) {
	t.Helper()
	ledger := newForkLedger(t)
	h := newSandboxDelegateHarness(launcher, forkSpecResolver(), successResultQueue(t), untrustedAgentInstances(), testMinter(t))
	h.forks = &ForkSupport{Parked: NewParkedSources(), Ledger: ledger}
	return h, ledger
}

// A node that a later node names parks at its result line, and the harness
// records its sandbox and the id of its grant.
func TestDelegateToAgent_ForkableNodeParks(t *testing.T) {
	launcher := &recordingLauncher{outcome: sandboxed.AgentRunResult{
		SandboxID: "ns/src-1/u0", Parked: true, Result: &sandboxed.AgentTerminalResult{Success: true, Output: "mapped"},
	}}
	h, _ := forkHarness(t, launcher)
	task := agent.NewTask("recon", "map the host", nil)
	task.NodeID, task.Forkable = "recon", true

	if _, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task); err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if !launcher.gotDispatch.Forkable {
		t.Fatal("the dispatch of a forkable node must be forkable")
	}
	src, ok := h.forks.Parked.Lookup("run-xyz", "recon")
	if !ok || src.SandboxID != "ns/src-1/u0" || src.Tenant != "zerocool-lab" || src.GrantJTI == "" {
		t.Fatalf("parked source = %+v, %v", src, ok)
	}
}

// A node with starts_from runs in a fork of the parked source, with the
// network of its own node, and its result names the snapshot.
func TestDelegateToAgent_StartsFromForksTheParkedSource(t *testing.T) {
	launcher := &recordingLauncher{
		forkIDs: []string{"ns/fork-1/u1"},
		forkRun: sandboxed.ForkRun{
			Snapshot: "snap-9",
			Results:  []sandboxed.AgentRunResult{{SandboxID: "ns/fork-1/u1", Result: &sandboxed.AgentTerminalResult{Success: true, Output: "exploited"}}},
			Errs:     []error{nil},
		},
	}
	h, ledger := forkHarness(t, launcher)
	h.forks.Parked.Park("run-xyz", "recon", ParkedSource{Tenant: "zerocool-lab", SandboxID: "ns/src-1/u0", GrantJTI: "jti-src"})

	task := agent.NewTask("exploit", "exploit the host", nil)
	task.NodeID, task.StartsFrom = "exploit", "recon"
	task.Network = &agent.NodeNetwork{Targets: []string{"10.0.0.5:443"}}

	res, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task)
	if err != nil {
		t.Fatalf("DelegateToAgent: %v", err)
	}
	if launcher.forkCalls != 1 || launcher.calls != 0 || launcher.gotSource != "ns/src-1/u0" {
		t.Fatalf("fork calls = %d, launch calls = %d, source = %q", launcher.forkCalls, launcher.calls, launcher.gotSource)
	}
	if launcher.gotFork.NetworkMode != sandboxed.NetworkModeAllowList || len(launcher.gotFork.Egress) == 0 ||
		!strings.HasPrefix(launcher.gotFork.Egress[0].Host, "10.0.0.5") {
		t.Fatalf("fork network = %q %+v; want the scope of the exploit node", launcher.gotFork.NetworkMode, launcher.gotFork.Egress)
	}
	meta, _ := res.Output["metadata"].(map[string]any)
	if meta["snapshot"] != "snap-9" || meta["starts_from"] != "recon" {
		t.Fatalf("result metadata = %v", meta)
	}
	d, err := ledger.Claim(context.Background(), "ns/fork-1/u1")
	if err != nil || d.NodeID != "exploit" || d.Tenant == "" || d.AgentName == "" {
		t.Fatalf("claim = %+v, %v", d, err)
	}
}

// A node whose source is not parked fails with a clear error and does not
// start in a fresh sandbox.
func TestDelegateToAgent_StartsFromWithNoParkedSourceFails(t *testing.T) {
	launcher := &recordingLauncher{}
	h, _ := forkHarness(t, launcher)
	task := agent.NewTask("exploit", "x", nil)
	task.NodeID, task.StartsFrom = "exploit", "recon"

	_, err := h.DelegateToAgent(callerCtx(t, "user-1", "zerocool-lab"), "zerocool", task)
	if err == nil || !strings.Contains(err.Error(), "no parked sandbox") {
		t.Fatalf("err = %v; want the missing source error", err)
	}
	if launcher.calls != 0 || launcher.forkCalls != 0 {
		t.Fatal("a node with a missing source must not start")
	}
}

// Each other refusal of the fork path.
func TestDelegateToAgent_StartsFromRefusals(t *testing.T) {
	task := agent.NewTask("exploit", "x", nil)
	task.NodeID, task.StartsFrom = "exploit", "recon"
	ctx := callerCtx(t, "user-1", "zerocool-lab")

	h := newSandboxDelegateHarness(&recordingLauncher{}, forkSpecResolver(), successResultQueue(t), untrustedAgentInstances(), testMinter(t))
	if _, err := h.DelegateToAgent(ctx, "zerocool", task); err == nil || !strings.Contains(err.Error(), "no fork support") {
		t.Errorf("no fork support: err = %v", err)
	}

	h, _ = forkHarness(t, &recordingLauncher{})
	h.forks.Parked.Park("run-xyz", "recon", ParkedSource{Tenant: "other", SandboxID: "s", GrantJTI: "j"})
	if _, err := h.DelegateToAgent(ctx, "zerocool", task); err == nil || !strings.Contains(err.Error(), "another tenant") {
		t.Errorf("other tenant: err = %v", err)
	}

	h, _ = forkHarness(t, &recordingLauncher{})
	h.forks.Parked.Park("run-xyz", "recon", ParkedSource{Tenant: "zerocool-lab", SandboxID: "s"})
	if _, err := h.DelegateToAgent(ctx, "zerocool", task); err == nil || !strings.Contains(err.Error(), "no id") {
		t.Errorf("grant with no id: err = %v", err)
	}

	l := &recordingLauncher{forkErr: errors.New("source gone")}
	h, _ = forkHarness(t, l)
	h.forks.Parked.Park("run-xyz", "recon", ParkedSource{Tenant: "zerocool-lab", SandboxID: "s", GrantJTI: "j"})
	if _, err := h.DelegateToAgent(ctx, "zerocool", task); err == nil || !strings.Contains(err.Error(), "agent fork failed") {
		t.Errorf("fork error: err = %v", err)
	}

	l = &recordingLauncher{forkIDs: []string{"f"}, forkRun: sandboxed.ForkRun{
		Results: []sandboxed.AgentRunResult{{}}, Errs: []error{errors.New("fork died")},
	}}
	h, _ = forkHarness(t, l)
	h.forks.Parked.Park("run-xyz", "recon", ParkedSource{Tenant: "zerocool-lab", SandboxID: "s", GrantJTI: "j"})
	if _, err := h.DelegateToAgent(ctx, "zerocool", task); err == nil || !strings.Contains(err.Error(), "fork run failed") {
		t.Errorf("fork run error: err = %v", err)
	}
}

func TestGrantJTI(t *testing.T) {
	if grantJTI("") != "" || grantJTI("a.b") != "" || grantJTI("a.!!!.c") != "" || grantJTI("a.bm90IGpzb24.c") != "" {
		t.Error("an unreadable grant must have no id")
	}
	// {"jti":"j-1"}
	if got := grantJTI("x.eyJqdGkiOiJqLTEifQ.y"); got != "j-1" {
		t.Errorf("grantJTI = %q, want j-1", got)
	}
}
