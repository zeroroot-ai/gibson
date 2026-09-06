// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
)

// TestDelegateToAgent_ManifestSandboxed_ForcesSandbox proves the S9 routing
// linchpin: a catalog agent whose manifest declares dispatchMode==sandboxed is
// LAUNCHED as an ephemeral sandbox even though its registry content trust is
// TRUSTED (unspecified). The injected agentDispatchMode seam stands in for
// componentcatalog.LookupAgent so the routing is exercised without depending on
// the embedded manifest.
func TestDelegateToAgent_ManifestSandboxed_ForcesSandbox(t *testing.T) {
	launcher := &recordingLauncher{outcome: sandboxed.AgentRunResult{SandboxID: "sbx-1", ExitCode: 0}}
	resolver := &stubSpecResolver{spec: sandboxed.AgentLaunchSpec{
		Image:        "ghcr.io/zeroroot-ai/zerocool-agent@sha256:abc",
		SandboxClass: "agent",
	}}
	q := successResultQueue(t)
	// remoteAgentInstances() is a registry-TRUSTED agent (content trust
	// unspecified) reachable only by the work queue.
	h := newSandboxDelegateHarness(launcher, resolver, q, remoteAgentInstances(), testMinter(t))
	h.agentDispatchMode = func(name string) (string, bool) {
		if name == "zerocool" {
			return componentcatalog.DispatchModeSandboxed, true
		}
		return "", false
	}

	ctx := callerCtx(t, "user-1", "zerocool-lab")
	res, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil))
	if err != nil {
		t.Fatalf("a manifest-sandboxed agent must launch, not error: %v", err)
	}
	if launcher.calls != 1 {
		t.Fatalf("launcher calls = %d; want 1 (manifest dispatchMode must force the sandbox launch)", launcher.calls)
	}
	if q.gotKind != "" {
		t.Fatalf("a forced-sandbox agent was also enqueued (gotKind=%q); it must not be", q.gotKind)
	}
	if res.Status != agent.ResultStatusCompleted {
		t.Errorf("result status = %q; want completed", res.Status)
	}
}

// TestDelegateToAgent_ManifestNotSandboxed_Passthrough is the control: with the
// seam reporting the agent is NOT sandboxed (listed=false, the default catalog
// answer for an unlisted agent), a registry-TRUSTED agent takes the unchanged
// work-queue path and the launcher is never called.
func TestDelegateToAgent_ManifestNotSandboxed_Passthrough(t *testing.T) {
	launcher := &recordingLauncher{}
	q := successResultQueue(t)
	h := newSandboxDelegateHarness(launcher, &stubSpecResolver{}, q, remoteAgentInstances(), testMinter(t))
	h.agentDispatchMode = func(string) (string, bool) { return "", false }

	ctx := callerCtx(t, "user-1", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil)); err != nil {
		t.Fatalf("a not-sandboxed trusted agent must dispatch on the unchanged path: %v", err)
	}
	if launcher.calls != 0 {
		t.Fatalf("launcher calls = %d; want 0 (a not-sandboxed agent must not be sandboxed)", launcher.calls)
	}
	if q.gotKind != "agent" {
		t.Fatalf("not-sandboxed trusted agent did not take the work-queue path (gotKind=%q)", q.gotKind)
	}
}

// TestDelegateToAgent_ManifestListedNonSandbox_Passthrough covers the branch
// where the agent IS listed but its dispatchMode is empty (route by registry
// trust): a trusted agent still takes the work-queue path.
func TestDelegateToAgent_ManifestListedNonSandbox_Passthrough(t *testing.T) {
	launcher := &recordingLauncher{}
	q := successResultQueue(t)
	h := newSandboxDelegateHarness(launcher, &stubSpecResolver{}, q, remoteAgentInstances(), testMinter(t))
	h.agentDispatchMode = func(string) (string, bool) { return "", true }

	ctx := callerCtx(t, "user-1", "zerocool-lab")
	if _, err := h.DelegateToAgent(ctx, "zerocool", agent.NewTask("probe", "goal", nil)); err != nil {
		t.Fatalf("a listed non-sandbox trusted agent must dispatch on the unchanged path: %v", err)
	}
	if launcher.calls != 0 {
		t.Fatalf("launcher calls = %d; want 0", launcher.calls)
	}
	if q.gotKind != "agent" {
		t.Fatalf("listed non-sandbox trusted agent did not take the work-queue path (gotKind=%q)", q.gotKind)
	}
}
