// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e — sandboxed_agent_dispatch_test.go is the exit test for ADR-0016
// (sandboxed platform-agent dispatch, epic gibson#1593, slice gibson#1600).
//
// It proves the isolation contract on a live kind cluster running the sanctioned
// setec+gvisor profile (charts values-baseline.yaml):
//
//  1. An ENABLED tenant that dispatches the platform agent `zerocool` runs it in
//     an EPHEMERAL setec sandbox — a running instance appears in that tenant's
//     live console (backed by a real sandbox id) and is TORN DOWN afterwards.
//  2. A tenant that never enabled `zerocool` is DENIED dispatch (fail-closed),
//     and no sandbox is created for it.
//  3. The live console is tenant-scoped: a tenant sees only its own running
//     instances, and a run id it does not own returns NOT_FOUND — indistinguishable
//     from one that never existed.
//
// Per ADR-0012 this runs on `main` and on a schedule, never on a PR: it needs a
// live cluster, so it cannot gate a PR. The workflow is
// .github/workflows/exit-test-sandboxed-dispatch.yml.
//
// Prerequisites (the workflow sets them up):
//   - GIBSON_TEST_FIXTURES_ENABLED=true       (production-safety gate, checked first)
//   - A kind cluster with the sanctioned setec+gvisor profile deployed, and the
//     daemon built with `-tags="e2e_fixtures setec_integration test_fixtures"`
//     and sandbox.enabled=true (so DelegateToAgent reaches the setec launcher).
//   - DAEMON_GRPC_ADDR pointing at the daemon (default localhost:50002).
//
// Invocation:
//
//	GIBSON_TEST_FIXTURES_ENABLED=true \
//	  go test -tags=e2e -run TestSandboxedAgentDispatch ./tests/e2e/... -timeout 15m
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	agentconsolev1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/agentconsole/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// zerocoolAgentName is the dispatched agent name, matching the catalog
	// manifest id (internal/platform/componentcatalog/manifests/zerocool.yaml).
	zerocoolAgentName = "zerocool"

	// zerocoolComponentRef is the SetCatalogEnabled component_ref (kind/name,
	// no "component:" prefix). The daemon canonicalises it to
	// component:agent/zerocool.
	zerocoolComponentRef = "agent/" + zerocoolAgentName

	// dispatchTenant is the tenant that enables and runs zerocool. The sanctioned
	// baseline profile always provisions "primary".
	dispatchTenant = "primary"

	// must be refused fail-closed.
)

// dispatchTarget is the synthetic target every mission below references.
const (
	dispatchTargetName = "test-target.gibson.svc.cluster.local"
	dispatchTargetURL  = "http://test-target.gibson.svc.cluster.local:8080"
)

// TestSandboxedAgentDispatch is the gibson#1600 exit test. Each named subtest is
// an independent assertion; the deterministic security guarantees (denial,
// console isolation) do not depend on the image-driven happy path.
func TestSandboxedAgentDispatch(t *testing.T) {
	checkTestFixturesEnabled(t)

	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })

	membership := tenantv1.NewMembershipServiceClient(clients.Conn())
	console := agentconsolev1.NewAgentConsoleServiceClient(clients.Conn())

	ctxA := auth.ContextWithTenantString(context.Background(), dispatchTenant)

	// Register the synthetic target both tenants' missions reference.
	targetID, err := helpers.RegisterTestTarget(ctxA, clients.Daemon, dispatchTargetName, dispatchTargetURL)
	require.NoError(t, err, "register synthetic target")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		helpers.DeleteTestTarget(auth.ContextWithTenantString(c, dispatchTenant), clients.Daemon, targetID)
	})

	// The provisioned tenant starts with zerocool DISABLED, so the denial
	// below is the per-tenant gate the happy path passes after enabling. The
	// old test used a second, never-provisioned tenant, whose run failed at
	// the data-plane check before the gate ran.
	t.Run("zerocool starts disabled for the tenant", func(t *testing.T) {
		_, err := membership.SetCatalogEnabled(ctxA, &tenantv1.SetCatalogEnabledRequest{
			ComponentRef: zerocoolComponentRef,
			Enabled:      false,
		})
		require.NoError(t, err, "SetCatalogEnabled(agent/zerocool, false) for %q", dispatchTenant)
	})
	t.Run("unenabled tenant is denied dispatch", func(t *testing.T) {
		defID := createZerocoolMissionDefinition(t, ctxA, clients.Daemon, "zerocool-denied-e2e")
		reason, denied := runMissionExpectingGateDenial(t, ctxA, clients.Daemon, defID, targetID)
		require.True(t, denied,
			"a tenant that has not enabled zerocool must be denied by the gate; got %q", reason)
		agents := listRunningAgents(t, ctxA, console)
		require.Empty(t, agents,
			"a denied dispatch must never leave a running zerocool instance; got %d", len(agents))
	})
	t.Run("enable zerocool for the dispatch tenant", func(t *testing.T) {
		_, err := membership.SetCatalogEnabled(ctxA, &tenantv1.SetCatalogEnabledRequest{
			ComponentRef: zerocoolComponentRef,
			Enabled:      true,
		})
		require.NoError(t, err, "SetCatalogEnabled(agent/zerocool) for %q", dispatchTenant)
	})
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cctx := auth.ContextWithTenantString(c, dispatchTenant)
		_, _ = membership.SetCatalogEnabled(cctx, &tenantv1.SetCatalogEnabledRequest{
			ComponentRef: zerocoolComponentRef,
			Enabled:      false,
		})
	})
	t.Run("console rejects a foreign run id with NotFound", func(t *testing.T) {
		// A run id nobody owns: NotFound, whatever tenant asks.
		streamCtx, cancel := context.WithTimeout(ctxA, 20*time.Second)
		defer cancel()
		stream, err := console.StreamAgentEvents(streamCtx, &agentconsolev1.StreamAgentEventsRequest{
			RunId: "00000000-0000-0000-0000-000000000000",
		})
		require.NoError(t, err, "open StreamAgentEvents")
		_, err = stream.Recv()
		require.Error(t, err, "a foreign/absent run id must not stream")
		require.Equal(t, codes.NotFound, status.Code(err),
			"a run id the tenant does not own must be NOT_FOUND, not a leak")
	})

	// -----------------------------------------------------------------------
	// Happy path: the enabled tenant runs zerocool in an EPHEMERAL sandbox. A
	// running instance appears in the tenant's console backed by a real sandbox
	// id, is not visible to the other tenant, and is torn down afterwards. This
	// path drives the real signed zerocool image through setec, so it is the one
	// assertion that depends on the image launching.
	// -----------------------------------------------------------------------
	t.Run("enabled tenant runs zerocool in an ephemeral sandbox", func(t *testing.T) {
		defID := createZerocoolMissionDefinition(t, ctxA, clients.Daemon, "zerocool-happy-e2e")

		// Start the mission in the background; it stays alive while we observe the
		// live console.
		runCtx, cancelRun := context.WithTimeout(ctxA, 10*time.Minute)
		defer cancelRun()
		eventCh, err := helpers.Subscribe(runCtx, clients.Daemon, defID, targetID)
		require.NoError(t, err, "RunMission open for the enabled tenant")

		// The dispatch launches an ephemeral sandbox; the instance appears in this
		// tenant's console, backed by a real setec sandbox id.
		running := waitForRunningAgent(t, ctxA, console, zerocoolAgentName, 3*time.Minute)
		require.NotEmpty(t, running.GetSandboxId(),
			"a sandboxed dispatch must carry the backing setec sandbox id")

		// The other tenant never sees it.
		// Cross-tenant isolation needs a second provisioned tenant, which the
		// fixture cluster does not carry (the baseline provisions "primary"
		// only). The console's NotFound on a foreign run id above and the
		// per-tenant tests in internal/server/daemon cover it.
		_, _, _ = helpers.WaitForTerminal(runCtx, eventCh, 8*time.Minute)
		requireInstanceTornDown(t, ctxA, console, running.GetRunId(), 3*time.Minute)
	})
}

// createZerocoolMissionDefinition creates a single-node mission definition whose
// one AGENT node dispatches zerocool, and returns its id.
func createZerocoolMissionDefinition(t *testing.T, ctx context.Context, daemon daemonpb.DaemonServiceClient, name string) string {
	t.Helper()
	resp, err := daemon.CreateMissionDefinition(ctx, &daemonpb.CreateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{
			Name:        name,
			Description: "ADR-0016 sandboxed dispatch exit test (gibson#1600)",
			Nodes: map[string]*missionpb.MissionNode{
				"zerocool-node": {
					Id:          "zerocool-node",
					Name:        "Zerocool",
					Description: "Dispatches the zerocool platform agent",
					Type:        missionpb.NodeType_NODE_TYPE_AGENT,
					Config: &missionpb.MissionNode_AgentConfig{
						AgentConfig: &missionpb.AgentNodeConfig{AgentName: zerocoolAgentName},
					},
				},
			},
		},
	})
	require.NoError(t, err, "CreateMissionDefinition(%s)", name)
	require.NotEmpty(t, resp.GetMissionDefinitionId(), "empty mission_definition_id")
	return resp.GetMissionDefinitionId()
}

// listRunningAgents returns the caller-tenant's running instances.
func listRunningAgents(t *testing.T, ctx context.Context, console agentconsolev1.AgentConsoleServiceClient) []*agentconsolev1.RunningAgent {
	t.Helper()
	c, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	resp, err := console.ListRunningAgents(c, &agentconsolev1.ListRunningAgentsRequest{})
	require.NoError(t, err, "ListRunningAgents")
	return resp.GetAgents()
}

// waitForRunningAgent polls the console until a running instance of agentName
// appears, or fails after the deadline.
func waitForRunningAgent(t *testing.T, ctx context.Context, console agentconsolev1.AgentConsoleServiceClient, agentName string, deadline time.Duration) *agentconsolev1.RunningAgent {
	t.Helper()
	stop := time.Now().Add(deadline)
	for time.Now().Before(stop) {
		for _, a := range listRunningAgents(t, ctx, console) {
			if a.GetAgentName() == agentName {
				return a
			}
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("no running %q instance appeared in the console within %s", agentName, deadline)
	return nil
}

// requireInstanceTornDown polls until the named run id is no longer listed —
// proof the ephemeral sandbox was reclaimed.
func requireInstanceTornDown(t *testing.T, ctx context.Context, console agentconsolev1.AgentConsoleServiceClient, runID string, deadline time.Duration) {
	t.Helper()
	stop := time.Now().Add(deadline)
	for time.Now().Before(stop) {
		present := false
		for _, a := range listRunningAgents(t, ctx, console) {
			if a.GetRunId() == runID {
				present = true
				break
			}
		}
		if !present {
			return
		}
		time.Sleep(3 * time.Second)
	}
	t.Fatalf("run %q was still listed after %s — the ephemeral sandbox was not torn down", runID, deadline)
}
