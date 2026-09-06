// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

// Package e2e — tool_dispatch_test.go is the exit test for manifest-seeded TOOL
// dispatch (ADR-0017, gibson#1644; slice gibson#1659).
//
// In plain words: a tenant that switched a tool on can run it, a tenant that
// never did cannot, and nobody can run a tool that is not in the catalog.
//
// It proves that contract on a live kind cluster running the sanctioned
// setec+gvisor profile (deploy values-vanilla.yaml):
//
//  1. A tenant that ENABLED `tool/nmap` runs a TOOL-node mission to completion:
//     the manifest supplies the runtime shape, the can_execute gate admits it,
//     and the tool executes in an ephemeral setec sandbox.
//  2. A tenant that never enabled it is DENIED before anything is launched
//     (fail-closed, `authorizeToolDispatch` → SANDBOX_POLICY_DENIED).
//  3. A tool name that is in no catalog manifest never dispatches, whatever the
//     tenant has enabled — there is no second, ungated path to reach one.
//
// WHY THIS EXISTS. Until ADR-0017 a tool could reach dispatch two ways: the
// manifest path, and a runtime catalog refresher that wrote `_system` registry
// entries which dispatched with NO per-tenant check — any tenant could run any
// discovered tool. That refresher is deleted (gibson#1641, ADR-0027 hard
// cutover) and the manifest is now the single source of truth. Assertions 2 and
// 3 are what keep it that way: they fail if a second path ever returns.
//
// Per ADR-0012 this runs on `main` and on a schedule, never on a PR: it needs a
// live cluster, so it cannot gate a PR. The workflow is
// .github/workflows/exit-test-tool-dispatch.yml.
//
// Prerequisites (the workflow sets them up):
//   - GIBSON_TEST_FIXTURES_ENABLED=true       (production-safety gate, checked first)
//   - A kind cluster with the sanctioned setec+gvisor profile deployed, and the
//     daemon built with `-tags="e2e_fixtures setec_integration test_fixtures"`
//     and sandbox.enabled=true (so tool dispatch reaches the setec executor).
//   - DAEMON_GRPC_ADDR pointing at the daemon (default localhost:50002).
//
// Invocation:
//
//	GIBSON_TEST_FIXTURES_ENABLED=true \
//	  go test -tags=e2e -run TestToolDispatch ./tests/e2e/... -timeout 20m
package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/tests/e2e/helpers"
	daemonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/daemon/v1"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	// toolName is the dispatched tool, matching the catalog manifest id
	// (internal/platform/componentcatalog/manifests/nmap.yaml). nmap is the
	// tracer-bullet tool: it is generated from the executor's own --list-tools,
	// so if the generated manifests stop matching the image this test is where
	// it shows.
	toolName = "nmap"

	// toolComponentRef is the SetCatalogEnabled component_ref (kind/name, no
	// "component:" prefix). The daemon canonicalises it to component:tool/nmap.
	toolComponentRef = "tool/" + toolName

	// absentToolName is in no manifest. Nothing may ever dispatch it.
	absentToolName = "e2e-tool-that-does-not-exist"

	// toolTenant is the tenant that enables and runs the tool. The sanctioned
	// vanilla profile always provisions "primary".
	toolTenant = "primary"

	// toolDeniedTenant never enables the tool. Its dispatch must be refused.
	toolDeniedTenant = "e2e-tool-denied-tenant"
)

// The synthetic target every mission below scans. Loopback keeps the scan
// inside the sandbox: this test is about the dispatch decision, not about
// nmap's findings.
const (
	toolTargetName = "tool-e2e-target.gibson.svc.cluster.local"
	toolTargetURL  = "http://tool-e2e-target.gibson.svc.cluster.local:8080"
	toolScanHost   = "127.0.0.1"
	toolScanPorts  = "22,80,443"
)

// TestToolDispatch is the gibson#1659 exit test. Each named subtest is an
// independent assertion; the deterministic security guarantees (denial, absent
// tool) do not depend on the executor image running.
func TestToolDispatch(t *testing.T) {
	checkTestFixturesEnabled(t)

	clients, err := helpers.NewGRPCClients()
	require.NoError(t, err, "dial daemon at DAEMON_GRPC_ADDR")
	t.Cleanup(func() { _ = clients.Close() })

	membership := tenantv1.NewMembershipServiceClient(clients.Conn())

	ctxEnabled := auth.ContextWithTenantString(context.Background(), toolTenant)
	ctxDenied := auth.ContextWithTenantString(context.Background(), toolDeniedTenant)

	// Register the synthetic target both tenants' missions reference.
	targetID, err := helpers.RegisterTestTarget(context.Background(), toolTargetName, toolTargetURL)
	require.NoError(t, err, "register synthetic target")
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		helpers.DeleteTestTarget(c, targetID, toolTargetName)
	})

	// Enable the tool for one tenant ONLY. toolDeniedTenant is never enabled.
	t.Run("enable the tool for one tenant", func(t *testing.T) {
		_, err := membership.SetCatalogEnabled(ctxEnabled, &tenantv1.SetCatalogEnabledRequest{
			ComponentRef: toolComponentRef,
			Enabled:      true,
		})
		require.NoError(t, err, "SetCatalogEnabled(%s) for %q", toolComponentRef, toolTenant)
	})
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		cctx := auth.ContextWithTenantString(c, toolTenant)
		_, _ = membership.SetCatalogEnabled(cctx, &tenantv1.SetCatalogEnabledRequest{
			ComponentRef: toolComponentRef,
			Enabled:      false,
		})
	})

	// -----------------------------------------------------------------------
	// Deterministic guarantee: a tenant that never enabled the tool is denied.
	// This is the property the deleted refresher used to break — it dispatched
	// _system registry entries with no per-tenant check at all.
	// -----------------------------------------------------------------------
	t.Run("unenabled tenant is denied tool dispatch", func(t *testing.T) {
		defID := createToolMissionDefinition(t, ctxDenied, clients.Daemon, "tool-denied-e2e", toolName)

		terminal, denied := runMissionExpectingDenialOrFailure(t, ctxDenied, clients.Daemon, defID)
		require.True(t, denied,
			"a tenant that never enabled %s must be denied; got terminal state %q", toolComponentRef, terminal)
	})

	// -----------------------------------------------------------------------
	// Deterministic guarantee: a tool in no manifest never dispatches, however
	// the calling tenant is configured. There is no second path to a tool.
	// -----------------------------------------------------------------------
	t.Run("a tool in no manifest never dispatches", func(t *testing.T) {
		defID := createToolMissionDefinition(t, ctxEnabled, clients.Daemon, "tool-absent-e2e", absentToolName)

		terminal, denied := runMissionExpectingDenialOrFailure(t, ctxEnabled, clients.Daemon, defID)
		require.True(t, denied,
			"a tool with no catalog manifest must never run, even for an enabled tenant; got %q", terminal)
	})

	// -----------------------------------------------------------------------
	// Happy path: the enabled tenant's TOOL-node mission completes. This drives
	// the real signed executor image through setec, so it is the one assertion
	// that depends on the image launching.
	// -----------------------------------------------------------------------
	t.Run("enabled tenant runs the tool to completion", func(t *testing.T) {
		defID := createToolMissionDefinition(t, ctxEnabled, clients.Daemon, "tool-happy-e2e", toolName)

		runCtx, cancelRun := context.WithTimeout(ctxEnabled, 10*time.Minute)
		defer cancelRun()
		eventCh, err := helpers.Subscribe(runCtx, clients.Daemon, defID)
		require.NoError(t, err, "RunMission open for the enabled tenant")

		terminal, _, waitErr := helpers.WaitForTerminal(runCtx, eventCh, 8*time.Minute)
		require.NoError(t, waitErr, "the tool mission must reach a terminal state")
		require.Equal(t, "mission_completed", terminal.EventType,
			"an enabled tenant's tool mission must complete; got %q (error: %s)",
			terminal.EventType, terminal.Error)
	})
}

// createToolMissionDefinition creates a single-node mission definition whose one
// TOOL node runs the named tool, and returns its id.
func createToolMissionDefinition(t *testing.T, ctx context.Context, daemon daemonpb.DaemonServiceClient, name, tool string) string {
	t.Helper()
	resp, err := daemon.CreateMissionDefinition(ctx, &daemonpb.CreateMissionDefinitionRequest{
		Definition: &missionpb.MissionDefinition{
			Name:        name,
			Description: "ADR-0017 manifest-seeded tool dispatch exit test (gibson#1659)",
			Nodes: map[string]*missionpb.MissionNode{
				"tool-node": {
					Id:          "tool-node",
					Name:        "Scan",
					Description: "Runs a manifest-seeded tool in a sandbox",
					Type:        missionpb.NodeType_NODE_TYPE_TOOL,
					Config: &missionpb.MissionNode_ToolConfig{
						ToolConfig: &missionpb.ToolNodeConfig{
							ToolName: tool,
							Input: map[string]string{
								"target": toolScanHost,
								"ports":  toolScanPorts,
							},
						},
					},
				},
			},
			EntryPoints: []string{"tool-node"},
		},
	})
	require.NoError(t, err, "CreateMissionDefinition(%s)", name)
	require.NotEmpty(t, resp.GetMissionDefinitionId(), "empty mission_definition_id")
	return resp.GetMissionDefinitionId()
}
