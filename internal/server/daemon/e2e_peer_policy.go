// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

// e2e_peer_policy.go — the exit-test runner's direct-dial identity.
//
// ONLY compiled with -tags=test_fixtures. Production `make bin` never passes
// that flag, so this identity and its method policy are absent from production
// binaries entirely — see e2e_peer_policy_stub.go.
//
// WHY THIS EXISTS. The daemon's gRPC listener speaks SPIFFE mTLS and nothing
// else: it refuses to bind a non-loopback plaintext listener at all
// (zero-trust-hardening Req 1.2). An exit test therefore cannot dial it from a
// CI runner over a port-forward — it must be a peer inside the mesh with an
// attested SVID. ADR-0002 additionally requires every direct-dial peer to carry
// an explicit method policy, or the daemon fails closed at boot.
//
// So the suite gets an identity like any other control-plane caller, rather
// than the daemon getting a hole. Spec: gibson#1642.

package daemon

import (
	"github.com/zeroroot-ai/sdk/auth"
	grpcmetadata "google.golang.org/grpc/metadata"
)

// e2eRunnerSVID is the exit-test suite's identity. The deploy chart registers a
// ClusterSPIFFEID for the runner's ServiceAccount that mints exactly this ID,
// and lists it in allowedPeerIDs for the kind test profile only.
const e2eRunnerSVID = "spiffe://zeroroot.ai/platform/e2e-runner"

// e2ePeerMethodPolicies grants the exit-test runner the methods its assertions
// need, and only those.
//
// It is deliberately NOT "allow everything". An e2e suite that can call any RPC
// stops being able to prove that a denial is a denial — if the harness has more
// authority than the thing under test, a passing assertion says nothing. These
// are the RPCs tests/e2e/tool_dispatch_test.go and
// tests/e2e/sandboxed_agent_dispatch_test.go actually use.
func e2ePeerMethodPolicies() map[string]map[string]bool {
	return map[string]map[string]bool{
		e2eRunnerSVID: {
			// Per-tenant enablement — the gate the tool/agent tests toggle.
			"/gibson.tenant.v1.MembershipService/SetCatalogEnabled": true,
			// Mission definition + run: how a tool or agent is actually dispatched.
			// The synthetic scan target the suite runs its missions against.
			// It is created through the API, never written into Redis: the
			// state client keys every tenant's targets under its own prefix,
			// and a document planted at the raw key is "not found" to the run
			// (gibson#14, run 35421412151).
			"/gibson.daemon.v1.DaemonService/CreateTarget":            true,
			"/gibson.daemon.v1.DaemonService/DeleteTarget":            true,
			"/gibson.daemon.v1.DaemonService/CreateMissionDefinition": true,
			"/gibson.daemon.v1.DaemonService/RunMission":              true,
			"/gibson.daemon.v1.DaemonService/GetMission":              true,
			// The live console assertions (tenant-scoped visibility).
			"/gibson.daemon.agentconsole.v1.AgentConsoleService/ListRunningAgents": true,
			"/gibson.daemon.agentconsole.v1.AgentConsoleService/StreamAgentEvents": true,
		},
	}
}

// e2ePeerTenant is the tenant the exit-test runner asserts for a tenant-scoped
// RPC. A direct-dial SPIFFE peer gets an identity with no tenant (its SVID
// names a platform component, not a tenant), and the suite's assertions are
// tenant-scoped by design: it enables a tool for one tenant and proves the
// other is denied. So the runner, and only the runner, carries the tenant in
// x-gibson-identity-tenant, the header ext-authz would set on the edge path,
// and the daemon takes it at face value because the SVID already proves who
// is asking and this file exists only in the fixture build. A malformed or
// absent header yields the zero tenant, which the handler refuses as before.
func e2ePeerTenant(svid string, md grpcmetadata.MD) auth.TenantID {
	if svid != e2eRunnerSVID {
		return auth.TenantID{}
	}
	vals := md.Get(auth.HeaderTenant)
	if len(vals) == 0 || vals[0] == "" {
		return auth.TenantID{}
	}
	t, err := auth.NewTenantID(vals[0])
	if err != nil {
		return auth.TenantID{}
	}
	return t
}
