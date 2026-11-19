// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

package daemon

import "testing"

// The A2A inbound exit test calls these RPCs with the runner SVID
// (tests/e2e/a2a_inbound_test.go). The policy is an allow-list, so a call that it
// does not name is denied at the daemon, and the exit test reads red for a reason
// that has nothing to do with the epic (run 44627735431).
func TestE2EPeerPolicy_CoversTheA2AInboundExitTest(t *testing.T) {
	policy := e2ePeerMethodPolicies(testTD)[e2eRunnerSVID(testTD)]
	for _, m := range []string{
		"/gibson.tenant.v1.InboundMissionService/PublishInboundMission",
		"/gibson.tenant.v1.InboundMissionService/UnpublishInboundMission",
		"/gibson.tenant.v1.InboundMissionService/GrantInboundCaller",
		"/gibson.tenant.v1.InboundMissionService/RevokeInboundCaller",
		"/gibson.agentidentity.v1.AgentIdentityService/CreateAgentIdentity",
		"/gibson.agentidentity.v1.AgentIdentityService/RevokeAgentIdentity",
		"/gibson.daemon.v1.DaemonService/CreateTarget",
		"/gibson.daemon.v1.DaemonService/DeleteTarget",
		"/gibson.daemon.v1.DaemonService/CreateMissionDefinition",
		"/gibson.daemon.v1.DaemonService/ListMissions",
		"/gibson.tenant.v1.MembershipService/SetCatalogEnabled",
		"/gibson.component.v1.ComponentService/RegisterComponent",
		"/gibson.component.v1.ComponentService/Heartbeat",
		"/gibson.component.v1.ComponentService/PollWork",
		"/gibson.component.v1.ComponentService/Complete",
		"/gibson.component.v1.ComponentService/SubmitResult",
		"/gibson.component.v1.ComponentService/SubmitFinding",
	} {
		if !policy[m] {
			t.Errorf("the runner policy does not allow %s, which tests/e2e/a2a_inbound_test.go calls", m)
		}
	}
}
