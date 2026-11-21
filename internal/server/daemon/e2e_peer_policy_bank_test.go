// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

package daemon

import "testing"

// The secrets isolation suite calls these admin RPCs with the runner SVID
// (tests/e2e/secrets, gibson#213). Its component calls go through the edge
// and are not in this policy.
func TestE2EPeerPolicy_CoversTheSecretsSuite(t *testing.T) {
	policy := e2ePeerMethodPolicies(testTD)[e2eRunnerSVID(testTD)]
	for _, m := range []string{
		"/gibson.agentidentity.v1.AgentIdentityService/CreateAgentIdentity",
		"/gibson.agentidentity.v1.AgentIdentityService/RevokeAgentIdentity",
		"/gibson.secrets.v1.SecretsService/SetSecret",
		"/gibson.secrets.v1.SecretsService/DeleteSecret",
	} {
		if !policy[m] {
			t.Errorf("the runner policy does not allow %s, which tests/e2e/secrets calls", m)
		}
	}
}
