// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

package daemon

import "testing"

// The bank exit test calls these RPCs (tests/e2e/bank_test.go). The runner's
// method policy is an allow-list, so a suite that grows a call the policy
// does not name is denied at the daemon and the exit test reads red for a
// reason that has nothing to do with banks (gibson#13, run 35436962740).
func TestE2EPeerPolicy_CoversTheBankExitTest(t *testing.T) {
	policy := e2ePeerMethodPolicies(testTD)[e2eRunnerSVID(testTD)]
	for _, m := range []string{
		"/gibson.tenant.v1.ProviderService/CreateProvider",
		"/gibson.tenant.v1.ProviderService/DeleteProvider",
		"/gibson.bank.v1.BankService/CreateBank",
		"/gibson.bank.v1.BankService/GetBank",
		"/gibson.bank.v1.BankService/UpdateBank",
		"/gibson.bank.v1.BankService/DeleteBank",
		"/gibson.bank.v1.BankService/ListMembers",
		"/gibson.job.v1.JobService/OpenJob",
		"/gibson.job.v1.JobService/GetJob",
		"/gibson.job.v1.JobService/CloseJob",
	} {
		if !policy[m] {
			t.Errorf("the runner policy does not allow %s, which tests/e2e/bank_test.go calls", m)
		}
	}
}

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
