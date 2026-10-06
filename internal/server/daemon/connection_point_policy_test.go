// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/server/daemon/api"
	connectionv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/connection/v1"
)

// Each caller of a connection point gets exactly its own methods on the
// direct-dial path, and no caller gets an operator method.
func TestConnectionPointPeerPolicies(t *testing.T) {
	const completer = "spiffe://zeroroot.ai/component/step-completer"
	const activation = "spiffe://zeroroot.ai/component/activation"
	policies := spiffePeerMethodPolicies(testTD, api.ConnectionPointCallers{
		SignupStepCompleter: completer,
		TenantActivation:    activation,
	})

	if got := policies[completer]; len(got) != 1 || !got[connectionv1.ConnectionPointService_CompleteSignupStep_FullMethodName] {
		t.Fatalf("completer methods = %v, want only CompleteSignupStep", got)
	}
	got := policies[activation]
	if len(got) != 2 ||
		!got[connectionv1.ConnectionPointService_SetTenantActivation_FullMethodName] ||
		!got[connectionv1.ConnectionPointService_ListTenantUsage_FullMethodName] {
		t.Fatalf("activation methods = %v, want SetTenantActivation and ListTenantUsage", got)
	}
	if policies[tenantOperatorSVID(testTD)][connectionv1.ConnectionPointService_SetTenantActivation_FullMethodName] {
		t.Fatal("the tenant operator must not reach a connection point")
	}
}

// One identity may hold both roles.
func TestConnectionPointPeerPolicies_OneIdentityForBoth(t *testing.T) {
	const both = "spiffe://zeroroot.ai/component/external"
	got := connectionPointPeerPolicies(api.ConnectionPointCallers{SignupStepCompleter: both, TenantActivation: both})
	if len(got[both]) != 3 {
		t.Fatalf("methods = %v, want all three", got[both])
	}
	if len(connectionPointPeerPolicies(api.ConnectionPointCallers{})) != 0 {
		t.Fatal("no configured caller must give no policy")
	}
}
