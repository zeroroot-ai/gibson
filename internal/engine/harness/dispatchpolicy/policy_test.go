// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dispatchpolicy

import (
	"testing"

	capabilitypb "github.com/zeroroot-ai/sdk/api/gen/gibson/capability/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

func TestParseShape(t *testing.T) {
	cases := map[string]DeploymentShape{
		"customer-isolation": ShapeCustomerIsolation,
		"setec-only":         ShapeSetecOnly,
		"":                   ShapeSetecOnly, // fail-closed
		"nonsense":           ShapeSetecOnly, // fail-closed
		"SETEC-ONLY":         ShapeSetecOnly, // case-sensitive; loader lower-cases first
	}
	for raw, want := range cases {
		if got := ParseShape(raw); got != want {
			t.Errorf("ParseShape(%q) = %d; want %d", raw, got, want)
		}
	}
}

// TestZeroValueIsSetecOnly pins the fail-closed property: an unwired harness
// (zero-value DeploymentShape) must be the strict shape.
func TestZeroValueIsSetecOnly(t *testing.T) {
	var s DeploymentShape
	if s != ShapeSetecOnly {
		t.Fatalf("zero-value DeploymentShape = %d; want ShapeSetecOnly", s)
	}
}

func TestDecide(t *testing.T) {
	const (
		untrusted   = componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED
		trusted     = componentpb.ContentTrust_CONTENT_TRUST_TRUSTED
		unspecified = componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED
	)
	cases := []struct {
		name       string
		placement  Placement
		trust      componentpb.ContentTrust
		hasSandbox bool
		shape      DeploymentShape
		want       Decision
	}{
		// Code in the platform's cluster with no sandbox, hosted: only a
		// stated trust runs. The unspecified case is the failing fixture: it
		// was AllowInProcess before.
		{"cluster/untrusted/no-sandbox/saas", PlacementCluster, untrusted, false, ShapeSetecOnly, Deny},
		{"cluster/unspecified/no-sandbox/saas", PlacementCluster, unspecified, false, ShapeSetecOnly, Deny},
		{"cluster/trusted/no-sandbox/saas", PlacementCluster, trusted, false, ShapeSetecOnly, AllowInProcess},
		// A component on the tenant's own machine gets queued work whatever
		// it says about itself. Untrusted was Deny before.
		{"outside/untrusted/no-sandbox/saas", PlacementOutside, untrusted, false, ShapeSetecOnly, AllowInProcess},
		{"outside/unspecified/no-sandbox/saas", PlacementOutside, unspecified, false, ShapeSetecOnly, AllowInProcess},
		{"outside/trusted/no-sandbox/saas", PlacementOutside, trusted, false, ShapeSetecOnly, AllowInProcess},
		// A sandboxed dispatch is always used.
		{"cluster/untrusted/sandbox/saas", PlacementCluster, untrusted, true, ShapeSetecOnly, RequireSetec},
		{"cluster/trusted/sandbox/saas", PlacementCluster, trusted, true, ShapeSetecOnly, RequireSetec},
		{"cluster/unspecified/sandbox/saas", PlacementCluster, unspecified, true, ShapeSetecOnly, RequireSetec},
		{"outside/untrusted/sandbox/saas", PlacementOutside, untrusted, true, ShapeSetecOnly, RequireSetec},
		{"cluster/untrusted/sandbox/onprem", PlacementCluster, untrusted, true, ShapeCustomerIsolation, RequireSetec},
		// Under customer-isolation the customer owns isolation.
		{"cluster/untrusted/no-sandbox/onprem", PlacementCluster, untrusted, false, ShapeCustomerIsolation, AllowInProcess},
		{"cluster/unspecified/no-sandbox/onprem", PlacementCluster, unspecified, false, ShapeCustomerIsolation, AllowInProcess},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decide(tc.placement, tc.trust, tc.hasSandbox, tc.shape); got != tc.want {
				t.Errorf("Decide(placement=%d, %v, sandbox=%v, shape=%d) = %d; want %d",
					tc.placement, tc.trust, tc.hasSandbox, tc.shape, got, tc.want)
			}
		})
	}
}

// TestZeroValuePlacementIsCluster pins the fail-closed property: a caller that
// does not know where a component runs gets the strict rule.
func TestZeroValuePlacementIsCluster(t *testing.T) {
	var p Placement
	if p != PlacementCluster {
		t.Fatalf("zero-value Placement = %d; want PlacementCluster", p)
	}
}

// TestIsolationAllowed is the (deployment-shape × isolation-mode) matrix from
// ADR-0110 / gibson#998: under setec-only only HOSTED_SANDBOX (and UNSPECIFIED,
// treated as HOSTED_SANDBOX) is permitted; under customer-isolation every mode
// is permitted.
func TestIsolationAllowed(t *testing.T) {
	all := []capabilitypb.IsolationMode{
		capabilitypb.IsolationMode_ISOLATION_MODE_UNSPECIFIED,
		capabilitypb.IsolationMode_ISOLATION_MODE_HOSTED_SANDBOX,
		capabilitypb.IsolationMode_ISOLATION_MODE_CUSTOMER_CLUSTER_ATTESTED,
		capabilitypb.IsolationMode_ISOLATION_MODE_CUSTOMER_SELF_SANDBOX,
		capabilitypb.IsolationMode_ISOLATION_MODE_ON_PREM_SANDBOX_ENDPOINT,
	}

	// setec-only: only UNSPECIFIED + HOSTED_SANDBOX allowed.
	setecOnlyAllowed := map[capabilitypb.IsolationMode]bool{
		capabilitypb.IsolationMode_ISOLATION_MODE_UNSPECIFIED:               true,
		capabilitypb.IsolationMode_ISOLATION_MODE_HOSTED_SANDBOX:            true,
		capabilitypb.IsolationMode_ISOLATION_MODE_CUSTOMER_CLUSTER_ATTESTED: false,
		capabilitypb.IsolationMode_ISOLATION_MODE_CUSTOMER_SELF_SANDBOX:     false,
		capabilitypb.IsolationMode_ISOLATION_MODE_ON_PREM_SANDBOX_ENDPOINT:  false,
	}
	for _, iso := range all {
		if got, want := IsolationAllowed(iso, ShapeSetecOnly), setecOnlyAllowed[iso]; got != want {
			t.Errorf("IsolationAllowed(%v, ShapeSetecOnly) = %v; want %v", iso, got, want)
		}
		// customer-isolation: every mode allowed (customer owns the boundary).
		if !IsolationAllowed(iso, ShapeCustomerIsolation) {
			t.Errorf("IsolationAllowed(%v, ShapeCustomerIsolation) = false; want true", iso)
		}
	}
}
