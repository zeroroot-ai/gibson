// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dispatchpolicy

import (
	"testing"

	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
)

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
		want       Decision
	}{
		// Code in the platform's cluster with no sandbox: only a stated
		// trust gets queued work.
		{"cluster/untrusted/no-sandbox", PlacementCluster, untrusted, false, Deny},
		{"cluster/unspecified/no-sandbox", PlacementCluster, unspecified, false, Deny},
		{"cluster/trusted/no-sandbox", PlacementCluster, trusted, false, AllowWorkQueue},
		// A component on the tenant's own machine gets queued work whatever
		// it says about itself.
		{"outside/untrusted/no-sandbox", PlacementOutside, untrusted, false, AllowWorkQueue},
		{"outside/unspecified/no-sandbox", PlacementOutside, unspecified, false, AllowWorkQueue},
		{"outside/trusted/no-sandbox", PlacementOutside, trusted, false, AllowWorkQueue},
		// A sandboxed dispatch is always used.
		{"cluster/untrusted/sandbox", PlacementCluster, untrusted, true, RequireSetec},
		{"cluster/trusted/sandbox", PlacementCluster, trusted, true, RequireSetec},
		{"cluster/unspecified/sandbox", PlacementCluster, unspecified, true, RequireSetec},
		{"outside/untrusted/sandbox", PlacementOutside, untrusted, true, RequireSetec},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Decide(tc.placement, tc.trust, tc.hasSandbox); got != tc.want {
				t.Errorf("Decide(placement=%d, %v, sandbox=%v) = %d; want %d",
					tc.placement, tc.trust, tc.hasSandbox, got, tc.want)
			}
		})
	}
}

// TestZeroValueDecisionIsDeny pins the fail-closed property: a caller that
// forgets to set a decision denies.
func TestZeroValueDecisionIsDeny(t *testing.T) {
	var d Decision
	if d != Deny {
		t.Fatalf("zero-value Decision = %d; want Deny", d)
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
