// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package gatewayheaders

import (
	"slices"
	"testing"
)

// The removed list holds each trusted header and each header that names the
// caller, the route or the grant. It holds no name twice.
func TestRemoved_HoldsEveryGibsonHeaderOnce(t *testing.T) {
	got := Removed()
	for _, h := range Trusted() {
		if !slices.Contains(got, h) {
			t.Errorf("Removed() does not hold the trusted header %s", h)
		}
	}
	for _, must := range []string{
		"x-capability-grant",
		"x-gibson-tenant", "x-gibson-subject", "x-gibson-mission", "x-gibson-task",
		"x-gibson-identity-subject", "x-gibson-identity-issuer", "x-gibson-identity-credential-type",
		"x-gibson-identity-tenant", "x-gibson-identity-issued-at",
		"x-gibson-route-tenant", "x-gibson-route-provider", "x-gibson-route-agent", "x-gibson-route-bank",
	} {
		if !slices.Contains(got, must) {
			t.Errorf("Removed() does not hold %s", must)
		}
	}
	seen := map[string]bool{}
	for _, h := range got {
		if seen[h] {
			t.Errorf("Removed() holds %s twice", h)
		}
		seen[h] = true
	}
}
