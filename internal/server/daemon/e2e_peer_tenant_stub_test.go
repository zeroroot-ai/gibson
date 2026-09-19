// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !test_fixtures

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/sdk/auth"
	grpcmetadata "google.golang.org/grpc/metadata"
)

// TestE2EPeerTenant_AbsentFromProductionBuilds: a production daemon never
// takes a tenant from a header on a direct-dial SPIFFE peer.
func TestE2EPeerTenant_AbsentFromProductionBuilds(t *testing.T) {
	md := grpcmetadata.Pairs(auth.HeaderTenant, "acme")
	if got := e2ePeerTenant("spiffe://zeroroot.ai/platform/e2e-runner", md); got != (auth.TenantID{}) {
		t.Fatalf("production build asserted a tenant for a SPIFFE peer: %v", got)
	}
}
