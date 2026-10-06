// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build test_fixtures

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/sdk/auth"
	grpcmetadata "google.golang.org/grpc/metadata"
)

// TestE2EPeerTenant: the runner's SVID may assert a tenant through the
// identity header; any other SVID, a missing header or a malformed tenant
// yields the zero tenant.
func TestE2EPeerTenant(t *testing.T) {
	md := grpcmetadata.Pairs(auth.HeaderTenant, "acme")
	if got := e2ePeerTenant(e2eRunnerSVID(testTD), md, testTD); got.String() != "acme" {
		t.Fatalf("runner with header: %v", got)
	}
	if got := e2ePeerTenant("spiffe://zeroroot.ai/platform/tenant-operator", md, testTD); got != (auth.TenantID{}) {
		t.Fatalf("another peer must not assert a tenant: %v", got)
	}
	if got := e2ePeerTenant(e2eRunnerSVID(testTD), grpcmetadata.MD{}, testTD); got != (auth.TenantID{}) {
		t.Fatalf("no header: %v", got)
	}
	if got := e2ePeerTenant(e2eRunnerSVID(testTD), grpcmetadata.Pairs(auth.HeaderTenant, "not a tenant!"), testTD); got != (auth.TenantID{}) {
		t.Fatalf("malformed header: %v", got)
	}
}
