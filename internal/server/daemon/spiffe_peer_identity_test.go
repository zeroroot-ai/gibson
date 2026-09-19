// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/sdk/auth"
	grpcmetadata "google.golang.org/grpc/metadata"
)

// TestSpiffePeerIdentity: a direct-dial peer acts as its SVID with the
// spiffe issuer and credential type. Whether the tenant header is honoured
// is e2ePeerTenant's decision, tested per build; here a peer that is not the
// runner keeps the zero tenant with and without incoming metadata.
func TestSpiffePeerIdentity(t *testing.T) {
	const svid = "spiffe://zeroroot.ai/platform/tenant-operator"
	ctx := grpcmetadata.NewIncomingContext(context.Background(), grpcmetadata.Pairs(auth.HeaderTenant, "acme"))
	id := spiffePeerIdentity(ctx, svid)
	if id.Subject != svid || id.Issuer != auth.Issuer("spiffe") || id.CredentialType != auth.CredentialType("spiffe") {
		t.Fatalf("identity = %+v", id)
	}
	if id.Tenant != (auth.TenantID{}) {
		t.Fatalf("a platform peer must not take a tenant from a header: %v", id.Tenant)
	}
	if id := spiffePeerIdentity(context.Background(), svid); id.Tenant != (auth.TenantID{}) || id.Subject != svid {
		t.Fatalf("no metadata: %+v", id)
	}
}
