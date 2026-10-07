// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package headers

import (
	"testing"
	"time"
)

// The identity of a fork claim carries no tenant, and Emit still sends the
// tenant header with an empty value, so a tenant header from the client never
// reaches the daemon (D80).
func TestSandboxClaimIdentity_HasNoTenantAndEmitsAnEmptyHeader(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	id := SandboxClaimIdentity(now)
	if id.Tenant != "" {
		t.Fatalf("tenant = %q, want none", id.Tenant)
	}
	if id.Subject != SandboxClaimSubject || id.Issuer != IssuerCapabilityGrant ||
		id.CredentialType != CredentialSandboxIdentity || !id.IssuedAt.Equal(now) {
		t.Fatalf("identity = %+v", id)
	}
	h := Emit(id)
	if v := h.Values(HeaderTenant); len(v) != 1 || v[0] != "" {
		t.Fatalf("tenant header values = %q, want one empty value", v)
	}
	if h.Get(HeaderCredentialType) != CredentialSandboxIdentity {
		t.Fatalf("credential type header = %q", h.Get(HeaderCredentialType))
	}
}
