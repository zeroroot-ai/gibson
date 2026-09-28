// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package registry_test

// ownership_relations_test.go pins the Owner-rules deny contract (hosted#190,
// ADR-0093 §5).
//
// The registry IS the deny contract: ext-authz runs the FGA Check each entry
// names (see rpc_authz_deny_test.go). model.fga defines
// owner ⊆ admin ⊆ writer ⊆ member (each higher relation implies the ones
// below it via a computed union), so a "relation: owner" entry denies an
// Admin — an Admin holds admin (and everything admin implies) but never
// holds owner unless they ARE the Owner. Before this fix TransferOwnership
// was gated on "admin", so any Admin could transfer ownership to themselves.

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
)

func TestTransferOwnershipRequiresOwnerRelation(t *testing.T) {
	const rpc = "/gibson.tenant.v1.MembershipService/TransferOwnership"

	entry, ok := registry.Registry[rpc]
	if !ok {
		t.Fatalf("%s: missing from the generated registry", rpc)
	}
	if entry.Relation != "owner" {
		t.Errorf("%s: relation = %q, want %q (hosted#190: an Admin must never pass this gate)",
			rpc, entry.Relation, "owner")
	}
	if entry.ObjectType != "tenant" {
		t.Errorf("%s: object_type = %q, want %q", rpc, entry.ObjectType, "tenant")
	}
	if entry.ObjectDeriver != "tenant_from_identity" {
		t.Errorf("%s: object_deriver = %q, want %q (the object must be the CALLER's own tenant)",
			rpc, entry.ObjectDeriver, "tenant_from_identity")
	}
}

// TestSetTenantRoleStaysAdminGated pins that SetTenantRole itself is still
// reachable by any tenant Admin (the RPC-level gate is unchanged); the Owner
// rules for SetTenantRole (refusing role "owner" and refusing to touch the
// current Owner) are enforced inside the handler, not by the registry, and
// are covered by the admin-package unit tests
// (TestSetTenantRole_RefusesOwnerRole and
// TestSetTenantRole_RefusesTouchingCurrentOwner).
func TestSetTenantRoleStaysAdminGated(t *testing.T) {
	const rpc = "/gibson.tenant.v1.MembershipService/SetTenantRole"

	entry, ok := registry.Registry[rpc]
	if !ok {
		t.Fatalf("%s: missing from the generated registry", rpc)
	}
	if entry.Relation != "admin" {
		t.Errorf("%s: relation = %q, want %q", rpc, entry.Relation, "admin")
	}
}
