// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package registry_test

// ontology_extension_relations_test.go pins the tenant-owner approval gate
// for OntologyExtensionService (ADR-0133, gibson#392): the
// registry IS the deny contract ext-authz enforces (see
// ownership_relations_test.go's own doc), so this is the "not-authorized"
// test for a non-owner (e.g. a plain tenant Admin or a member/agent) caller
// — a live FGA Check is exercised by ext-authz in the deployed daemon, not
// by this handler in-process (mirrors TestTransferOwnershipRequiresOwnerRelation).

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
)

func TestApproveOntologyExtensionProposalRequiresOwnerRelation(t *testing.T) {
	const rpc = "/gibson.tenant.v1.OntologyExtensionService/ApproveOntologyExtensionProposal"

	entry, ok := registry.Registry[rpc]
	if !ok {
		t.Fatalf("%s: missing from the generated registry", rpc)
	}
	if entry.Relation != "owner" {
		t.Errorf("%s: relation = %q, want %q (ADR-0133: explicit TENANT-OWNER approval, not a plain admin/member/agent)",
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

func TestRejectOntologyExtensionProposalRequiresOwnerRelation(t *testing.T) {
	const rpc = "/gibson.tenant.v1.OntologyExtensionService/RejectOntologyExtensionProposal"

	entry, ok := registry.Registry[rpc]
	if !ok {
		t.Fatalf("%s: missing from the generated registry", rpc)
	}
	if entry.Relation != "owner" {
		t.Errorf("%s: relation = %q, want %q (ADR-0133: explicit TENANT-OWNER approval, not a plain admin/member/agent)",
			rpc, entry.Relation, "owner")
	}
}

// TestListOntologyExtensionProposalsStaysAdminGated pins that visibility into
// the proposal queue is available to any tenant Admin (a broader relation
// than the strict "owner" gate Approve/Reject require) — ADR-0133's "the
// tenant owner seeing every proposal" does not preclude an admin assisting
// them from also seeing the queue; only the DECISION is owner-exclusive.
func TestListOntologyExtensionProposalsStaysAdminGated(t *testing.T) {
	const rpc = "/gibson.tenant.v1.OntologyExtensionService/ListOntologyExtensionProposals"

	entry, ok := registry.Registry[rpc]
	if !ok {
		t.Fatalf("%s: missing from the generated registry", rpc)
	}
	if entry.Relation != "admin" {
		t.Errorf("%s: relation = %q, want %q", rpc, entry.Relation, "admin")
	}
}
