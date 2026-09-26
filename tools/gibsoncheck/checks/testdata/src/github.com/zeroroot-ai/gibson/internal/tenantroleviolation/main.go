// Package tenantroleviolation exercises the tenantrolewrite guard: every
// R-numbered case constructs a tenant-role tuple outside
// internal/platform/tenantrole and must be flagged; every N-numbered case
// must stay silent.
package tenantroleviolation

import (
	"fmt"

	fgaclient "github.com/openfga/go-sdk/client"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/pkg/platform/tenant"
)

// R1 — the shape SetTenantRole used before ADR-0093: a direct authz.Tuple
// write of a role relation on a tenant object, built by string
// concatenation.
func writeOwnerTupleDirectly(id, t string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: "tenant:" + t} // want `tenant-role tuple written outside tenantrole\.Syncer`
}

// R2 — the OpenFGA SDK's own tuple-key type, used directly against the
// client instead of through tenantrole.Syncer.
func writeViaRawSDKType(id, t string) fgaclient.ClientTupleKey {
	return fgaclient.ClientTupleKey{User: "user:" + id, Relation: "admin", Object: "tenant:" + t} // want `tenant-role tuple written outside tenantrole\.Syncer`
}

// R3 — the tenant object is produced by a call to a recognized
// tenant-object function (Names.FGAObject) rather than string
// concatenation. Still a role relation, still flagged.
func writeUsingNamesHelper(id string, names tenant.Names) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "member", Object: names.FGAObject()} // want `tenant-role tuple written outside tenantrole\.Syncer`
}

// R4 — the object is produced by authz.ActiveSessionObject, the other
// recognized tenant-object constructor, and the relation is a
// request-derived variable rather than a literal. The analyzer cannot
// prove a non-constant relation is not a role, so this is flagged even
// though "role" here happens to be "writer".
func writeUsingActiveSessionObjectHelper(id, t, role string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: role, Object: authz.ActiveSessionObject(t)} // want `tenant-role tuple written outside tenantrole\.Syncer`
}

// R5 — the plan's original fmt.Sprintf case, and a pointer type
// (*authz.ConditionalTuple): typeFullName must see through the pointer to
// match by the same underlying name as the value type.
func writeViaSprintfOnAConditionalTuplePointer(id, t string) *authz.ConditionalTuple {
	return &authz.ConditionalTuple{User: "user:" + id, Relation: "admin", Object: fmt.Sprintf("tenant:%s", t)} // want `tenant-role tuple written outside tenantrole\.Syncer`
}

// --- must NOT be flagged ---------------------------------------------------

// N4 — a fmt.Sprintf call whose format string does not start with
// "tenant:": the Sprintf-detection path fires, but the prefix check fails,
// so this is a component object, not a tenant object.
func writeUsingSprintfOnANonTenantObject(id, componentRef string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: fmt.Sprintf("component:%s", componentRef)}
}

// N5 — an unkeyed tuple literal. This codebase writes every tuple literal
// keyed; the analyzer explicitly does not analyze the unkeyed form.
func writeUnkeyedTuple(id, t string) authz.Tuple {
	return authz.Tuple{"user:" + id, "owner", "tenant:" + t}
}

// N1 — a non-role relation on a tenant object. Real, legitimate direct
// writes like this (tenant_enabled, parent, active_session) must never be
// blocked by this guard.
func writeNonRoleRelation(id, t string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "tenant_enabled", Object: "tenant:" + t}
}

// N2 — a role-shaped relation, but the object is NOT a tenant object (it is
// a component). The guard is specifically about tenant-role tuples.
func writeRoleOnNonTenantObject(id, componentRef string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: "component:" + componentRef}
}

// N3 — a CheckRequest, a read shape, never a write. Sharing the field names
// User/Relation/Object with the tuple types must not make this look like a
// tuple write; it is a different, unmatched type.
func buildCheckRequest(id, t string) authz.CheckRequest {
	return authz.CheckRequest{User: "user:" + id, Relation: "owner", Object: "tenant:" + t}
}
