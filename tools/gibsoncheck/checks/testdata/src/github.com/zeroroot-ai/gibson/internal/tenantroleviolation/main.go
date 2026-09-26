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

// N6 — an anonymous struct that happens to share field names with a tuple
// type. It has no name at all, so typeFullName's named-type assertion must
// fail closed to "" (no match) rather than panic or misidentify it.
func buildAnonymousStructWithTupleShapedFields(id, t string) any {
	return struct{ User, Relation, Object string }{User: "user:" + id, Relation: "owner", Object: "tenant:" + t}
}

// localFormatter has its own Sprintf method, unrelated to fmt.Sprintf. A
// selector call named "Sprintf" is not enough to be treated as the
// tenant-prefix-detecting fmt.Sprintf: the analyzer must also confirm the
// resolved function belongs to package "fmt".
type localFormatter struct{}

func (localFormatter) Sprintf(format string, a ...any) string { return format }

// N7 — a Sprintf call, but not fmt's. Must not be mistaken for the
// tenant-prefix-detecting fmt.Sprintf case.
func writeUsingALocalSprintfMethod(id, t string) authz.Tuple {
	var lf localFormatter
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: lf.Sprintf("tenant:%s", t)}
}

// box has a pointer-receiver method. It is not in tenantObjectFuncs, but
// calling it as an Object source exercises qualifiedFuncName's
// pointer-receiver branch (the analyzer still has to compute the qualified
// name correctly to decide it does NOT match).
type box struct{ label string }

func (b *box) Label() string { return b.label }

// N8 — a pointer-receiver method call as the Object source. Not a
// recognized tenant-object function, so this is not flagged even though
// the relation is a role name.
func writeUsingAPointerReceiverMethod(id string, b *box) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: b.Label()}
}

// N9 — the Object is a bare identifier: neither a string concatenation nor
// a call. isTenantObjectExpr's default case (neither BinaryExpr nor
// CallExpr) must return false.
func writeUsingABareIdentifierAsObject(id, precomputedObject string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: precomputedObject}
}

// R6 — a slice of *authz.Tuple built with Go's elided "&" form: the inner
// literal's own recorded type is *authz.Tuple, not authz.Tuple, so
// typeFullName must see through the pointer here too, not just for an
// explicit &authz.Tuple{} (R5 already covers that; this is the other way a
// composite literal ends up pointer-typed).
func writeSliceOfTuplePointers(id, t string) []*authz.Tuple {
	return []*authz.Tuple{
		{User: "user:" + id, Relation: "owner", Object: "tenant:" + t}, // want `tenant-role tuple written outside tenantrole\.Syncer`
	}
}

// tenantPrefixConst is a known limitation: the analyzer recognizes the
// tenant prefix only as a literal ("tenant:" + x), not through a named
// constant. writeUsingANamedConstantPrefix below is a false negative this
// analyzer accepts (documented, not silently missed).
const tenantPrefixConst = "tenant:"

// N10 — the tenant prefix comes from a named constant, not a literal.
// startsWithTenantPrefix only recognizes a literal operand, so this is not
// flagged — a known, accepted limitation, not a bug: every actual
// conversion in this codebase writes the literal form.
func writeUsingANamedConstantPrefix(id, t string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: tenantPrefixConst + t}
}

// N11 — the Object comes from calling a local func-typed variable, not a
// package-level function. The identifier resolves to a *types.Var holding a
// func value, not a *types.Func, so isTenantObjectFuncCall must not treat
// it as a recognized tenant-object constructor.
func writeUsingALocalFuncVariable(id, t string) authz.Tuple {
	buildObject := func() string { return "tenant:" + t }
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: buildObject()}
}

// N12 — the Object comes from an immediately-invoked function literal.
// call.Fun here is neither a *ast.SelectorExpr nor a *ast.Ident, so
// isTenantObjectFuncCall's switch must fail closed through its default
// case.
func writeUsingAnImmediatelyInvokedFunctionLiteral(id, t string) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: func() string { return "tenant:" + t }()}
}

// sprintfField is a struct with a func-typed field literally named
// "Sprintf" — a selector access to it is not a use of a package-level
// function at all (it resolves through Selections, not Uses), so
// isFmtSprintfCall must not mistake it for fmt.Sprintf just because the
// selector name matches.
type sprintfField struct {
	Sprintf func(format string, a ...any) string
}

// N13 — Sprintf named field, not fmt.Sprintf.
func writeUsingASprintfNamedField(id, t string, sf sprintfField) authz.Tuple {
	return authz.Tuple{User: "user:" + id, Relation: "owner", Object: sf.Sprintf("tenant:%s", t)}
}
