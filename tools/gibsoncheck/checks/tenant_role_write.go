// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// TenantRoleWriteAnalyzer enforces ADR-0093 decision 3: tenantrole.Syncer is
// the ONLY writer of tenant-role tuples — the direct role relations (owner,
// admin, writer, member) on a tenant object. Every writer that used to poke
// FGA (or the tenant-operator's own FGA client) directly for a role tuple —
// SetTenantRole, TransferOwnership, AcceptInvitation, the TenantMember
// reconciler, bootstrap-tenant-owner — now goes through Syncer.Assign /
// Revoke / Transfer, which also writes the backing Zitadel grant. A write
// that bypasses it puts FGA and Zitadel out of sync silently.
//
// # What is flagged
//
// A composite literal of a tuple type (matched by type identity — see
// tenantRoleTupleTypes) whose Object field is a tenant object (see
// isTenantObjectExpr) and whose Relation field is either a role relation
// constant (tenantrole.Relations) or not a compile-time constant at all —
// the analyzer cannot prove a non-constant relation is not a role, so it
// fails closed rather than silently waving it through.
//
// # What is NOT flagged
//
//   - A relation that IS a constant and is NOT a role relation (e.g.
//     "tenant_enabled", "active_session", "parent") — these are real,
//     legitimately-direct tenant-object tuple writes this analyzer must
//     never block.
//   - CheckRequest literals and Check/BatchCheck calls: reads, not writes.
//   - Test files, and the analyzer's own testdata fixtures.
//   - internal/platform/tenantrole itself (it IS the writer) and the
//     tenant-operator's FGA adapter file, which translates a
//     tenantrole.Tuple into its own client's wire shape.
//   - The three files in tenantRoleAllowedFiles below that write "member"
//     (Viewer's relation string) on a tenant object for a subject ADR-0093
//     never governs: a non-human "<kind>_principal:<id>" component identity
//     (ADR-0045/0046 tenant membership, unrelated to any Zitadel project
//     grant), or the exit-test runner's SPIFFE-derived pseudo-user
//     (gibson#14 fixture seed, excluded from Sync by the same "/" rule as
//     tenantrole.IsZitadelUserSubject). The relation string is shared with
//     the human Viewer role by coincidence of the FGA model, not because
//     these writes are tenant roles.
//
// Spec: ADR-0093 (tenant roles live in Zitadel), hosted#194.
var TenantRoleWriteAnalyzer = &analysis.Analyzer{
	Name: "tenantrolewrite",
	Doc:  "fail on any tenant-role tuple written outside tenantrole.Syncer (ADR-0093)",
	Run:  runTenantRoleWrite,
}

// tenantRoleTupleTypes are the fully-qualified type names ("pkgpath.Name")
// this analyzer treats as FGA tuple literals. Matched by type identity via
// the type checker — never by the literal's source-level type expression —
// so an alias or a renamed import cannot evade it. client.ClientTupleKey
// and client.ClientTupleKeyWithoutCondition are themselves Go type aliases
// for the two entries under github.com/openfga/go-sdk, so matching those
// underlying names catches both spellings.
var tenantRoleTupleTypes = map[string]bool{
	"github.com/zeroroot-ai/gibson/internal/platform/authz.Tuple":                          true,
	"github.com/zeroroot-ai/gibson/internal/platform/authz.ConditionalTuple":               true,
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga.Tuple":            true,
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga.ConditionalTuple": true,
	"github.com/openfga/go-sdk.TupleKey":                                                   true,
	"github.com/openfga/go-sdk.TupleKeyWithoutCondition":                                   true,
}

// tenantRoleAllowedPackages are package paths allowed to construct a
// tenant-role tuple literal directly: the one Syncer.
var tenantRoleAllowedPackages = []string{
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole",
}

// tenantRoleAllowedFiles are file paths (matched by suffix) allowed outside
// the packages above. Do not add an entry to silence a finding without the
// same review this list already got: each one here writes a "member" /
// "writer" / "admin" / "owner" relation on a tenant object for a subject
// that is provably not, and can never become, a Zitadel-backed human user —
// so ADR-0093 (which governs the sync of a HUMAN's Zitadel project role)
// does not reach it. The analyzer cannot see that itself (the User field is
// a runtime value, not a literal it can trace), so the exemption is by
// file, matching this package's existing convention for adjacent guards.
var tenantRoleAllowedFiles = []string{
	// The tenant-operator's own FGA client adapter: translates a
	// tenantrole.Tuple into that client's wire shape, never originates one.
	"operators/tenant/internal/clients/fga/tenantrole.go",

	// ProvisionPluginPrincipal grants a first-party plugin's technical
	// principal ("plugin_principal:<vendor>") membership on its install
	// tenant (ADR-0045: a plugin has no Zitadel machine user, so FGA alone
	// is its tenancy authority). The User is the plugin principal, not a
	// Zitadel user.
	"internal/platform/capabilitygrant/plugin_svid.go",

	// CreateAgentIdentity grants a non-human component identity
	// ("<kind>_principal:<sub>") membership on its tenant so its
	// capability-grant JWT authorizes client RPCs (ADR-0045/0046). The
	// User is the component principal, not a Zitadel user; the IdP here
	// only authenticates the machine user and is deliberately not a
	// tenancy authority.
	"internal/server/daemon/api/tenant_admin_create.go",

	// seedE2ERunnerTenancy seeds the exit-test runner's SPIFFE-derived
	// pseudo-user as a tenant member at boot, fixture builds only
	// (gibson#14). That subject is excluded from tenantrole.Syncer by
	// design (owner decision D2, option b: tenantrole.IsZitadelUserSubject
	// rejects any "user:" id containing "/", which every SPIFFE id does) —
	// it is not, and can never become, a Zitadel grant.
	"internal/server/daemon/e2e_runner_tenancy.go",
}

// tenantRoleRelations mirrors tenantrole.Relations. Kept as a literal list,
// not an import, matching this analyzer package's existing convention of
// referencing analyzed-code identifiers by string (see e.g. graph_write.go,
// admin_pool_acquire.go) rather than importing the code under analysis.
var tenantRoleRelations = map[string]bool{
	"owner":  true,
	"admin":  true,
	"writer": true,
	"member": true,
}

// tenantObjectFuncs are fully-qualified function/method names ("pkgpath.Func"
// or "pkgpath.Type.Method") that return a tenant FGA object string
// ("tenant:<id>"). A call to one of these as (or as part of) a tuple's
// Object field marks it as a tenant object.
var tenantObjectFuncs = map[string]bool{
	"github.com/zeroroot-ai/gibson/pkg/platform/tenant.Names.FGAObject":         true,
	"github.com/zeroroot-ai/gibson/internal/platform/authz.ActiveSessionObject": true,
}

func runTenantRoleWrite(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()
	for _, allowed := range tenantRoleAllowedPackages {
		if pkgPath == allowed {
			return nil, nil
		}
	}

	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		// No "/testdata/" filename check here: the go tool (and
		// golang.org/x/tools/go/packages) never hands a real package's files
		// from a directory literally named testdata to this analyzer in the
		// first place, and analysistest's own fixture files live under a
		// testdata/src root but resolve to an import path that does not
		// contain "testdata" — a filename check would only ever hide this
		// analyzer's own violation fixtures from itself.
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		if isTenantRoleAllowedFile(fname) {
			continue
		}

		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if !isTenantTupleType(pass, lit) {
				return true
			}
			objExpr, relExpr := tenantTupleFields(lit)
			if objExpr == nil || relExpr == nil {
				return true
			}
			if !isTenantObjectExpr(pass, objExpr) {
				return true
			}
			if !isRoleRelation(pass, relExpr) {
				return true
			}
			pass.Reportf(lit.Pos(),
				"tenant-role tuple written outside tenantrole.Syncer: internal/platform/tenantrole "+
					"is the ONLY writer of tenant-role tuples (ADR-0093 decision 3). Call "+
					"Syncer.Assign, Syncer.Revoke or Syncer.Transfer instead of constructing this "+
					"tuple directly.")
			return true
		})
	}
	return nil, nil
}

func isTenantRoleAllowedFile(fname string) bool {
	fname = filepathToSlash(fname)
	for _, allowed := range tenantRoleAllowedFiles {
		if strings.HasSuffix(fname, allowed) {
			return true
		}
	}
	return false
}

func filepathToSlash(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// isTenantTupleType reports whether lit's static type is one of
// tenantRoleTupleTypes.
func isTenantTupleType(pass *analysis.Pass, lit *ast.CompositeLit) bool {
	tv, ok := pass.TypesInfo.Types[lit]
	if !ok || tv.Type == nil {
		return false
	}
	return tenantRoleTupleTypes[typeFullName(tv.Type)]
}

// typeFullName renders t (or what it points to) as "pkgpath.Name", or "" if
// t is not a named type from a real package. t is unaliased first: since Go
// 1.23, "type X = Y" materializes as its own *types.Alias node rather than
// resolving straight to Y's *types.Named, so a naive type switch sees the
// alias's own (package, name) pair — exactly backwards from the point of
// matching by underlying type identity, which is why
// client.ClientTupleKey (a type alias for openfga.TupleKey) must be
// unaliased before the switch below, not looked up by its own name.
func typeFullName(t types.Type) string {
	t = types.Unalias(t)
	if ptr, ok := t.(*types.Pointer); ok {
		t = types.Unalias(ptr.Elem())
	}
	named, ok := t.(*types.Named)
	if !ok {
		return ""
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return ""
	}
	return obj.Pkg().Path() + "." + obj.Name()
}

// tenantTupleFields returns the Object and Relation field value expressions
// from a keyed composite literal. Either return is nil if that field is
// absent or the literal is unkeyed (this codebase writes every tuple
// literal keyed; an unkeyed literal is not analyzed).
func tenantTupleFields(lit *ast.CompositeLit) (object, relation ast.Expr) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "Object":
			object = kv.Value
		case "Relation":
			relation = kv.Value
		}
	}
	return object, relation
}

// isTenantObjectExpr reports whether e names a tenant object: a string
// concatenation starting with the constant "tenant:", a fmt.Sprintf whose
// format string starts with "tenant:", or a call to a function in
// tenantObjectFuncs.
func isTenantObjectExpr(pass *analysis.Pass, e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return false
		}
		return startsWithTenantPrefix(leftmostAddOperand(v))
	case *ast.CallExpr:
		if isFmtSprintfCall(pass, v) {
			if len(v.Args) == 0 {
				return false
			}
			return startsWithTenantPrefix(v.Args[0])
		}
		return isTenantObjectFuncCall(pass, v)
	}
	return false
}

// leftmostAddOperand walks down the left side of a chain of "+" expressions
// to the first non-BinaryExpr operand — the constant prefix in
// `"tenant:" + a + b`.
func leftmostAddOperand(e ast.Expr) ast.Expr {
	for {
		bin, ok := e.(*ast.BinaryExpr)
		if !ok || bin.Op != token.ADD {
			return e
		}
		e = bin.X
	}
}

func startsWithTenantPrefix(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return false
	}
	return strings.HasPrefix(s, "tenant:")
}

func isFmtSprintfCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Sprintf" {
		return false
	}
	fn, ok := pass.TypesInfo.Uses[sel.Sel].(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	return fn.Pkg().Path() == "fmt" && fn.Name() == "Sprintf"
}

func isTenantObjectFuncCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	var selIdent *ast.Ident
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		selIdent = fn.Sel
	case *ast.Ident:
		selIdent = fn
	default:
		return false
	}
	fn, ok := pass.TypesInfo.Uses[selIdent].(*types.Func)
	if !ok {
		return false
	}
	return tenantObjectFuncs[qualifiedFuncName(fn)]
}

// qualifiedFuncName renders fn as "pkgpath.Func" for a plain function, or
// "pkgpath.RecvType.Method" for a method.
func qualifiedFuncName(fn *types.Func) string {
	if fn.Pkg() == nil {
		return fn.Name()
	}
	if sig, ok := fn.Type().(*types.Signature); ok {
		if recv := sig.Recv(); recv != nil {
			recvType := recv.Type()
			if ptr, ok := recvType.(*types.Pointer); ok {
				recvType = ptr.Elem()
			}
			if named, ok := recvType.(*types.Named); ok && named.Obj() != nil {
				return fn.Pkg().Path() + "." + named.Obj().Name() + "." + fn.Name()
			}
		}
	}
	return fn.Pkg().Path() + "." + fn.Name()
}

// isRoleRelation reports whether e is either a compile-time string constant
// naming a role relation (tenantRoleRelations), or not a compile-time
// constant at all — the analyzer cannot prove a non-constant relation is
// not a role, so it fails closed (owner decision, section 9): this is what
// catches `Relation: role`, `Relation: rec.Role` and
// `Relation: string(tm.Spec.Role)`.
func isRoleRelation(pass *analysis.Pass, e ast.Expr) bool {
	tv, ok := pass.TypesInfo.Types[e]
	if !ok || tv.Value == nil {
		return true
	}
	if tv.Value.Kind() != constant.String {
		return true
	}
	return tenantRoleRelations[constant.StringVal(tv.Value)]
}
