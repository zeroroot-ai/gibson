// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// TenantFromContextAnalyzer flags request-body tenant reads.
//
// ext-authz authorizes every RPC against an object derived from the CALLER's
// own identity (`object_deriver: tenant_from_identity` in the authz registry).
// No deriver reads a request-body field, so a tenant id arriving on the wire is
// authorized by nothing. A handler that lets such a field select the tenant it
// operates on is a cross-tenant defect, reachable by any authenticated caller.
//
// The analyzer therefore flags every read of a tenant identifier off a request
// value inside handler-bearing packages — both the struct field
// (`req.TenantId`) and, since it is what generated protobuf code actually
// produces, the accessor call (`req.GetTenantId()`).
//
// Suppression: a function whose doc comment contains
// `gibsoncheck:allow tenant-from-request` is exempted. Use it ONLY where the
// handler re-authorizes the caller against the supplied tenant — a
// requireTenantAdmin / platform_operator check — and name that guard in the
// comment so a reviewer can confirm it without reading the whole body.
//
// Spec: Requirement 8.7.
var TenantFromContextAnalyzer = &analysis.Analyzer{
	Name: "tenantfromcontext",
	Doc:  "warn on suspicious request-body tenant reads in handlers",
	Run:  runTenantFromContext,
}

// requestTenantSelectors are the selector names that read a tenant identifier
// off a request value. Both the raw struct field (hand-written types, and the
// exported protobuf field) and the generated `Get*` accessor are covered — the
// accessor is what handler code overwhelmingly uses, and matching only the
// field left the whole class invisible to this check.
var requestTenantSelectors = map[string]struct{}{
	"Tenant":      {},
	"TenantId":    {},
	"TenantID":    {},
	"GetTenant":   {},
	"GetTenantId": {},
	"GetTenantID": {},
}

// tenantHandlerPackages are the package-path fragments the analyzer inspects.
// Every gRPC handler that can be reached by an authenticated caller must be
// covered; internal/server/admin (the MembershipService / TenantAdminService
// surface) and the whole of internal/server/daemon are in scope, not just
// internal/server/daemon/api.
var tenantHandlerPackages = []string{
	"/internal/server/admin",
	"/internal/server/daemon",
	"/internal/engine/harness",
	"/internal/platform/component",
}

// allowTenantFromRequestDirective is the magic substring that must
// appear in a function's doc comment to opt out of the check.
const allowTenantFromRequestDirective = "gibsoncheck:allow tenant-from-request"

func runTenantFromContext(pass *analysis.Pass) (any, error) {
	if !inTenantHandlerPackage(pass.Pkg.Path()) {
		return nil, nil
	}
	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		// Iterate per top-level decl so each function body is scanned
		// in isolation. A function whose doc comment carries the
		// allow directive is skipped entirely; everything else is
		// inspected the same way as before.
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if funcHasAllowDirective(fn) {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if _, ok := requestTenantSelectors[sel.Sel.Name]; !ok {
					return true
				}
				// The receiver must be an identifier shaped like a request
				// value, so `s.GetTenantQuota` on a server receiver and
				// `tenant.String()` on a resolved tenant stay quiet.
				x, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if !looksLikeRequestIdent(x.Name) {
					return true
				}
				pass.Reportf(sel.Pos(),
					"%s.%s is a request-body tenant read in handler code; tenant MUST come from auth.TenantFromContext(ctx) per Requirement 8.7. If this access is legitimate (admin RPC re-checking caller-provided tenant against FGA), add an explicit `// gibsoncheck:allow tenant-from-request` comment naming the guard.",
					x.Name, sel.Sel.Name)
				return true
			})
		}
	}
	return nil, nil
}

// inTenantHandlerPackage reports whether pkgPath is one of the handler-bearing
// trees this analyzer inspects.
func inTenantHandlerPackage(pkgPath string) bool {
	for _, frag := range tenantHandlerPackages {
		if strings.Contains(pkgPath, frag) {
			return true
		}
	}
	return false
}

// looksLikeRequestIdent reports whether an identifier names an inbound request
// value. Matching is deliberately broad — "req", "request", and any name
// carrying either as a prefix or suffix (reqIn, createReq, listRequest) — so a
// handler cannot dodge the check by renaming its parameter.
func looksLikeRequestIdent(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "req", "request", "in", "msg":
		return true
	}
	return strings.HasPrefix(lower, "req") ||
		strings.HasSuffix(lower, "req") ||
		strings.HasPrefix(lower, "request") ||
		strings.HasSuffix(lower, "request")
}

// funcHasAllowDirective reports whether fn's doc comment carries
// the gibsoncheck:allow tenant-from-request opt-out.
func funcHasAllowDirective(fn *ast.FuncDecl) bool {
	if fn.Doc == nil {
		return false
	}
	for _, c := range fn.Doc.List {
		if strings.Contains(c.Text, allowTenantFromRequestDirective) {
			return true
		}
	}
	return false
}
