package checks

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// TenantFromContextAnalyzer flags request-body tenant reads.
// Specifically: any handler function whose body reads `req.Tenant`,
// `req.TenantId`, `req.TenantID`, or `request.Tenant*` is suspect —
// tenant must come from the Identity established by the auth
// interceptor (auth.TenantFromContext), never from caller-supplied
// fields. The analyzer is conservative: it flags the access but not
// every assignment, leaving operator confirmation in CI.
//
// Suppression: a handler whose doc comment contains
// `gibsoncheck:allow tenant-from-request` is exempted from the check.
// Use this for legitimate admin RPCs that take a target tenant in the
// request body (PlatformOperatorService impersonation, TenantAdminService
// cross-tenant guards) — Envoy + ext-authz enforces authorization at
// the FGA layer before the handler runs.
//
// Spec: Requirement 8.7.
var TenantFromContextAnalyzer = &analysis.Analyzer{
	Name: "tenantfromcontext",
	Doc:  "warn on suspicious request-body tenant reads in handlers",
	Run:  runTenantFromContext,
}

var requestTenantSelectors = map[string]struct{}{
	"Tenant":   {},
	"TenantId": {},
	"TenantID": {},
}

// allowTenantFromRequestDirective is the magic substring that must
// appear in a function's doc comment to opt out of the check.
const allowTenantFromRequestDirective = "gibsoncheck:allow tenant-from-request"

func runTenantFromContext(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()
	// Limit to handler-bearing packages.
	if !strings.Contains(pkgPath, "/internal/daemon/api") &&
		!strings.Contains(pkgPath, "/internal/harness") &&
		!strings.Contains(pkgPath, "/internal/component") {
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
				// X must be an identifier shaped like a request — match
				// "req", "request", "r" with cap-letter type, or anything
				// with "Request" in the name. To keep noise down we match
				// on `req.Tenant*` and `request.Tenant*` only.
				x, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if x.Name != "req" && x.Name != "request" {
					return true
				}
				pass.Reportf(sel.Pos(),
					"%s.%s is a request-body tenant read in handler code; tenant MUST come from auth.TenantFromContext(ctx) per Requirement 8.7. If this access is legitimate (admin RPC re-checking caller-provided tenant against FGA), add an explicit `// gibsoncheck:allow tenant-from-request` comment.",
					x.Name, sel.Sel.Name)
				return true
			})
		}
	}
	return nil, nil
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
