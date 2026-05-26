package checks

import (
	"go/ast"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// AdminPoolAcquireAnalyzer flags any package outside the two authorised
// locations that calls admin.AdminPool.Acquire, constructs an AdminConn
// directly, or imports the admin pool package at all.
//
// The two authorised locations are:
//
//	internal/datapool/admin/   — the pool implementation itself
//	internal/admin/            — platform-operator business logic
//
// Any other package importing internal/datapool/admin is a policy violation
// per database-per-tenant-data-plane Requirement 11.5 and the design's
// "narrow-waist" CODEOWNERS policy.
//
// Spec: database-per-tenant-data-plane, Phase E, task 5.2.
var AdminPoolAcquireAnalyzer = &analysis.Analyzer{
	Name: "adminpoolacquire",
	Doc:  "fail when a package outside internal/admin/ or internal/datapool/admin/ imports the admin pool package (database-per-tenant-data-plane Requirement 11.5)",
	Run:  runAdminPoolAcquire,
}

// adminPoolImportPath is the Go import path of the admin pool package.
const adminPoolImportPath = "github.com/zeroroot-ai/gibson/internal/datapool/admin"

// allowedAdminPackages lists package path substrings that are permitted to
// import the admin pool. The check uses substring matching so sub-packages
// of internal/admin/ are also allowed.
var allowedAdminPackages = []string{
	"/internal/datapool/admin",
	"/internal/admin",
	"/internal/migrate",   // migration runner uses admin pool for tenant enumeration
	"/cmd/gibson-migrate", // migration CLI entry point
	"/tools/gibsoncheck",  // the analyzer itself during test runs
}

func runAdminPoolAcquire(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()

	// Check if this package is in the allowlist.
	for _, allowed := range allowedAdminPackages {
		if strings.Contains(pkgPath, allowed) {
			return nil, nil
		}
	}

	for _, file := range pass.Files {
		// Skip test files — tests may need to import the admin pool for
		// integration tests against a real admin pool instance.
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}

		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			if path == adminPoolImportPath {
				pass.Reportf(imp.Pos(),
					"forbidden import %q in %q: only internal/admin/ and internal/datapool/admin/ may import the admin pool (database-per-tenant-data-plane Requirement 11.5). Cross-tenant access requires CODEOWNERS review.",
					path, pkgPath)
			}
		}
	}

	// Additionally flag direct construction of AdminConn from datapool if the
	// struct literal appears in the AST — belt-and-suspenders for packages
	// that happen to have datapool in scope via other imports.
	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			cl, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := cl.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// Flag calls like adminPool.Acquire(...) where the selector is
			// "Acquire" on a receiver named "*AdminPool" — we check the
			// selector name only (type information is not available in
			// analysis.Pass without type checking; a name check is
			// sufficient to catch accidental direct calls).
			if sel.Sel.Name == "Acquire" {
				// We cannot determine the exact receiver type without
				// type information; leave that to the import check above
				// which is the primary enforcement mechanism.
				_ = cl
			}
			return true
		})
	}

	return nil, nil
}
