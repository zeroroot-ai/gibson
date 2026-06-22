package identityresolver_test

// resolver_no_auth_callers_test.go asserts that no non-test, non-identityresolver
// Go source file in the gibson repo imports or directly calls the exported
// Resolve* symbols from this package.
//
// Rationale: identityresolver is for log enrichment only. Any call from an
// auth-decision code path (check, verify, authz, etc.) would violate the
// canonical-service-identity invariant: "auth decisions compare on numeric
// sub; readable names are for humans, not gates."
//
// Spec: zero-trust-hardening Requirement 3.4 (regression guard)
// Spec: canonical-service-identity Req 8.

import (
	"fmt"
	"go/token"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// resolveSymbols is the set of exported symbols from the identityresolver
// package that must not appear outside the package itself (or _test.go files).
var resolveSymbols = []string{"Resolve", "New", "Resolver", "DefaultPath"}

// TestIdentityResolverHasNoAuthCallers loads all internal packages of the
// gibson module, walks their ASTs, and asserts that no non-test file outside
// the identityresolver package imports or references identityresolver.Resolve*.
//
// Uses golang.org/x/tools/go/packages so that the check is rooted at the
// actual module rather than the working directory of the test binary.
func TestIdentityResolverHasNoAuthCallers(t *testing.T) {
	const modulePath = "github.com/zeroroot-ai/gibson"
	const resolverPkg = modulePath + "/internal/platform/auth/identityresolver"

	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedSyntax |
			packages.NeedImports |
			packages.NeedDeps,
		Tests: false, // exclude _test.go files from packages loaded
	}

	// Load all internal packages.
	pattern := modulePath + "/internal/..."
	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		t.Fatalf("packages.Load(%q): %v", pattern, err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		t.Fatal("packages.Load returned errors (see above)")
	}

	var violations []string

	for _, pkg := range pkgs {
		// Skip the identityresolver package itself.
		if pkg.PkgPath == resolverPkg {
			continue
		}

		// Only flag packages that actually import identityresolver.
		if _, imports := pkg.Imports[resolverPkg]; !imports {
			continue
		}

		// Walk AST of each non-test file in the package.
		for i, f := range pkg.Syntax {
			// Determine the source file name (position info).
			fileName := ""
			if i < len(pkg.GoFiles) {
				fileName = pkg.GoFiles[i]
			}
			// Skip test files as a belt-and-suspenders check (Tests:false
			// should already exclude them, but file names may still appear).
			if strings.HasSuffix(fileName, "_test.go") {
				continue
			}

			// Walk top-level declarations looking for identityresolver selector
			// expressions: identityresolver.<Symbol>.
			for _, decl := range f.Decls {
				fset := token.NewFileSet()
				_ = fset // used for position reporting if needed
				_ = decl
			}

			// Simpler approach: check the import list of this file for the
			// resolver package import path. If the file imports it, that is
			// already a violation regardless of whether it calls Resolve.
			for _, imp := range f.Imports {
				if imp.Path != nil {
					// imp.Path.Value is a quoted string, e.g. `"github.com/..."`
					importPath := strings.Trim(imp.Path.Value, `"`)
					if importPath == resolverPkg {
						violations = append(violations,
							fmt.Sprintf("%s imports identityresolver (pkg: %s)",
								fileName, pkg.PkgPath))
					}
				}
			}
		}
	}

	if len(violations) > 0 {
		t.Errorf("REGRESSION (zero-trust-hardening Req 3.4 / canonical-service-identity Req 8):\n"+
			"identityresolver is for log enrichment ONLY — it must not be imported from\n"+
			"non-test code outside the package itself. Found %d violation(s):\n  - %s\n\n"+
			"Fix: remove the import and use the numeric sub directly for auth decisions.",
			len(violations), strings.Join(violations, "\n  - "))
	}
}
