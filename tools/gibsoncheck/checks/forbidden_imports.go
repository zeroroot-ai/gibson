package checks

import (
	"go/ast"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// ForbiddenImportsAnalyzer flags imports of packages that the daemon
// must not depend on per the unified-identity-and-authorization spec
// (Requirement 8.1):
//
//   - github.com/zitadel/* (any subpackage): JWT validation belongs
//     to Envoy; the daemon does not validate Zitadel tokens.
//   - github.com/openfga/* (any subpackage): FGA decisions belong to
//     ext-authz; the daemon does not call OpenFGA directly.
//
// A small allowlist exists for paths where the import is legitimate
// despite the package boundary (e.g. internal/authz still wraps the
// FGA SDK for the very narrow CanInvokeTool path that capability-
// grant uses). The allowlist is a slice of substrings checked
// against the package import path of the file being analyzed.
//
// The analyzer ignores test files and the tools/ directory.
var ForbiddenImportsAnalyzer = &analysis.Analyzer{
	Name: "forbiddenimports",
	Doc:  "fail on disallowed third-party imports per unified-identity-and-authorization spec",
	Run:  runForbiddenImports,
}

// forbidden lists import path prefixes that are disallowed.
var forbidden = []string{
	"github.com/zitadel/",
	"github.com/openfga/",
}

// allowlistPaths lists analyzed-package path substrings that are
// permitted to import forbidden packages (CG-JWT minting needs jwt
// libs; the existing authz package wraps the FGA SDK during the
// migration).
var allowlistPaths = []string{
	"/internal/authz",
	"/internal/capabilitygrant",
	"/cmd/", // standalone binaries may need OIDC/FGA for diagnostic tooling
}

func runForbiddenImports(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()
	for _, allow := range allowlistPaths {
		if strings.Contains(pkgPath, allow) {
			return nil, nil
		}
	}
	for _, file := range pass.Files {
		// Skip test files.
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}
			for _, prefix := range forbidden {
				if strings.HasPrefix(path, prefix) {
					pass.Reportf(imp.Pos(),
						"forbidden import %q in %q: package belongs to ext-authz/Envoy upstream chain (see unified-identity-and-authorization Requirement 8.1)",
						path, pkgPath)
				}
			}
		}
	}
	return nil, nil
}

// astWalkPlaceholder is here to satisfy go vet's unused-import warnings
// while keeping the file ready for future ast-based checks.
var _ = ast.Walk
