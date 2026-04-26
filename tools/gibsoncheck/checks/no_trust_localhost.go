package checks

import (
	"go/ast"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// NoTrustLocalhostAnalyzer flags any reference to "TrustLocalhost"
// in source. The legacy interceptor option that allowed unauthenticated
// loopback connections is removed (Requirement 8.6); reintroduction
// is a regression of audit C17.
var NoTrustLocalhostAnalyzer = &analysis.Analyzer{
	Name: "notrustlocalhost",
	Doc:  "fail on any reintroduction of the deleted TrustLocalhost option",
	Run:  runNoTrustLocalhost,
}

func runNoTrustLocalhost(pass *analysis.Pass) (any, error) {
	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			if id.Name == "TrustLocalhost" {
				pass.Reportf(id.Pos(),
					"TrustLocalhost was removed by unified-identity-and-authorization Requirement 8.6 — do not reintroduce")
			}
			return true
		})
	}
	return nil, nil
}
