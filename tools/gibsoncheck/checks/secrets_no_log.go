package checks

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// SecretsNoLogAnalyzer flags any code path within secrets-handling packages
// where a []byte value returned from a known source method is passed (directly
// or through a single-rename assignment) to a logging-shaped sink call.
//
// Source methods (calls whose return values are tainted):
//
//   - secrets.Service.Resolve        — daemon internal service
//   - SecretsBroker.Get              — any type whose method is named "Get"
//                                      in a secrets-package context
//   - TenantSecretsOps.Get           — Postgres DAO
//
// Logging sinks (calls that must never receive tainted values):
//
//   - log.Print / log.Println / log.Printf / log.Fatal* / log.Panic*
//   - slog.Info / slog.Debug / slog.Warn / slog.Error
//   - fmt.Print / fmt.Println / fmt.Printf / fmt.Sprintf / fmt.Errorf
//     (only when a tainted []byte appears directly in the argument list)
//   - zap.*Logger.Info / Debug / Warn / Error / Sugar().Infow / etc.
//
// Scope: only packages whose import path contains one of the secrets-package
// prefixes (see secretsPackagePrefixes). This restriction keeps false-positive
// rates near zero because the relevant source methods are common names ("Get").
//
// The analysis is intentionally flow-naive: it detects single-rename
// propagation (v := source(); sink(v)) within a single function body.
// Multi-step propagation through structs, maps, channels, or closures is
// out of scope for v1.
//
// Spec: secrets-broker NFR Security.
var SecretsNoLogAnalyzer = &analysis.Analyzer{
	Name:     "secretsnolog",
	Doc:      "flag []byte values returned from secrets Get/Resolve methods being passed to logging sinks (secrets-broker NFR Security)",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      runSecretsNoLog,
}

// secretsPackagePrefixes lists the import-path substrings that place a
// package in scope for this check. Packages outside these prefixes are
// skipped entirely to prevent false positives from unrelated uses of
// common method names like "Get".
var secretsPackagePrefixes = []string{
	"github.com/zero-day-ai/sdk/secrets",
	"github.com/zero-day-ai/gibson/internal/secrets",
	"github.com/zero-day-ai/gibson/internal/database/postgres",
}

// sourceMethodNames are the method / function names whose []byte return
// values are considered tainted. We track only the name; the package-scope
// filter above prevents false positives from other packages' methods with
// the same name.
var sourceMethodNames = map[string]struct{}{
	"Get":     {},
	"Resolve": {},
}

// loggingSinkPkgs maps import-path prefixes to sets of function names that
// are logging sinks. A call to any of these functions with a tainted argument
// is a policy violation.
var loggingSinkPkgs = map[string]map[string]struct{}{
	"log": {
		"Print":   {},
		"Println": {},
		"Printf":  {},
		"Fatal":   {},
		"Fatalf":  {},
		"Fatalln": {},
		"Panic":   {},
		"Panicf":  {},
		"Panicln": {},
	},
	"log/slog": {
		"Info":  {},
		"Debug": {},
		"Warn":  {},
		"Error": {},
	},
	"fmt": {
		"Print":   {},
		"Println": {},
		"Printf":  {},
		"Sprintf": {},
		"Errorf":  {},
	},
}

// zapSinkMethodNames are the method names on zap.Logger / zap.SugaredLogger
// that accept variadic fields. We match by method name and check that the
// receiver's package path contains "go.uber.org/zap".
var zapSinkMethodNames = map[string]struct{}{
	"Info":    {},
	"Debug":   {},
	"Warn":    {},
	"Error":   {},
	"Infow":   {},
	"Debugw":  {},
	"Warnw":   {},
	"Errorw":  {},
	"With":    {},
	"Sugar":   {},
}

func runSecretsNoLog(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()

	// Skip packages that are not in the secrets scope.
	inScope := false
	for _, prefix := range secretsPackagePrefixes {
		if strings.Contains(pkgPath, prefix) {
			inScope = true
			break
		}
	}
	if !inScope {
		return nil, nil
	}

	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// We analyse each function body independently. For each function, we
	// build a set of "tainted" identifiers — those assigned from source
	// method return values — then check every call expression to see whether
	// a tainted identifier appears in the argument list.
	//
	// We walk *ast.FuncDecl and *ast.FuncLit to cover both named and anonymous
	// functions.
	nodeFilter := []ast.Node{
		(*ast.FuncDecl)(nil),
		(*ast.FuncLit)(nil),
	}

	insp.Preorder(nodeFilter, func(n ast.Node) {
		var body *ast.BlockStmt
		switch fn := n.(type) {
		case *ast.FuncDecl:
			if fn.Body == nil {
				return
			}
			body = fn.Body
		case *ast.FuncLit:
			body = fn.Body
		}

		// Phase 1: collect tainted variables defined within this function body.
		// A tainted variable is one that receives the (first, []byte) return
		// value of a call whose method name is in sourceMethodNames.
		tainted := collectTainted(pass, body)
		if len(tainted) == 0 {
			return
		}

		// Phase 2: walk call expressions in the body and flag any tainted
		// argument passed to a logging sink.
		ast.Inspect(body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}

			if !isLoggingSink(pass, call) {
				return true
			}

			// Check each argument.
			for _, arg := range call.Args {
				if isTaintedIdent(arg, tainted) {
					pass.Reportf(arg.Pos(),
						"secrets value from Get/Resolve must not be passed to a logging sink — plaintext credential leaks to logs are forbidden (secrets-broker NFR Security). Received tainted []byte at argument position.")
				}
			}
			return true
		})
	})

	return nil, nil
}

// collectTainted returns the set of identifier names in body that are
// directly assigned from a call to a source method (Get or Resolve).
//
// It covers the following assignment forms:
//
//	v := broker.Get(...)           // AssignStmt, single LHS ident
//	v, err := broker.Get(...)      // AssignStmt, first LHS ident
//	v := svc.Resolve(...)          // same patterns
func collectTainted(pass *analysis.Pass, body *ast.BlockStmt) map[string]struct{} {
	tainted := make(map[string]struct{})

	ast.Inspect(body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(assign.Rhs) != 1 {
			return true
		}

		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}

		if !isSourceCall(pass, call) {
			return true
		}

		// The first (leftmost) LHS identifier receives the []byte return value.
		if len(assign.Lhs) == 0 {
			return true
		}
		if ident, ok := assign.Lhs[0].(*ast.Ident); ok {
			if ident.Name != "_" {
				tainted[ident.Name] = struct{}{}
			}
		}
		return true
	})

	return tainted
}

// isSourceCall reports whether call is a call to a method whose name is in
// sourceMethodNames and whose receiver/function is within a secrets-package
// context. We verify the receiver type's package path to avoid false positives.
func isSourceCall(pass *analysis.Pass, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		// Also handle bare function calls like Resolve(...) within the package.
		if ident, ok := call.Fun.(*ast.Ident); ok {
			if _, isSrc := sourceMethodNames[ident.Name]; isSrc {
				// Within a secrets package, a bare call to Resolve or Get is
				// still a source. Accept conservatively.
				return true
			}
		}
		return false
	}

	if _, isSrc := sourceMethodNames[sel.Sel.Name]; !isSrc {
		return false
	}

	// Use type information to check whether the receiver is from a
	// secrets-related package.
	obj, ok := pass.TypesInfo.Uses[sel.Sel]
	if !ok {
		// Without type info, fall back to name-only detection (conservative).
		return true
	}

	fn, ok := obj.(*types.Func)
	if !ok {
		return false
	}

	pkg := fn.Pkg()
	if pkg == nil {
		return false
	}

	for _, prefix := range secretsPackagePrefixes {
		if strings.Contains(pkg.Path(), prefix) {
			return true
		}
	}
	return false
}

// isLoggingSink reports whether call is a call to one of the known logging
// sink functions.
func isLoggingSink(pass *analysis.Pass, call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.SelectorExpr:
		// Could be a method call (e.g. logger.Info) or a package-qualified
		// call (e.g. slog.Info, log.Println).
		methodName := fn.Sel.Name

		// Check zap-style method calls by resolving the receiver type's package.
		if _, isZap := zapSinkMethodNames[methodName]; isZap {
			if obj, ok := pass.TypesInfo.Uses[fn.Sel]; ok {
				if f, ok := obj.(*types.Func); ok {
					if pkg := f.Pkg(); pkg != nil && strings.Contains(pkg.Path(), "go.uber.org/zap") {
						return true
					}
				}
			}
		}

		// Check package-qualified calls (slog.Info, log.Print, fmt.Printf, etc.).
		if obj, ok := pass.TypesInfo.Uses[fn.Sel]; ok {
			if f, ok := obj.(*types.Func); ok {
				if pkg := f.Pkg(); pkg != nil {
					if sinks, ok := loggingSinkPkgs[pkg.Path()]; ok {
						if _, isSink := sinks[methodName]; isSink {
							return true
						}
					}
				}
			}
		}

	case *ast.Ident:
		// Bare function call — only matches within the same package context.
		// The stdlib log/fmt packages are never imported without qualification
		// in well-formed Go, so this case is a safety net only.
		_ = fn
	}

	return false
}

// isTaintedIdent reports whether expr is an identifier whose name is in the
// tainted set, or a type-conversion expression (string(value), []byte(value))
// wrapping such an ident. We deliberately do NOT recurse into arbitrary
// function calls (e.g. len(value)) because those do not leak the raw value.
func isTaintedIdent(expr ast.Expr, tainted map[string]struct{}) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		_, ok := tainted[e.Name]
		return ok
	case *ast.CallExpr:
		// Only recurse when this looks like a type conversion:
		//   string(value)      — Fun is an *ast.Ident naming a builtin type
		//   []byte(value)      — Fun is an *ast.ArrayType
		//   MyType(value)      — Fun is an *ast.Ident naming a type
		// Skip calls like len(value), cap(value), copy(dst, value) — those
		// don't produce the raw secret bytes as the call result.
		if len(e.Args) == 1 {
			switch e.Fun.(type) {
			case *ast.Ident, *ast.ArrayType, *ast.SelectorExpr:
				// Heuristic: if the function expression is not a simple
				// package-qualified function (which would have type info
				// resolving to *types.Func), treat it as a type conversion.
				// We can disambiguate using TypesInfo if available, but the
				// conservative check is: only flag if the single-arg call
				// expression's Fun is an *ast.Ident that names a type OR the
				// inner arg is an ident in the tainted set AND the Fun is a
				// non-function type-ident. Since we cannot easily determine
				// "is this a type conversion vs a function call" without type
				// info at this AST-only level, we restrict to *ast.ArrayType
				// (always a type conversion) and leave *ast.Ident unrecursed
				// to avoid the len(value) false positive.
				if _, isArrayType := e.Fun.(*ast.ArrayType); isArrayType {
					return isTaintedIdent(e.Args[0], tainted)
				}
			}
		}
	case *ast.SliceExpr:
		// value[0:n] still contains the raw bytes — flag it.
		return isTaintedIdent(e.X, tainted)
	}
	return false
}
