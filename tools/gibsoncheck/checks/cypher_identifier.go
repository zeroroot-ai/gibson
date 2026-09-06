// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// CypherIdentifierAnalyzer closes the read-path half of gibson#1440: the
// write path (ADR-0012's graph projector) has exactly one writer, enforced
// structurally by GraphWriteAnalyzer, but the read path in
// internal/engine/graphrag/local_provider.go still assembled Cypher text from
// caller-supplied node types, relationship types and property keys via
// fmt.Sprintf, with a sanitiser (sanitizeIdentifier) placed in front of every
// current call site by convention rather than by construction.
//
// gibson#1266's acceptance criterion claimed a structural property — "No
// fmt.Sprintf-built Cypher remains anywhere in internal/engine/graphrag/" —
// that its own PR only delivered for the write path. A closed allow-list for
// node/relationship types was considered and rejected: the taxonomy is agent
// extensible at runtime (sdk/graphrag.TaxonomyRegistry.RegisterExtension), so
// a fixed list would reject legitimate custom types. Instead,
// local_provider.go now routes every identifier through a dedicated type,
// cypherFrag, that can only be produced by sanitizeIdentifier and a handful
// of combinators (intFrag, paramFrag, cypherf, joinFrags, labelExpr) or by
// converting a compile-time string constant. This analyzer is what makes
// that the ONLY way in, from the outside:
//
//   - A raw fmt.Sprintf (or string concatenation) building Cypher-shaped text
//     is flagged — the call site should have used cypherf instead, which
//     accepts only cypherFrag arguments for its %s verbs.
//   - A conversion to cypherFrag whose argument is not a compile-time
//     constant and not produced inside one of the designated constructors is
//     flagged — the type alone does not stop `cypherFrag(rawInput)`, since
//     Go permits any conversion between identical underlying types.
//
// # Scope
//
// Exactly the graphrag package (internal/engine/graphrag), not its
// subpackages: that is where cypherFrag is declared and where local_provider.go
// lives. internal/engine/graphrag/engine has its own, unrelated
// sanitizeIdentifier for the write path (gibson#1266) and does not define
// cypherFrag, so it is out of this analyzer's reach by construction — the
// type-conversion rule cannot even parse there.
//
// Ships with NO baseline, matching GraphWriteAnalyzer: the refactor that
// introduced cypherFrag left zero violations, and a baseline would only ever
// grow.
//
// Spec: gibson#1440.
var CypherIdentifierAnalyzer = &analysis.Analyzer{
	Name: "cypheridentifier",
	Doc:  "fail on Cypher text assembled from caller input outside the cypherFrag boundary (gibson#1440)",
	Run:  runCypherIdentifier,
}

// cypherIdentifierScopedPackage is the exact package this analyzer inspects.
// Not a substring match like graphWriteAllowedPackages: this rule is about a
// specific package's own local type, so an exact match is both correct and
// sufficient (a subpackage cannot even reference the unexported cypherFrag
// type from outside).
const cypherIdentifierScopedPackage = "github.com/zeroroot-ai/gibson/internal/engine/graphrag"

// cypherIdentifierTrustedConstructors are the only functions allowed to
// convert an arbitrary expression to cypherFrag. Every other conversion in
// the package must convert a compile-time constant.
var cypherIdentifierTrustedConstructors = map[string]bool{
	"sanitizeIdentifier": true,
	"intFrag":            true,
	"paramFrag":          true,
	"cypherf":            true,
	"joinFrags":          true,
	"labelExpr":          true,
}

// cypherKeyword matches an uppercase Cypher clause keyword as a whole word,
// so English prose containing a lowercase "return" or "match" in an error
// message is never a false positive. Every legitimate Cypher fragment in this
// package is written in the conventional uppercase Cypher style.
var cypherKeyword = regexp.MustCompile(`\b(MATCH|MERGE|CREATE|DELETE|DETACH|SET|WHERE|RETURN|WITH|UNWIND|OPTIONAL)\b`)

func runCypherIdentifier(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Path() != cypherIdentifierScopedPackage {
		return nil, nil
	}

	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") {
			// Test fixtures may build throwaway Cypher-shaped strings to seed a
			// mock; that is not the data plane this analyzer protects.
			continue
		}

		var enclosing *ast.FuncDecl
		ast.Inspect(file, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.FuncDecl:
				enclosing = v
			case *ast.CallExpr:
				checkRawSprintf(pass, v)
				checkFragConversion(pass, v, enclosing)
			case *ast.BinaryExpr:
				checkRawConcat(pass, v)
			}
			return true
		})
	}

	return nil, nil
}

// checkRawSprintf flags fmt.Sprintf calls whose format string looks like
// Cypher: the call site should have used cypherf, whose signature refuses a
// plain string for a %s verb.
func checkRawSprintf(pass *analysis.Pass, call *ast.CallExpr) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Sprintf" {
		return
	}
	if !isPackageFunc(pass, sel, "fmt", "Sprintf") {
		return
	}
	if len(call.Args) == 0 {
		return
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return
	}
	text, err := strconv.Unquote(lit.Value)
	if err != nil || !cypherKeyword.MatchString(text) {
		return
	}
	pass.Reportf(call.Pos(),
		"fmt.Sprintf builds Cypher-shaped text (%q) directly: use cypherf instead, which only "+
			"accepts cypherFrag arguments — a raw string cannot reach its %%s verbs (gibson#1440)",
		text)
}

// checkRawConcat flags string concatenation (`"MATCH (n:" + x + ")"`) whose
// literal half looks like Cypher and whose other operand is not itself
// cypherFrag-typed. This is the shape the original vulnerable code used for
// the QueryNodes MATCH clause before cypherf existed.
func checkRawConcat(pass *analysis.Pass, expr *ast.BinaryExpr) {
	if expr.Op != token.ADD {
		return
	}
	lit, other := literalOperand(expr)
	if lit == nil {
		return
	}
	text, err := strconv.Unquote(lit.Value)
	if err != nil || !cypherKeyword.MatchString(text) {
		return
	}
	if other == nil {
		return
	}
	if isCypherFragType(pass.TypesInfo.TypeOf(other), pass.Pkg.Path()) {
		return
	}
	pass.Reportf(expr.Pos(),
		"string concatenation builds Cypher-shaped text (%q) directly: use cypherf instead of "+
			"splicing a non-cypherFrag value into query text (gibson#1440)",
		text)
}

// literalOperand returns the string BasicLit half of a binary expression and
// the other operand, if exactly one side is a string literal. Returns (nil,
// nil) otherwise (both literals, e.g. plain constant folding, is not this
// analyzer's concern).
func literalOperand(expr *ast.BinaryExpr) (*ast.BasicLit, ast.Expr) {
	xLit, xOK := expr.X.(*ast.BasicLit)
	yLit, yOK := expr.Y.(*ast.BasicLit)
	switch {
	case xOK && xLit.Kind == token.STRING && !yOK:
		return xLit, expr.Y
	case yOK && yLit.Kind == token.STRING && !xOK:
		return yLit, expr.X
	default:
		return nil, nil
	}
}

// checkFragConversion flags a conversion to cypherFrag whose argument is
// neither a compile-time constant nor produced inside one of the trusted
// constructors. This is what stops `cypherFrag(rawInput)` from being used to
// route around sanitizeIdentifier: the named type alone does not prevent it,
// because Go permits a conversion between any two types with the same
// underlying type.
func checkFragConversion(pass *analysis.Pass, call *ast.CallExpr, enclosing *ast.FuncDecl) {
	if len(call.Args) != 1 {
		return
	}
	if !isCypherFragConversion(pass, call) {
		return
	}
	if enclosing != nil && cypherIdentifierTrustedConstructors[enclosing.Name.Name] {
		return
	}
	if tv, ok := pass.TypesInfo.Types[call.Args[0]]; ok && tv.Value != nil {
		// A compile-time constant (a string literal, or a const built from
		// one) cannot carry caller input.
		return
	}
	pass.Reportf(call.Pos(),
		"cypherFrag(%s) converts a non-constant value outside sanitizeIdentifier/intFrag/paramFrag/"+
			"cypherf/joinFrags/labelExpr: this is how a future call site bypasses the sanitiser without "+
			"anyone noticing (gibson#1440)", describeConversionArg(call.Args[0]))
}

// describeConversionArg renders the argument of a flagged cypherFrag(...)
// conversion for the diagnostic message.
func describeConversionArg(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return describeConversionArg(v.X) + "." + v.Sel.Name
	case *ast.CallExpr:
		return describeConversionArg(v.Fun) + "(…)"
	case *ast.BasicLit:
		return v.Value
	default:
		return "value"
	}
}

// isCypherFragConversion reports whether call is a type conversion to the
// cypherFrag type declared in this package.
func isCypherFragConversion(pass *analysis.Pass, call *ast.CallExpr) bool {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return false
	}
	obj := pass.TypesInfo.Uses[ident]
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return false
	}
	return isCypherFragType(tn.Type(), pass.Pkg.Path())
}

// isCypherFragType reports whether t is the cypherFrag named type declared in
// pkgPath.
func isCypherFragType(t types.Type, pkgPath string) bool {
	if t == nil {
		return false
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Name() == "cypherFrag" && obj.Pkg() != nil && obj.Pkg().Path() == pkgPath
}

// isPackageFunc reports whether sel resolves to funcName declared in pkgPath.
func isPackageFunc(pass *analysis.Pass, sel *ast.SelectorExpr, pkgPath, funcName string) bool {
	obj := pass.TypesInfo.Uses[sel.Sel]
	fn, ok := obj.(*types.Func)
	if !ok || fn.Name() != funcName {
		return false
	}
	return fn.Pkg() != nil && fn.Pkg().Path() == pkgPath
}
