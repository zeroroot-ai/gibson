// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// ProjectorCypherAnalyzer enforces the second half of ADR-0112: the graph
// projector builds no Cypher from input. GraphWriteAnalyzer proves that the
// projector is the only writer. This analyzer proves what the projector
// writes: in a file of the projector, each Cypher text that reaches the
// driver is a compile-time constant. Labels and relationship types travel as
// parameters ($params, apoc.merge.node), never as query text.
//
// # What is checked
//
// In each projector file (internal/server/daemon/graph_projector*.go, not a
// test), each argument passed to a string parameter named `cypher` (the
// driver's Run, and each projector helper that forwards a query), or to a
// string parameter named `query` of a Neo4j driver function, must be one of:
//
//   - a compile-time constant;
//   - a parameter named `cypher` of the function that holds the call, which
//     forwards the constant its own callers pass (each of those calls is
//     checked by the same rule);
//   - a conversion to string of a value of the type schemaStatement.
//
// schemaStatement is the one exception, and it is closed by construction.
// Neo4j DDL takes no parameter for a label or a property, so a schema
// statement holds their text. A conversion to schemaStatement of a value that
// is not a constant is allowed only inside the designated constructors, which
// refuse a name that is not a plain identifier (taxonomy.ValidIdentifier).
//
// Ships with NO baseline, like GraphWriteAnalyzer. The rule held on the
// projector when it was written.
//
// Spec: ADR-0112, gibson#993.
var ProjectorCypherAnalyzer = &analysis.Analyzer{
	Name: "projectorcypher",
	Doc:  "fail when a file of the graph projector passes Cypher text that is not a constant to the driver (ADR-0112)",
	Run:  runProjectorCypher,
}

// projectorCypherParam is the name of the parameter that carries Cypher text
// in the driver (Run) and in each projector helper.
const projectorCypherParam = "cypher"

// projectorDriverQueryParam is the name of the query parameter of a driver
// function such as neo4j.ExecuteQuery.
const projectorDriverQueryParam = "query"

// projectorSchemaStatementType is the type of a schema statement.
const projectorSchemaStatementType = "schemaStatement"

// projectorSchemaConstructors are the only functions that may convert text
// that is not a constant to schemaStatement.
var projectorSchemaConstructors = map[string]bool{
	"ddlUniqueConstraint": true,
	"ddlIndex":            true,
}

func runProjectorCypher(pass *analysis.Pass) (any, error) {
	if !strings.HasSuffix(pass.Pkg.Path(), graphWriteProjectorPackage) {
		return nil, nil
	}
	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		if strings.HasSuffix(fname, "_test.go") || !isGraphProjectorFile(fname) {
			continue
		}
		forwarders := cypherParams(pass, file)
		for _, decl := range file.Decls {
			fn, _ := decl.(*ast.FuncDecl)
			ast.Inspect(decl, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				checkSchemaConversion(pass, fn, call)
				checkCypherArguments(pass, call, forwarders)
				return true
			})
		}
	}
	return nil, nil
}

// cypherParams returns each function parameter of the file that is named
// cypher and has the type string. Such a parameter forwards Cypher text.
func cypherParams(pass *analysis.Pass, file *ast.File) map[types.Object]bool {
	out := map[types.Object]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		var ft *ast.FuncType
		switch f := n.(type) {
		case *ast.FuncDecl:
			ft = f.Type
		case *ast.FuncLit:
			ft = f.Type
		default:
			return true
		}
		if ft.Params == nil {
			return true
		}
		for _, field := range ft.Params.List {
			for _, name := range field.Names {
				obj := pass.TypesInfo.Defs[name]
				if obj != nil && name.Name == projectorCypherParam && isStringType(obj.Type()) {
					out[obj] = true
				}
			}
		}
		return true
	})
	return out
}

// checkCypherArguments checks each argument that the callee takes as Cypher
// text.
func checkCypherArguments(pass *analysis.Pass, call *ast.CallExpr, forwarders map[types.Object]bool) {
	tv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok || tv.IsType() {
		return
	}
	sig, ok := tv.Type.Underlying().(*types.Signature)
	if !ok {
		return
	}
	driver := isNeo4jDriverCallee(pass, call.Fun)
	params := sig.Params()
	for i := 0; i < params.Len() && i < len(call.Args); i++ {
		if sig.Variadic() && i == params.Len()-1 {
			break
		}
		p := params.At(i)
		if !isStringType(p.Type()) {
			continue
		}
		if p.Name() != projectorCypherParam && (!driver || p.Name() != projectorDriverQueryParam) {
			continue
		}
		arg := call.Args[i]
		if allowedCypherArgument(pass, arg, forwarders) {
			continue
		}
		pass.Reportf(arg.Pos(),
			"the graph projector passes Cypher text that is not a constant (%s): pass labels and "+
				"relationship types as $params, and keep each query a constant (ADR-0112)",
			exprString(arg))
	}
}

// allowedCypherArgument reports whether arg is a constant, a forwarding
// cypher parameter, or a conversion to string of a schemaStatement.
func allowedCypherArgument(pass *analysis.Pass, arg ast.Expr, forwarders map[types.Object]bool) bool {
	arg = ast.Unparen(arg)
	if tv, ok := pass.TypesInfo.Types[arg]; ok && tv.Value != nil {
		return true
	}
	if id, ok := arg.(*ast.Ident); ok {
		if obj := pass.TypesInfo.Uses[id]; obj != nil && forwarders[obj] {
			return true
		}
	}
	if conv, ok := arg.(*ast.CallExpr); ok && len(conv.Args) == 1 {
		if ftv, ok := pass.TypesInfo.Types[conv.Fun]; ok && ftv.IsType() && isStringType(ftv.Type) {
			if inner, ok := pass.TypesInfo.Types[conv.Args[0]]; ok && isSchemaStatement(pass, inner.Type) {
				return true
			}
		}
	}
	return false
}

// checkSchemaConversion reports a conversion to schemaStatement of a value
// that is not a constant, outside the designated constructors.
func checkSchemaConversion(pass *analysis.Pass, fn *ast.FuncDecl, call *ast.CallExpr) {
	if len(call.Args) != 1 {
		return
	}
	ftv, ok := pass.TypesInfo.Types[call.Fun]
	if !ok || !ftv.IsType() || !isSchemaStatement(pass, ftv.Type) {
		return
	}
	if tv, ok := pass.TypesInfo.Types[call.Args[0]]; ok && tv.Value != nil {
		return
	}
	if fn != nil && fn.Recv == nil && projectorSchemaConstructors[fn.Name.Name] {
		return
	}
	pass.Reportf(call.Pos(),
		"a schemaStatement is made from text that is not a constant outside ddlUniqueConstraint and ddlIndex: "+
			"only those constructors check each name (ADR-0112)")
}

// isSchemaStatement reports whether t is the schemaStatement type of the
// analyzed package.
func isSchemaStatement(pass *analysis.Pass, t types.Type) bool {
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Name() == projectorSchemaStatementType && obj.Pkg() == pass.Pkg
}

// isNeo4jDriverCallee reports whether the called function or method is
// declared in the Neo4j driver module.
func isNeo4jDriverCallee(pass *analysis.Pass, fun ast.Expr) bool {
	switch f := ast.Unparen(fun).(type) {
	case *ast.SelectorExpr:
		if isNeo4jDriverReceiver(pass, f) {
			return true
		}
		if obj := pass.TypesInfo.Uses[f.Sel]; obj != nil && obj.Pkg() != nil {
			return strings.HasPrefix(obj.Pkg().Path(), neo4jDriverModulePath)
		}
	case *ast.Ident:
		if obj := pass.TypesInfo.Uses[f]; obj != nil && obj.Pkg() != nil {
			return strings.HasPrefix(obj.Pkg().Path(), neo4jDriverModulePath)
		}
	}
	return false
}

// isStringType reports whether t is the basic type string.
func isStringType(t types.Type) bool {
	b, ok := t.(*types.Basic)
	return ok && b.Kind() == types.String
}
