// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks

// White-box tests for GraphWriteAnalyzer's pure helper functions.
//
// The analysistest fixtures in graph_write_test.go exercise the analyzer end
// to end against real, type-checked Go source, which is the right tool for
// "does this rule fire on realistic code" — but neo4j.SessionWithContext is a
// sealed interface (it embeds unexported methods, so nothing outside the
// driver package can implement it) and several branches here exist for AST
// shapes and go/types edge cases that are awkward or impossible to coax out
// of real source: a nil *analysis.Pass.TypesInfo, a Selections-map miss, a
// non-Named receiver type, a receiver expression that isn't a plain
// identifier. Those are tested directly against the unexported helpers with
// hand-built go/ast and go/types values, which is simpler and more precise
// than contriving source that happens to produce the right shape.
import (
	"go/ast"
	"go/token"
	"go/types"
	"testing"

	"golang.org/x/tools/go/analysis"
)

// neo4jNamedType returns a *types.Named standing in for a type declared in
// the Neo4j driver module, e.g. neo4j.SessionWithContext.
func neo4jNamedType(typeName string) *types.Named {
	pkg := types.NewPackage(neo4jDriverModulePath+"/neo4j", "neo4j")
	obj := types.NewTypeName(token.NoPos, pkg, typeName, nil)
	return types.NewNamed(obj, types.NewInterfaceType(nil, nil), nil)
}

// otherNamedType returns a *types.Named for an unrelated package, standing in
// for a same-named method on a type the analyzer must NOT flag.
func otherNamedType(typeName string) *types.Named {
	pkg := types.NewPackage("github.com/zeroroot-ai/gibson/internal/example", "example")
	obj := types.NewTypeName(token.NoPos, pkg, typeName, nil)
	return types.NewNamed(obj, types.NewStruct(nil, nil), nil)
}

func TestIsNeo4jDriverType(t *testing.T) {
	neo4jType := neo4jNamedType("SessionWithContext")
	otherType := otherNamedType("Foo")

	// A Named type whose Obj() has no package — this is how go/types
	// represents predeclared/universe types (e.g. error, comparable); it is
	// not something a real Neo4j driver call site produces, but the nil-pkg
	// guard exists for exactly this shape and deserves direct coverage.
	noPkgObj := types.NewTypeName(token.NoPos, nil, "Bar", nil)
	noPkgType := types.NewNamed(noPkgObj, types.NewStruct(nil, nil), nil)

	tests := []struct {
		name string
		typ  types.Type
		want bool
	}{
		{"nil type", nil, false},
		{"basic (non-Named) type", types.Typ[types.Int], false},
		{"named type with no package", noPkgType, false},
		{"named type outside the neo4j driver module", otherType, false},
		{"named neo4j driver type", neo4jType, true},
		{"pointer to a named neo4j driver type", types.NewPointer(neo4jType), true},
		{"pointer to a named non-neo4j type", types.NewPointer(otherType), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNeo4jDriverType(tt.typ); got != tt.want {
				t.Errorf("isNeo4jDriverType(%v) = %v, want %v", tt.typ, got, tt.want)
			}
		})
	}
}

func TestIsNeo4jDriverReceiver(t *testing.T) {
	newSel := func() (*ast.Ident, *ast.SelectorExpr) {
		x := ast.NewIdent("x")
		return x, &ast.SelectorExpr{X: x, Sel: ast.NewIdent("ExecuteWrite")}
	}

	t.Run("nil TypesInfo returns false rather than panicking", func(t *testing.T) {
		_, sel := newSel()
		pass := &analysis.Pass{TypesInfo: nil}
		if got := isNeo4jDriverReceiver(pass, sel); got != false {
			t.Errorf("isNeo4jDriverReceiver() = %v, want false", got)
		}
	})

	t.Run("Selections miss falls back to Types and finds a neo4j receiver", func(t *testing.T) {
		x, sel := newSel()
		info := &types.Info{
			Selections: map[*ast.SelectorExpr]*types.Selection{}, // sel absent: miss
			Types: map[ast.Expr]types.TypeAndValue{
				x: {Type: neo4jNamedType("SessionWithContext")},
			},
		}
		pass := &analysis.Pass{TypesInfo: info}
		if got := isNeo4jDriverReceiver(pass, sel); got != true {
			t.Errorf("isNeo4jDriverReceiver() = %v, want true", got)
		}
	})

	t.Run("Selections miss and Types miss returns false", func(t *testing.T) {
		_, sel := newSel()
		info := &types.Info{
			Selections: map[*ast.SelectorExpr]*types.Selection{},
			Types:      map[ast.Expr]types.TypeAndValue{}, // sel.X absent too
		}
		pass := &analysis.Pass{TypesInfo: info}
		if got := isNeo4jDriverReceiver(pass, sel); got != false {
			t.Errorf("isNeo4jDriverReceiver() = %v, want false", got)
		}
	})

	t.Run("Selections miss falls back to Types and finds a non-neo4j receiver", func(t *testing.T) {
		x, sel := newSel()
		info := &types.Info{
			Selections: map[*ast.SelectorExpr]*types.Selection{},
			Types: map[ast.Expr]types.TypeAndValue{
				x: {Type: otherNamedType("Foo")},
			},
		}
		pass := &analysis.Pass{TypesInfo: info}
		if got := isNeo4jDriverReceiver(pass, sel); got != false {
			t.Errorf("isNeo4jDriverReceiver() = %v, want false", got)
		}
	})
}

func TestExprString(t *testing.T) {
	ident := ast.NewIdent("session")
	sel := &ast.SelectorExpr{X: ast.NewIdent("h"), Sel: ast.NewIdent("sess")}
	call := &ast.CallExpr{Fun: ast.NewIdent("getSession")}
	index := &ast.IndexExpr{X: ast.NewIdent("sessions"), Index: ast.NewIdent("0")}
	// A shape exprString does not special-case, to hit the fallback.
	other := &ast.StarExpr{X: ast.NewIdent("session")}

	tests := []struct {
		name string
		expr ast.Expr
		want string
	}{
		{"identifier", ident, "session"},
		{"selector expression", sel, "h.sess"},
		{"call expression", call, "getSession(…)"},
		{"index expression", index, "sessions[…]"},
		{"unhandled shape falls back to a placeholder", other, "session"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exprString(tt.expr); got != tt.want {
				t.Errorf("exprString(%T) = %q, want %q", tt.expr, got, tt.want)
			}
		})
	}
}
