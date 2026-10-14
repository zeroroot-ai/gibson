// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// notRunIn returns each analyzer name that the workflow text never invokes
// as `gibsoncheck -<name>`.
func notRunIn(names []string, workflow string) []string {
	var missing []string
	for _, n := range names {
		if !regexp.MustCompile(`gibsoncheck\s+-` + regexp.QuoteMeta(n) + `\s`).MatchString(workflow) {
			missing = append(missing, n)
		}
	}
	return missing
}

// registeredNames reads the analyzers that main.go passes to
// multichecker.Main, and the Name of each from its declaration in checks/.
// It reads the source, so main.go keeps the one list.
func registeredNames(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	mainFile, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	var vars []string
	ast.Inspect(mainFile, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "checks" && strings.HasSuffix(sel.Sel.Name, "Analyzer") {
				vars = append(vars, sel.Sel.Name)
			}
		}
		return true
	})
	names := map[string]string{}
	files, err := filepath.Glob(filepath.Join("checks", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("list checks/*.go: %v (%d files)", err, len(files))
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				return true
			}
			ast.Inspect(vs.Values[0], func(m ast.Node) bool {
				kv, ok := m.(*ast.KeyValueExpr)
				if !ok {
					return true
				}
				if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Name" {
					if lit, ok := kv.Value.(*ast.BasicLit); ok {
						names[vs.Names[0].Name] = strings.Trim(lit.Value, `"`)
					}
				}
				return true
			})
			return true
		})
	}
	out := make([]string, 0, len(vars))
	for _, v := range vars {
		n, ok := names[v]
		if !ok {
			t.Fatalf("checks.%s has no `Name: \"...\"` literal that this test can read", v)
		}
		out = append(out, n)
	}
	return out
}

// TestEveryAnalyzerRunsInCI fails when an analyzer is registered but no CI
// step runs it. Five analyzers were in that state: their analysistest
// fixtures passed, and the guard itself never ran (gibson#807 condition 7).
func TestEveryAnalyzerRunsInCI(t *testing.T) {
	wf, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "gibsoncheck.yml"))
	if err != nil {
		t.Fatalf("read the workflow: %v", err)
	}
	names := registeredNames(t)
	if len(names) < 15 {
		t.Fatalf("found %d analyzers, want at least 15: the list did not load", len(names))
	}
	if missing := notRunIn(names, string(wf)); len(missing) > 0 {
		t.Fatalf("gibsoncheck.yml never runs %v. Add `./bin/gibsoncheck -<name> <packages>` to a gate step.", missing)
	}
}

// TestNotRunIn_FlagsAnAnalyzerTheWorkflowSkips is the failing fixture.
func TestNotRunIn_FlagsAnAnalyzerTheWorkflowSkips(t *testing.T) {
	wf := "run: |\n  ./bin/gibsoncheck -alpha ./internal/...\n  ./bin/gibsoncheck -alphabet ./cmd/...\n"
	got := notRunIn([]string{"alpha", "beta", "alphab"}, wf)
	if want := []string{"beta", "alphab"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("notRunIn = %v, want %v", got, want)
	}
}
