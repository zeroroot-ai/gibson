// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

// callCount counts the calls of pkg.fn in the Go source at path. Comments
// do not count.
func callCount(path, pkg, fn string) (int, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	n := 0
	ast.Inspect(f, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == pkg && sel.Sel.Name == fn {
				n++
			}
		}
		return true
	})
	return n, nil
}

// countProblems compares the calls of pkg.fn in each allowlisted file with
// the count the allowlist recorded. The allowlist of ast-checks is keyed by
// file and call text, so one entry covers every call of a file: a NEW call in
// an allowlisted file passed unseen (gibson#807 condition 7). A count that
// differs either way is a problem: more is a new call that needs its own
// reason, fewer is a stale count.
func countProblems(repoRoot string, counts map[string]int, pkg, fn string) []string {
	var out []string
	for rel, want := range counts {
		got, err := callCount(filepath.Join(repoRoot, rel), pkg, fn)
		if err != nil {
			out = append(out, err.Error())
			continue
		}
		if got != want {
			out = append(out, fmt.Sprintf("%s: %d call(s) of %s.%s(), the allowlist recorded %d. "+
				"Give a new call its reason and update the count, or lower a stale count.", rel, got, pkg, fn, want))
		}
	}
	return out
}

// TestCountProblems_FlagsANewCallInAnAllowlistedFile is the failing fixture
// of the per-file call counts.
func TestCountProblems_FlagsANewCallInAnAllowlistedFile(t *testing.T) {
	dir := t.TempDir()
	src := "package x\n\nimport \"time\"\n\n// time.Now() in a comment does not count.\nfunc a() { _ = time.Now() }\nfunc b() { _ = time.Now() }\n"
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := countProblems(dir, map[string]int{"x.go": 2}, "time", "Now"); len(p) != 0 {
		t.Fatalf("an exact count was refused: %v", p)
	}
	if p := countProblems(dir, map[string]int{"x.go": 1}, "time", "Now"); len(p) != 1 {
		t.Fatalf("a new call in an allowlisted file passed: %v", p)
	}
	if p := countProblems(dir, map[string]int{"x.go": 3}, "time", "Now"); len(p) != 1 {
		t.Fatalf("a stale count passed: %v", p)
	}
}
