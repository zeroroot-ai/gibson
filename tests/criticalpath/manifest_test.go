package criticalpath

// manifest_test.go is the pure-unit guard for the integration lane's critical-
// path contract (gibson#795). It parses the test files of each pinned package
// and asserts every CoveringTest in the Manifest still exists. No Docker, no
// infra — it runs in the normal unit lane so a deleted/renamed critical-path
// test fails CI immediately, independent of whether the (slower, container-
// backed) integration lane ran.
//
// go/parser reads source regardless of build tags, so integration-tagged tests
// (//go:build integration) are still found here.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRoot resolves the module root from this file: tests/criticalpath/ ⇒ two up.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// testFuncsInDir returns the set of test function names declared in _test.go
// files directly under dir (non-recursive — a package is one directory).
func testFuncsInDir(t *testing.T, dir string) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out // missing dir surfaces as "function not found" below
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, e.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil {
				continue
			}
			out[fn.Name.Name] = struct{}{}
		}
	}
	return out
}

// TestManifestCoversFiveCriticalPaths is a sanity check on the manifest shape:
// QUALITY-BARS §4 Tier 3 names exactly five paths, each with at least one test.
func TestManifestCoversFiveCriticalPaths(t *testing.T) {
	const want = 5
	if len(Manifest) != want {
		t.Fatalf("manifest must declare exactly %d critical paths, has %d", want, len(Manifest))
	}
	seen := map[string]bool{}
	for _, cp := range Manifest {
		if cp.Name == "" || cp.Purpose == "" {
			t.Errorf("critical path %q missing name/purpose", cp.Name)
		}
		if seen[cp.Name] {
			t.Errorf("duplicate critical path name %q", cp.Name)
		}
		seen[cp.Name] = true
		if len(cp.Tests) == 0 {
			t.Errorf("critical path %q has no covering tests", cp.Name)
		}
	}
}

// TestEveryCriticalPathTestExists is the guard: every pinned test must be
// present in its declared package directory.
func TestEveryCriticalPathTestExists(t *testing.T) {
	root := repoRoot(t)

	// Cache per-directory function sets so repeated dirs are parsed once.
	cache := map[string]map[string]struct{}{}
	funcsFor := func(dir string) map[string]struct{} {
		if s, ok := cache[dir]; ok {
			return s
		}
		s := testFuncsInDir(t, filepath.Join(root, dir))
		cache[dir] = s
		return s
	}

	var missing []string
	for _, cp := range Manifest {
		for _, ct := range cp.Tests {
			if _, ok := funcsFor(ct.Dir)[ct.Func]; !ok {
				missing = append(missing, cp.Name+": "+ct.Dir+" :: "+ct.Func+"()")
			}
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("%d mandatory critical-path test(s) missing — restore them or update tests/criticalpath/manifest.go in the same change:\n  %s",
			len(missing), strings.Join(missing, "\n  "))
	}
}
