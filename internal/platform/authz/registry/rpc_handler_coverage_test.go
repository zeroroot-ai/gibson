package registry_test

// rpc_handler_coverage_test.go is the handler-test dimension of the per-RPC
// test walker (gibson#793, E3 / QUALITY-BARS §4).
//
// It enumerates every registered gRPC RPC (registry.Registry) and asserts a
// handler test exists for it. "Handler test exists" is detected structurally:
// a Go test function named Test<Method> or Test<Method>_<Scenario> somewhere
// in the module. This is the convention every handler test in this repo
// already follows (TestCreateAgentIdentity_HappyPath,
// TestListMissions_NotProvisioned..., TestRevokeMySession_RequiresSessionID).
//
// The companion authz-deny dimension lives in rpc_authz_deny_test.go and is
// green by construction for all RPCs (the registry IS the deny contract).
//
// === Ratchet, not a one-shot backfill ===
// 149 of the 250 distinct RPC methods do not yet have a handler test. Writing
// all of them in one PR is neither reviewable nor honest, so this gate uses
// the same shrinking-baseline mechanism the repo already uses for deadcode
// (see Makefile: lint-deadcode-baseline). rpc_handler_coverage_baseline.txt
// lists the full method paths that currently lack a handler test. The gate:
//
//   - FAILS if a registered RPC lacks a handler test AND is not in the
//     baseline  -> you added/renamed an RPC without a test. Write one.
//   - FAILS if a baseline entry now HAS a handler test (or is no longer
//     registered) -> the baseline must shrink. Delete that line.
//
// Net effect: the untested set can only go down. New RPCs are hard-gated from
// day one; the existing debt is tracked and burned down by deleting baseline
// lines as tests land.
//
// Regenerate the baseline (only when intentionally accepting current reality,
// e.g. after a large RPC rename) with:
//
//	GIBSON_REGEN_RPC_BASELINE=1 go test ./internal/platform/authz/registry/ -run TestEveryRegisteredRPCHasHandlerTest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/authz/registry"
)

const baselineFileName = "rpc_handler_coverage_baseline.txt"

// repoRoot resolves the gibson module root from this test file's location:
// internal/platform/authz/registry/ -> four directories up.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

// skipDirs are directories never scanned for test functions: VCS, agent
// worktrees (embedded clones), vendored code, build output, and generated
// proto trees. testdata is kept — fixtures occasionally hold real tests.
var skipDirs = map[string]struct{}{
	".git":         {},
	".claude":      {},
	".worktrees":   {},
	"vendor":       {},
	"bin":          {},
	".tmp":         {},
	"node_modules": {},
}

// collectTestFuncNames walks root and returns the set of test function names
// (the identifier after "Test") declared in every _test.go file. Parsing is
// name-only; bodies and imports are irrelevant, so a syntax error in one file
// is skipped rather than failing the whole walk.
func collectTestFuncNames(t *testing.T, root string) map[string]struct{} {
	t.Helper()
	names := map[string]struct{}{}
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			// Unparseable test file — ignore for name collection.
			return nil
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Name == nil {
				continue
			}
			name := fn.Name.Name
			if !strings.HasPrefix(name, "Test") || len(name) <= len("Test") {
				continue
			}
			// Must be a real test signature: func TestXxx(t *testing.T).
			if !isTestSignature(fn) {
				continue
			}
			names[strings.TrimPrefix(name, "Test")] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(names) == 0 {
		t.Fatalf("found no test functions under %s — scan is misconfigured", root)
	}
	return names
}

// isTestSignature reports whether fn looks like func TestX(*testing.T). It
// deliberately excludes TestMain, benchmarks, and helpers named TestFoo that
// take other args.
func isTestSignature(fn *ast.FuncDecl) bool {
	if fn.Name.Name == "TestMain" {
		return false
	}
	if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 {
		return false
	}
	star, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "T"
}

// methodShortName returns the RPC method from a full "/pkg.Service/Method" key.
func methodShortName(fullMethod string) string {
	i := strings.LastIndex(fullMethod, "/")
	if i < 0 {
		return fullMethod
	}
	return fullMethod[i+1:]
}

// hasHandlerTest reports whether any collected test name matches the repo
// convention Test<Method> or Test<Method>_<Scenario> for the given method.
func hasHandlerTest(method string, testNames map[string]struct{}) bool {
	if _, ok := testNames[method]; ok {
		return true
	}
	re := regexp.MustCompile("^" + regexp.QuoteMeta(method) + "_")
	for n := range testNames {
		if re.MatchString(n) {
			return true
		}
	}
	return false
}

// TestEveryRegisteredRPCHasHandlerTest is the ratcheting handler-test gate.
func TestEveryRegisteredRPCHasHandlerTest(t *testing.T) {
	root := repoRoot(t)
	testNames := collectTestFuncNames(t, root)

	// Compute the current set of registered methods lacking a handler test.
	currentGaps := map[string]struct{}{}
	for fullMethod := range registry.Registry {
		if !hasHandlerTest(methodShortName(fullMethod), testNames) {
			currentGaps[fullMethod] = struct{}{}
		}
	}

	baselinePath := filepath.Join(filepath.Dir(callerFile(t)), baselineFileName)

	if os.Getenv("GIBSON_REGEN_RPC_BASELINE") == "1" {
		writeBaseline(t, baselinePath, currentGaps)
		t.Logf("regenerated %s with %d untested RPC(s)", baselineFileName, len(currentGaps))
		return
	}

	baseline := readBaseline(t, baselinePath)

	// New gaps: registered, untested, and NOT already accepted in the baseline.
	var newGaps []string
	for m := range currentGaps {
		if _, accepted := baseline[m]; !accepted {
			newGaps = append(newGaps, m)
		}
	}

	// Stale baseline lines: accepted as untested but now either tested or no
	// longer registered. The baseline must shrink — delete these lines.
	var stale []string
	for m := range baseline {
		if _, stillGap := currentGaps[m]; !stillGap {
			stale = append(stale, m)
		}
	}

	if len(newGaps) > 0 {
		sort.Strings(newGaps)
		t.Errorf("%d registered RPC(s) have no handler test and are not in %s.\n"+
			"Add a Test<Method>[_Scenario] test (success + error) for each:\n  %s",
			len(newGaps), baselineFileName, strings.Join(newGaps, "\n  "))
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		t.Errorf("%d entr(y/ies) in %s are stale (now tested or unregistered) — delete these lines to ratchet the gate down:\n  %s",
			len(stale), baselineFileName, strings.Join(stale, "\n  "))
	}
}

// callerFile returns this test file's path so the baseline is read/written
// next to it regardless of the test binary's working directory.
func callerFile(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return file
}

func readBaseline(t *testing.T, path string) map[string]struct{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading baseline %s: %v (run with GIBSON_REGEN_RPC_BASELINE=1 to create it)", path, err)
	}
	out := map[string]struct{}{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = struct{}{}
	}
	return out
}

func writeBaseline(t *testing.T, path string, gaps map[string]struct{}) {
	t.Helper()
	lines := make([]string, 0, len(gaps))
	for m := range gaps {
		lines = append(lines, m)
	}
	sort.Strings(lines)
	header := "# Generated tech-debt baseline for the per-RPC handler-test walker (gibson#793).\n" +
		"# Each line is a registered RPC that does NOT yet have a handler test.\n" +
		"# This set may only SHRINK: write a Test<Method>[_Scenario] test, then delete\n" +
		"# its line here. The walker (TestEveryRegisteredRPCHasHandlerTest) fails on any\n" +
		"# new untested RPC and on any stale line left behind after a test lands.\n" +
		"# Regenerate (rarely): GIBSON_REGEN_RPC_BASELINE=1 go test ./internal/platform/authz/registry/\n"
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(header+body), 0o644); err != nil {
		t.Fatalf("writing baseline %s: %v", path, err)
	}
}
