// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package registry_test

// rpc_handler_coverage_test.go is the handler-test dimension of the per-RPC
// test walker (gibson#793, E3 / QUALITY-BARS §4).
//
// It enumerates every registered gRPC RPC (registry.Registry) and asserts a
// handler test exists for it. "Handler test exists" is detected structurally:
// a Go test function named Test<Method> or Test<Method>_<Scenario> in the
// directory of a package that implements the service of that RPC. A package
// implements a service when one of its non-test files embeds
// Unimplemented<Service>Server. The service counts, because the same method
// name exists on several services (QueryPlugin is on three), and a test of one
// handler must not cover the others. This is the convention every handler test in this repo
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
	"os/exec"
	"path/filepath"
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

// handlerTests maps a test function name (the identifier after "Test") to the
// directories whose _test.go files declare it.
type handlerTests map[string]map[string]struct{}

// serviceDirs maps a service short name (for example "ComponentService") to the
// directories of the packages that implement it.
type serviceDirs map[string]map[string]struct{}

// scanModule walks root once. It returns the test function names with their
// directories, and the directories that implement each service. Parsing is
// name-only; bodies and imports are irrelevant, so a syntax error in one file
// is skipped rather than failing the whole walk.
func scanModule(t *testing.T, root string) (handlerTests, serviceDirs) {
	t.Helper()
	tests := handlerTests{}
	services := serviceDirs{}
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
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return nil //nolint:nilerr // an unparseable file is ignored, as before
		}
		dir := filepath.Dir(path)
		if strings.HasSuffix(path, "_test.go") {
			addTestFuncs(tests, f, dir)
			return nil
		}
		for _, svc := range embeddedServices(f) {
			if services[svc] == nil {
				services[svc] = map[string]struct{}{}
			}
			services[svc][dir] = struct{}{}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	if len(tests) == 0 {
		t.Fatalf("found no test functions under %s — scan is misconfigured", root)
	}
	if len(services) == 0 {
		t.Fatalf("found no service implementation under %s — scan is misconfigured", root)
	}
	return tests, services
}

// addTestFuncs records the test functions of one _test.go file.
func addTestFuncs(tests handlerTests, f *ast.File, dir string) {
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name == nil {
			continue
		}
		name := fn.Name.Name
		if !strings.HasPrefix(name, "Test") || len(name) <= len("Test") || !isTestSignature(fn) {
			continue
		}
		short := strings.TrimPrefix(name, "Test")
		if tests[short] == nil {
			tests[short] = map[string]struct{}{}
		}
		tests[short][dir] = struct{}{}
	}
}

// embeddedServices returns the services whose Unimplemented<Service>Server a
// struct of the file embeds. An embedded field of that name is how a package
// declares that it implements the service.
func embeddedServices(f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		st, ok := n.(*ast.StructType)
		if !ok {
			return true
		}
		for _, field := range st.Fields.List {
			if len(field.Names) != 0 {
				continue
			}
			name := toolEmbeddedName(field.Type)
			if strings.HasPrefix(name, "Unimplemented") && strings.HasSuffix(name, "Server") {
				out = append(out, strings.TrimSuffix(strings.TrimPrefix(name, "Unimplemented"), "Server"))
			}
		}
		return true
	})
	return out
}

// toolEmbeddedName returns the type name of an embedded field.
func toolEmbeddedName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return toolEmbeddedName(t.X)
	}
	return ""
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

// serviceShortName returns the service from a full "/pkg.Service/Method" key.
func serviceShortName(fullMethod string) string {
	parts := strings.Split(strings.TrimPrefix(fullMethod, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[0][strings.LastIndex(parts[0], ".")+1:]
}

// testNameMatches reports whether a collected name follows the repo convention
// Test<Method> or Test<Method>_<Scenario> for the method.
func testNameMatches(method, name string) bool {
	return name == method || strings.HasPrefix(name, method+"_")
}

// hasHandlerTest reports whether a handler test exists for the RPC: a test
// named for its method, in a directory that implements its service.
func hasHandlerTest(fullMethod string, tests handlerTests, services serviceDirs) bool {
	method := methodShortName(fullMethod)
	impl := services[serviceShortName(fullMethod)]
	for name, dirs := range tests {
		if !testNameMatches(method, name) {
			continue
		}
		for dir := range dirs {
			if _, ok := impl[dir]; ok {
				return true
			}
		}
	}
	return false
}

// TestEveryRegisteredRPCHasHandlerTest is the ratcheting handler-test gate.
func TestEveryRegisteredRPCHasHandlerTest(t *testing.T) {
	root := repoRoot(t)
	tests, services := scanModule(t, root)

	// Compute the current set of registered methods lacking a handler test.
	currentGaps := map[string]struct{}{}
	for fullMethod := range registry.Registry {
		if !hasHandlerTest(fullMethod, tests, services) {
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

// The failing fixture of the service key. QueryPlugin exists on three services.
// A test of the handler of one service must not make the others count as
// tested, so a test in the directory of another service covers nothing.
func TestHasHandlerTest_KeysByServiceAndMethod(t *testing.T) {
	tests := handlerTests{
		"QueryPlugin":        {"internal/engine/harness": {}},
		"CallTool_Connector": {"internal/platform/component": {}},
	}
	services := serviceDirs{
		"HarnessCallbackService": {"internal/engine/harness": {}},
		"ComponentService":       {"internal/platform/component": {}},
		"DaemonService":          {"internal/server/daemon/api": {}},
	}
	for _, tc := range []struct {
		rpc  string
		want bool
	}{
		{"/gibson.harness.v1.HarnessCallbackService/QueryPlugin", true},
		{"/gibson.component.v1.ComponentService/QueryPlugin", false},
		{"/gibson.daemon.v1.DaemonService/QueryPlugin", false},
		{"/gibson.component.v1.ComponentService/CallTool", true},
		{"/gibson.harness.v1.HarnessCallbackService/CallTool", false},
		{"/gibson.unknown.v1.UnknownService/QueryPlugin", false},
	} {
		if got := hasHandlerTest(tc.rpc, tests, services); got != tc.want {
			t.Errorf("hasHandlerTest(%s) = %v, want %v", tc.rpc, got, tc.want)
		}
	}
}

// A package implements a service when a struct of a non-test file embeds
// Unimplemented<Service>Server, with a package qualifier or a pointer or none.
func TestEmbeddedServices(t *testing.T) {
	const src = `package p

type A struct {
	pb.UnimplementedComponentServiceServer
	name string
}

type B struct {
	*pb.UnimplementedDaemonServiceServer
	UnimplementedPlainServer
	pb.Other
	Unimplemented pb.X
}
`
	f, err := parser.ParseFile(token.NewFileSet(), "p.go", src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	got := embeddedServices(f)
	sort.Strings(got)
	if strings.Join(got, ",") != "ComponentService,DaemonService,Plain" {
		t.Errorf("embeddedServices = %v", got)
	}
}

// baselineEntries returns the RPC lines of the text of a baseline file.
func baselineEntries(text string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = struct{}{}
	}
	return out
}

// baselineGrowth returns the entries of head that base does not hold, sorted.
// The baseline may only shrink, so a head with any such entry fails. A swap of
// one entry for another keeps the count and still fails.
func baselineGrowth(base, head map[string]struct{}) []string {
	var added []string
	for entry := range head {
		if _, ok := base[entry]; !ok {
			added = append(added, entry)
		}
	}
	sort.Strings(added)
	return added
}

// TestEveryRegisteredRPCBaselineNeverGrows is the ratchet of the baseline. The
// baseline lists the RPCs with no handler test and may only shrink, but nothing
// stopped a pull request from regenerating it and adding lines. This test reads
// the baseline of origin/main and fails when the baseline of the branch holds an
// entry that main does not.
//
// The walker job sets RPC_BASELINE_REQUIRE=1 after it fetched main. In that job
// a base that cannot be read fails the test, so the guard never skips there. In
// another lane, or on a machine with no origin/main, the test skips.
func TestEveryRegisteredRPCBaselineNeverGrows(t *testing.T) {
	root := repoRoot(t)
	rel := "internal/platform/authz/registry/" + baselineFileName
	out, err := exec.Command("git", "-C", root, "show", "origin/main:"+rel).Output() //nolint:gosec // fixed arguments, a constant path under the module root
	if err != nil {
		if os.Getenv("RPC_BASELINE_REQUIRE") == "1" {
			t.Fatalf("the baseline of origin/main could not be read (%v). The walker job must fetch main first", err)
		}
		t.Skipf("no origin/main to compare with (%v); the walker job requires it", err)
	}
	head, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // a constant path under the module root
	if err != nil {
		t.Fatalf("reading %s: %v", rel, err)
	}
	if added := baselineGrowth(baselineEntries(string(out)), baselineEntries(string(head))); len(added) > 0 {
		t.Errorf("the baseline holds %d entr(y/ies) that origin/main does not. The baseline may only shrink: write the handler test instead of adding the line.\n  %s",
			len(added), strings.Join(added, "\n  "))
	}
}

// The failing fixture of the ratchet: growth fails, a swap fails, a shrink and
// no change pass.
func TestBaselineGrowth_Fixture(t *testing.T) {
	base := baselineEntries("# header\n/a.v1.S/M1\n/a.v1.S/M2\n")
	for name, tc := range map[string]struct {
		head string
		want []string
	}{
		"no change":   {"/a.v1.S/M1\n/a.v1.S/M2\n", nil},
		"a shrink":    {"/a.v1.S/M1\n", nil},
		"a new entry": {"/a.v1.S/M1\n/a.v1.S/M2\n/a.v1.S/M3\n", []string{"/a.v1.S/M3"}},
		"a swap":      {"/a.v1.S/M1\n/a.v1.S/M9\n", []string{"/a.v1.S/M9"}},
		"comments":    {"# changed header\n\n/a.v1.S/M1\n", nil},
	} {
		got := baselineGrowth(base, baselineEntries(tc.head))
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: growth = %v, want %v", name, got, tc.want)
		}
	}
}
