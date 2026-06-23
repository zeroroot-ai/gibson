package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mod = "github.com/zeroroot-ai/gibson"

func TestEvaluate_BelowThresholdFails(t *testing.T) {
	// file.go has statements on lines 10-12 (covered) and 20-22 (uncovered).
	profile := `mode: atomic
github.com/zeroroot-ai/gibson/internal/x/file.go:10.2,12.10 2 5
github.com/zeroroot-ai/gibson/internal/x/file.go:20.2,22.10 2 0
`
	// Diff adds one covered line (11) and two uncovered lines (21, 22) => 1/3 = 33%.
	diff := `diff --git a/internal/x/file.go b/internal/x/file.go
--- a/internal/x/file.go
+++ b/internal/x/file.go
@@ -10,0 +11 @@
+	covered := true
@@ -20,0 +21,2 @@
+	missed := 1
+	missed2 := 2
`
	r := evaluate([]byte(profile), []byte(diff), mod, 85)
	if r.Pass {
		t.Fatalf("expected FAIL, got pass; report:\n%s", r)
	}
	if r.Total != 3 || r.Covered != 1 {
		t.Fatalf("want total=3 covered=1, got total=%d covered=%d", r.Total, r.Covered)
	}
	if len(r.Missed) != 2 {
		t.Fatalf("want 2 missed, got %d: %v", len(r.Missed), r.Missed)
	}
}

func TestEvaluate_AboveThresholdPasses(t *testing.T) {
	profile := `mode: atomic
github.com/zeroroot-ai/gibson/internal/x/file.go:10.2,14.10 5 3
`
	diff := `+++ b/internal/x/file.go
@@ -9,0 +10,5 @@
+	a := 1
+	b := 2
+	c := 3
+	d := 4
+	e := 5
`
	r := evaluate([]byte(profile), []byte(diff), mod, 85)
	if !r.Pass {
		t.Fatalf("expected PASS, got fail; report:\n%s", r)
	}
	if r.Percent() != 100 {
		t.Fatalf("want 100%%, got %.1f", r.Percent())
	}
}

func TestEvaluate_NonStatementLinesIgnored(t *testing.T) {
	// Only line 10 is a statement; the diff also adds a comment (line 9) and a
	// blank (line 11) that fall outside any block and must be ignored.
	profile := `mode: atomic
github.com/zeroroot-ai/gibson/internal/x/file.go:10.2,10.20 1 1
`
	diff := `+++ b/internal/x/file.go
@@ -8,0 +9,3 @@
+	// a comment
+	stmt := compute()
+
`
	r := evaluate([]byte(profile), []byte(diff), mod, 85)
	if r.Total != 1 || r.Covered != 1 {
		t.Fatalf("want total=1 covered=1 (comment+blank ignored), got total=%d covered=%d", r.Total, r.Covered)
	}
	if !r.Pass {
		t.Fatalf("expected PASS")
	}
}

func TestEvaluate_NoChangedStatementsPasses(t *testing.T) {
	profile := "mode: atomic\n"
	// Only a test file changed — excluded entirely.
	diff := `+++ b/internal/x/file_test.go
@@ -0,0 +1,3 @@
+func TestFoo(t *testing.T) {
+	_ = 1
+}
`
	r := evaluate([]byte(profile), []byte(diff), mod, 85)
	if !r.Pass || r.Total != 0 {
		t.Fatalf("want pass with total=0, got pass=%v total=%d", r.Pass, r.Total)
	}
}

func TestEvaluate_GeneratedAndTestFilesExcluded(t *testing.T) {
	profile := `mode: atomic
github.com/zeroroot-ai/gibson/internal/x/thing.pb.go:5.2,7.10 2 0
github.com/zeroroot-ai/gibson/internal/platform/authz/registry/registry.go:5.2,7.10 2 0
`
	diff := `+++ b/internal/x/thing.pb.go
@@ -4,0 +5,3 @@
+	gen := 1
+	gen2 := 2
+	gen3 := 3
+++ b/internal/platform/authz/registry/registry.go
@@ -4,0 +5,3 @@
+	reg := 1
+	reg2 := 2
+	reg3 := 3
`
	r := evaluate([]byte(profile), []byte(diff), mod, 85)
	if r.Total != 0 || !r.Pass {
		t.Fatalf("generated files must be excluded; got total=%d pass=%v", r.Total, r.Pass)
	}
}

func TestParseAddedLines_DeletionsDoNotAdvance(t *testing.T) {
	diff := `+++ b/a.go
@@ -10,2 +10,1 @@
-old1
-old2
+new1
`
	got := parseAddedLines([]byte(diff))
	lines := got["a.go"]
	if len(lines) != 1 || lines[0] != 10 {
		t.Fatalf("want [10], got %v", lines)
	}
}

func TestIsExcludedFile(t *testing.T) {
	excluded := []string{
		"internal/x/f_test.go", "internal/x/f.pb.go", "internal/x/f_grpc.pb.go",
		"internal/x/mock_thing.go", "internal/x/thing_mock.go", "internal/x/f.gen.go",
		"api/zz_generated.deepcopy.go", "internal/platform/authz/registry/registry.go",
		"README.md",
	}
	for _, f := range excluded {
		if !isExcludedFile(f) {
			t.Errorf("%s should be excluded", f)
		}
	}
	for _, f := range []string{"internal/x/handler.go", "cmd/gibson/main.go"} {
		if isExcludedFile(f) {
			t.Errorf("%s should NOT be excluded", f)
		}
	}
}

func TestReportStringContainsMissed(t *testing.T) {
	r := &Report{Threshold: 85, Total: 2, Covered: 1, Missed: []string{"a.go:5"}, Pass: false}
	if !strings.Contains(r.String(), "a.go:5") {
		t.Fatalf("report should list missed line; got:\n%s", r)
	}
}

func TestReportStringPassBranch(t *testing.T) {
	r := &Report{Threshold: 85, Total: 4, Covered: 4, Pass: true}
	if !strings.Contains(r.String(), "PASS") {
		t.Fatalf("passing report should say PASS; got:\n%s", r)
	}
}

func TestModuleFromGoMod(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(p, []byte("module github.com/zeroroot-ai/gibson\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := moduleFromGoMod(p); got != "github.com/zeroroot-ai/gibson" {
		t.Fatalf("got %q", got)
	}
	if got := moduleFromGoMod(filepath.Join(dir, "missing.mod")); got != "" {
		t.Fatalf("missing go.mod should yield empty, got %q", got)
	}
}

// TestRun_PassWithRealGit exercises run()'s full path — flag parsing, profile
// read, moduleFromGoMod, gitDiff (real git, base=HEAD ⇒ empty diff), evaluate,
// and output — without needing a synthetic git history. base HEAD diffed
// against HEAD yields no changed lines, so the gate passes.
func TestRun_PassWithRealGit(t *testing.T) {
	dir := t.TempDir()
	prof := filepath.Join(dir, "coverage.out")
	if err := os.WriteFile(prof, []byte("mode: atomic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"-profile", prof, "-base", "HEAD", "-threshold", "85"}, &out, &errb)
	if code != 0 {
		t.Fatalf("want exit 0, got %d; stderr=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "no changed statement lines") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}

func TestRun_MissingProfileReturns2(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"-profile", "/no/such/profile.out"}, &out, &errb)
	if code != 2 {
		t.Fatalf("want exit 2, got %d", code)
	}
	if !strings.Contains(errb.String(), "reading profile") {
		t.Fatalf("want profile-read error, got: %s", errb.String())
	}
}

func TestRun_BadFlagReturns2(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"-nonexistent-flag"}, &out, &errb); code != 2 {
		t.Fatalf("want exit 2 on bad flag, got %d", code)
	}
}

func TestRun_BadBaseRefReturns2(t *testing.T) {
	dir := t.TempDir()
	prof := filepath.Join(dir, "coverage.out")
	if err := os.WriteFile(prof, []byte("mode: atomic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"-profile", prof, "-base", "this-ref-does-not-exist-xyz"}, &out, &errb)
	if code != 2 {
		t.Fatalf("want exit 2 on bad base ref, got %d; stderr=%s", code, errb.String())
	}
}
