package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func names(src string) []string {
	found := NamesInSource("x.go", []byte(src))
	out := make([]string, 0, len(found))
	for n := range found {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// TestNamesInSource_OverApproximates proves the scan needs no list of
// helpers: a name reaches the set through any function, a struct tag, a
// "NAME=value" literal, a raw string or a selector. The measured failure was
// cmd/ext-authz, where seven names went through durationOr and intOr.
func TestNamesInSource_OverApproximates(t *testing.T) {
	src := "package x\n" +
		"type cfg struct {\n\tAddr string `env:\"TAG_ADDR\" envDefault:\"x\"`\n}\n" +
		"func f() {\n" +
		"\t_ = os.Getenv(\"PLAIN_GETENV\")\n" +
		"\t_ = durationOr(\"EXT_AUTHZ_TIMEOUT\", 0)\n" +
		"\t_ = intOr(\"EXT_AUTHZ_MAX\", 1)\n" +
		"\t_ = append(env, \"CHILD_FLAG=1\")\n" +
		"\t_ = `RAW_NAME`\n" +
		"\t_ = keys.SELECTOR_NAME\n" +
		"}\n"
	want := []string{"CHILD_FLAG", "EXT_AUTHZ_MAX", "EXT_AUTHZ_TIMEOUT", "PLAIN_GETENV", "RAW_NAME", "SELECTOR_NAME", "TAG_ADDR"}
	if got := names(src); !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %v\nwant    %v", got, want)
	}
}

// TestNamesInSource_ACommentIsNotAReader proves a name that only a comment
// holds stays out. LOKI_URL survived one audit of the chart that way.
func TestNamesInSource_ACommentIsNotAReader(t *testing.T) {
	src := "package x\n// os.Getenv(\"LOKI_URL\") was removed.\n/* \"BLOCK_NAME\" */\nfunc f() { _ = \"lower_case\"; _ = \"AB\"; _ = \"xUPPER_INSIDEy\" }\n"
	if got := names(src); len(got) != 0 {
		t.Fatalf("names = %v, want none", got)
	}
}

// repo builds a git repository with n filler files plus the given files.
func repo(t *testing.T, filler int, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := range filler {
		write(filepath.Join("pkg", "f"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+".go"), "package pkg\n")
	}
	for rel, body := range files {
		write(rel, body)
	}
	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}} {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...) //nolint:gosec // G204: fixed argv on a temp dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	return dir
}

// TestScan_ReadsTrackedSourceOnly proves a test file, test data, vendored
// code and an untracked file do not contribute a name.
func TestScan_ReadsTrackedSourceOnly(t *testing.T) {
	dir := repo(t, 0, map[string]string{
		"cmd/svc/main.go":          "package main\nvar _ = \"LIVE_NAME\"\n",
		"cmd/svc/main_test.go":     "package main\nvar _ = \"TEST_ONLY_NAME\"\n",
		"cmd/svc/testdata/x.go":    "package x\nvar _ = \"TESTDATA_NAME\"\n",
		"vendor/dep/dep.go":        "package dep\nvar _ = \"VENDORED_NAME\"\n",
		"operators/op/cmd/main.go": "package main\nvar _ = \"OPERATOR_NAME\"\n",
	})
	if err := os.WriteFile(filepath.Join(dir, "untracked.go"), []byte("package x\nvar _ = \"UNTRACKED_NAME\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Scan(dir, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"LIVE_NAME", "OPERATOR_NAME"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("scan = %v, want %v", got, want)
	}
}

// TestScan_RefusesASmallScan proves the floors: a tree that is not gibson
// fails, and does not write a short set.
func TestScan_RefusesASmallScan(t *testing.T) {
	dir := repo(t, 0, map[string]string{"main.go": "package main\nvar _ = \"ONE_NAME\"\n"})
	if _, err := Scan(dir, 200, 1); err == nil || !strings.Contains(err.Error(), "the floor is 200") {
		t.Fatalf("file floor: err = %v, want the file floor named", err)
	}
	if _, err := Scan(dir, 1, 100); err == nil || !strings.Contains(err.Error(), "the floor is 100") {
		t.Fatalf("name floor: err = %v, want the name floor named", err)
	}
}

// TestDrift_NamesEachDifference is the failing fixture of the gate: a set
// that lacks a name the source reads fails and names it, and a set that
// keeps a name the source dropped fails and names it.
func TestDrift_NamesEachDifference(t *testing.T) {
	missing, stale := Drift([]string{"KEPT", "GONE_FROM_SOURCE"}, []string{"KEPT", "NEW_IN_SOURCE"})
	if !reflect.DeepEqual(missing, []string{"NEW_IN_SOURCE"}) || !reflect.DeepEqual(stale, []string{"GONE_FROM_SOURCE"}) {
		t.Fatalf("missing=%v stale=%v", missing, stale)
	}
	if got := Parse(Render([]string{"A_B_C", "D_E_F"})); !reflect.DeepEqual(got, []string{"A_B_C", "D_E_F"}) {
		t.Fatalf("round trip = %v", got)
	}
}

// TestCommittedArtifactMatchesTheSource is the drift gate. It runs in the
// unit lane, so a change that adds or drops an env reader fails the merge
// gate until configs/env-readers.txt is refreshed.
func TestCommittedArtifactMatchesTheSource(t *testing.T) {
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("git rev-parse: %v", err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-dir", strings.TrimSpace(string(root)), "-check"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d\n%s", code, stderr.String())
	}
}
