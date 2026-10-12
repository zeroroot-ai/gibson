// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

// TestNamesInSource_RealReads proves each read form is found: a direct
// read, a constant, a helper that passes its parameter on (cmd/ext-authz
// reads seven names through durationOr and intOr), a getenv parameter, a
// closure, a loop over a list, a struct field and a struct tag.
func TestNamesInSource_RealReads(t *testing.T) {
	src := "package main\n" +
		"import (\n\t\"os\"\n\t\"strings\"\n)\n" +
		"const EnvConst = \"CONST_NAME\"\n" +
		"type cfg struct {\n\tAddr string `env:\"TAG_ADDR\" envDefault:\"x\"`\n}\n" +
		"type knob struct{ configKnob string }\n" +
		"var k = knob{configKnob: \"FIELD_KNOB\"}\n" +
		"var pkgLevel = os.Getenv(\"PACKAGE_LEVEL\")\n" +
		"func envOr(key, def string) string { if v := os.Getenv(key); v != \"\" { return v }; return def }\n" +
		"func durationOr(key string, d int) int { _ = envOr(key, \"\"); return d }\n" +
		"func fromEnv(getenv func(string) string) string { return getenv(\"GETENV_PARAM\") }\n" +
		"func f() {\n" +
		"\t_ = os.Getenv(\"PLAIN_GETENV\")\n" +
		"\t_, _ = os.LookupEnv(\"LOOKUP_ENV\")\n" +
		"\t_ = os.Getenv(EnvConst)\n" +
		"\t_ = os.Getenv(k.configKnob)\n" +
		"\t_ = strings.TrimSpace(os.Getenv(\"TRIMMED\"))\n" +
		"\t_ = durationOr(\"EXT_AUTHZ_TIMEOUT\", 0)\n" +
		"\tget := func(name string) string { return os.Getenv(name) }\n" +
		"\t_ = get(\"CLOSURE_READ\")\n" +
		"\tfor _, name := range []string{\"LIST_A\", EnvConst} { _ = os.Getenv(name) }\n" +
		"\t_ = fromEnv(os.Getenv)\n" +
		"}\n"
	want := []string{
		"CLOSURE_READ", "CONST_NAME", "EXT_AUTHZ_TIMEOUT", "FIELD_KNOB", "GETENV_PARAM", "LIST_A",
		"LOOKUP_ENV", "PACKAGE_LEVEL", "PLAIN_GETENV", "TAG_ADDR", "TRIMMED",
	}
	if got := names(src); !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %v\nwant    %v", got, want)
	}
}

// TestNamesInSource_NotARead is the failing fixture of gibson#1128: a name
// that no env read reaches is not a reader. gibson#1125 used time.RFC1123Z
// in a Date header, and the guard listed RFC1123Z as an env var. An error
// code, a child-process env entry, a Kubernetes EnvVar and a method call
// with a string argument are not reads either.
func TestNamesInSource_NotARead(t *testing.T) {
	src := "package x\n" +
		"import (\n\t\"errors\"\n\t\"os\"\n\t\"time\"\n)\n" +
		"type store struct{}\n" +
		"func (store) get(key string) string { return os.Getenv(key) }\n" +
		"func f(s store, env []string) {\n" +
		"\t_ = time.Now().Format(time.RFC1123Z)\n" +
		"\t_ = errors.New(\"WORKSPACE_NAME_TAKEN\")\n" +
		"\t_ = append(env, \"CHILD_FLAG=1\")\n" +
		"\t_ = []struct{ Name, Value string }{{Name: \"POD_ENV\", Value: \"x\"}}\n" +
		"\t_ = `RAW_NAME`\n" +
		"\t_ = s.get(\"METHOD_ARG\")\n" +
		"\t_ = os.Getenv(\"REAL_READ\")\n" +
		"}\n"
	if got := names(src); !reflect.DeepEqual(got, []string{"REAL_READ"}) {
		t.Fatalf("names = %v, want [REAL_READ]", got)
	}
}

// TestNamesInSource_ACommentIsNotAReader proves a name that only a comment
// holds stays out. LOKI_URL survived one audit of the chart that way.
func TestNamesInSource_ACommentIsNotAReader(t *testing.T) {
	src := "package x\nimport \"os\"\n// os.Getenv(\"LOKI_URL\") was removed.\n/* os.Getenv(\"BLOCK_NAME\") */\nfunc f() { _ = os.Getenv(\"lower_case\"); _ = os.Getenv(\"xUPPER_INSIDEy\") }\n"
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
		"cmd/svc/main.go":          "package main\nimport \"os\"\nvar _ = os.Getenv(\"LIVE_NAME\")\n",
		"cmd/svc/main_test.go":     "package main\nimport \"os\"\nvar _ = os.Getenv(\"TEST_ONLY_NAME\")\n",
		"cmd/svc/testdata/x.go":    "package x\nimport \"os\"\nvar _ = os.Getenv(\"TESTDATA_NAME\")\n",
		"vendor/dep/dep.go":        "package dep\nimport \"os\"\nvar _ = os.Getenv(\"VENDORED_NAME\")\n",
		"operators/op/cmd/main.go": "package main\nimport \"os\"\nvar _ = os.Getenv(\"OPERATOR_NAME\")\n",
	})
	if err := os.WriteFile(filepath.Join(dir, "untracked.go"), []byte("package x\nimport \"os\"\nvar _ = os.Getenv(\"UNTRACKED_NAME\")\n"), 0o600); err != nil {
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
	dir := repo(t, 0, map[string]string{"main.go": "package main\nimport \"os\"\nvar _ = os.Getenv(\"ONE_NAME\")\n"})
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

// command runs the whole command on dir with floors of one.
func command(dir string, mode ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = runWithFloors(append([]string{"-dir", dir}, mode...), &out, &errOut, 1, 1)
	return code, out.String(), errOut.String()
}

func gitAdd(t *testing.T, dir string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "add", "-A") //nolint:gosec // G204: fixed argv on a temp dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
}

// TestCommand_WriteThenCheckThenDrift runs the command the way make does:
// write gives a file that check accepts, a new reader makes check fail and
// name it, and a dropped reader makes check fail and name it.
func TestCommand_WriteThenCheckThenDrift(t *testing.T) {
	dir := repo(t, 0, map[string]string{"cmd/svc/main.go": "package main\nimport \"os\"\nvar _ = os.Getenv(\"FIRST_NAME\")\n"})

	if code, _, stderr := command(dir, "-check"); code != 1 || !strings.Contains(stderr, Artifact+" is missing") {
		t.Fatalf("check with no file: exit %d, stderr %q", code, stderr)
	}
	if code, stdout, stderr := command(dir, "-write"); code != 0 || !strings.Contains(stdout, "(1 names)") {
		t.Fatalf("write: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if code, stdout, stderr := command(dir, "-check"); code != 0 || !strings.Contains(stdout, "matches the source") {
		t.Fatalf("check after write: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}

	added := filepath.Join(dir, "cmd", "svc", "more.go")
	if err := os.WriteFile(added, []byte("package main\nimport \"os\"\nvar _ = os.Getenv(\"SECOND_NAME\")\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitAdd(t, dir)
	code, _, stderr := command(dir, "-check")
	if code != 1 || !strings.Contains(stderr, "the source reads SECOND_NAME") || !strings.Contains(stderr, "is stale") {
		t.Fatalf("check after a new reader: exit %d, stderr %q", code, stderr)
	}

	if code, _, stderr := command(dir, "-write"); code != 0 {
		t.Fatalf("second write: exit %d, stderr %q", code, stderr)
	}
	if err := os.Remove(added); err != nil {
		t.Fatal(err)
	}
	gitAdd(t, dir)
	code, _, stderr = command(dir, "-check")
	if code != 1 || !strings.Contains(stderr, "lists SECOND_NAME and the source no longer reads it") {
		t.Fatalf("check after a dropped reader: exit %d, stderr %q", code, stderr)
	}
}

// TestCommand_RefusesBadUse proves the command exits 2, and writes nothing,
// when the mode is unclear, a flag is unknown, the directory is not a git
// tree, or the scan is under a floor.
func TestCommand_RefusesBadUse(t *testing.T) {
	dir := repo(t, 0, map[string]string{"main.go": "package main\nimport \"os\"\nvar _ = os.Getenv(\"ONE_NAME\")\n"})
	for name, mode := range map[string][]string{
		"no mode":      nil,
		"both modes":   {"-write", "-check"},
		"unknown flag": {"-nope"},
	} {
		if code, _, _ := command(dir, mode...); code != 2 {
			t.Errorf("%s: exit %d, want 2", name, code)
		}
	}
	if code, _, stderr := command(t.TempDir(), "-check"); code != 2 || !strings.Contains(stderr, "git ls-files") {
		t.Errorf("not a git tree: exit %d, stderr %q", code, stderr)
	}
	var out, errOut bytes.Buffer
	if code := runWithFloors([]string{"-dir", dir, "-write"}, &out, &errOut, 200, 1); code != 2 || !strings.Contains(errOut.String(), "the floor is 200") {
		t.Errorf("under the floor: exit %d, stderr %q", code, errOut.String())
	}
	if _, err := os.Stat(filepath.Join(dir, Artifact)); err == nil {
		t.Error("a refused run wrote the artifact")
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
