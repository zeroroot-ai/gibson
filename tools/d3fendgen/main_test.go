// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is the repository root, two levels above this package.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestCommittedPackMatchesTheExtract is the guard: the committed pack file
// is exactly the output of the generator over the pinned extract.
func TestCommittedPackMatchesTheExtract(t *testing.T) {
	root := repoRoot(t)
	generated, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Clean(filepath.Join(root, PackFile)))
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(committed, generated); err != nil {
		t.Fatal(err)
	}
}

// TestCheck_FailsOnAStaleFile is the failing fixture of the guard: a pack
// file with one changed name fails the check.
func TestCheck_FailsOnAStaleFile(t *testing.T) {
	generated, err := Generate(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	stale := bytes.Replace(generated, []byte(`"File Analysis"`), []byte(`"File Analyses"`), 1)
	if bytes.Equal(stale, generated) {
		t.Fatal("fixture: the generated file has no name to change")
	}
	if err := Check(stale, generated); err == nil {
		t.Fatal("Check accepted a stale pack file")
	}
}

func gzipBytes(t *testing.T, raw []byte) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func sha(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

const fixtureExtract = `{"release":"9.9.9","release_date":"2026-01-01","license":"MIT",
"ontology_url":"https://d3fend.mitre.org/ontologies/d3fend.json","ontology_sha256":"abc",
"countermeasures":[
 {"id":"D3-FA","name":"File Analysis","tactic":"Detect","parent":"","counters":["T1059","T1059.001"],"nist_controls":["SI-3(10)"]},
 {"id":"D3-DA","name":"Dynamic Analysis","tactic":"Detect","parent":"D3-FA","counters":[]}
]}`

func TestBuildPack_FromAnExtract(t *testing.T) {
	raw := []byte(fixtureExtract)
	ex, err := ReadExtract(gzipBytes(t, raw), sha(raw))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := BuildPack(ex)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Countermeasures) != 2 || len(pack.Predicates) != 0 {
		t.Fatalf("pack = %+v", pack)
	}
	if pack.Source == nil || pack.Source.Release != "9.9.9" {
		t.Fatalf("source = %+v", pack.Source)
	}
}

func TestReadExtract_RefusesAWrongChecksum(t *testing.T) {
	raw := []byte(fixtureExtract)
	if _, err := ReadExtract(gzipBytes(t, raw), sha([]byte("other"))); err == nil {
		t.Fatal("ReadExtract accepted an extract with a wrong SHA-256")
	}
}

func TestBuildPack_RefusesAnEmptyExtract(t *testing.T) {
	raw := []byte(`{"release":"1","countermeasures":[]}`)
	ex, err := ReadExtract(gzipBytes(t, raw), sha(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPack(ex); err == nil {
		t.Fatal("BuildPack accepted an extract with no countermeasure")
	}
}

func TestBuildPack_MapsControlLabelsToPackIDs(t *testing.T) {
	raw := []byte(`{"release":"1","license":"MIT","ontology_url":"u","ontology_sha256":"abc","countermeasures":[
 {"id":"D3-EDL","name":"Executable Denylisting","tactic":"Isolate","counters":[],"nist_controls":["AC-17(8)","SC-3"]}]}`)
	ex, err := ReadExtract(gzipBytes(t, raw), sha(raw))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := BuildPack(ex)
	if err != nil {
		t.Fatal(err)
	}
	got := pack.Countermeasures[0].NISTControls
	if len(got) != 2 || got[0] != "ac-17.8" || got[1] != "sc-3" {
		t.Fatalf("controls = %v", got)
	}
}

// The command checks the committed pack, writes a pack into a copy of the
// tree, refuses a wrong flag set and fails on a tree with no extract.
func TestRun_ChecksWritesAndRefuses(t *testing.T) {
	root := repoRoot(t)
	var stderr bytes.Buffer
	if code := run([]string{"-dir", root, "-check"}, &stderr); code != 0 {
		t.Fatalf("check of the committed pack: code %d, %s", code, stderr.String())
	}
	if code := run([]string{"-dir", root}, &stderr); code != 2 {
		t.Errorf("no mode: code %d, want 2", code)
	}
	if code := run([]string{"-no-such-flag"}, &stderr); code != 2 {
		t.Errorf("a bad flag: code %d, want 2", code)
	}
	empty := t.TempDir()
	if code := run([]string{"-dir", empty, "-check"}, &stderr); code != 1 {
		t.Errorf("a tree with no extract: code %d, want 1", code)
	}

	// A copy of the tree with the extract and no pack: check fails, write
	// writes the pack, and the check then passes.
	tree := t.TempDir()
	raw, err := os.ReadFile(filepath.Clean(filepath.Join(root, ExtractFile)))
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{ExtractFile, PackFile} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(tree, rel)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Clean(filepath.Join(tree, ExtractFile)), raw, 0o600); err != nil { //nolint:gosec // G703: a path under t.TempDir and a constant
		t.Fatal(err)
	}
	if code := run([]string{"-dir", tree, "-check"}, &stderr); code != 1 {
		t.Errorf("a tree with no pack: code %d, want 1", code)
	}
	if code := run([]string{"-dir", tree, "-write"}, &stderr); code != 0 {
		t.Fatalf("write: code %d, %s", code, stderr.String())
	}
	if code := run([]string{"-dir", tree, "-check"}, &stderr); code != 0 {
		t.Errorf("check after the write: code %d, %s", code, stderr.String())
	}
	if err := os.WriteFile(filepath.Join(tree, PackFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"-dir", tree, "-check"}, &stderr); code != 1 {
		t.Errorf("a stale pack: code %d, want 1", code)
	}
}

// fetch.py runs on Linux, where env takes one argument unless -S splits it.
// Its distill step keeps only the D3 classes with a tactic, and a NIST
// control that maps to a class with no tactic is skipped, not a KeyError. The
// test runs that step with python3 -I on a small graph (review m22, r6).
func TestFetchScript_SkipsAClassWithNoTactic(t *testing.T) {
	raw, err := os.ReadFile("fetch.py")
	if err != nil {
		t.Fatalf("read fetch.py: %v", err)
	}
	if first, _, _ := strings.Cut(string(raw), "\n"); first != "#!/usr/bin/env -S python3 -I" {
		t.Fatalf("shebang = %q", first)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("python3 is required to test fetch.py: %v", err)
	}
	script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("fetch", sys.argv[1])
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)
graph = [
    {"@id": "d3f:Isolate", "rdfs:label": "Isolate"},
    {"@id": "_:r1", "@type": "owl:Restriction", "owl:onProperty": {"@id": "d3f:enables"},
     "owl:someValuesFrom": {"@id": "d3f:Isolate"}},
    {"@id": "d3f:NetIso", "d3f:d3fend-id": "D3-NI", "rdfs:label": "Network Isolation",
     "rdfs:subClassOf": [{"@id": "_:r1"}]},
    {"@id": "d3f:Model", "d3f:d3fend-id": "D3-ARMA", "rdfs:label": "A model"},
    {"@id": "d3f:NIST_SP_800-53_R5_SC-7", "d3f:control-name": "Boundary Protection", "rdfs:label": "SC-7",
     "d3f:broader": [{"@id": "d3f:NetIso"}, {"@id": "d3f:Model"}]},
]
print(json.dumps(fetch.distill(graph), sort_keys=True))
`
	out, err := exec.Command(python, "-I", "-c", script, "fetch.py").CombinedOutput() //nolint:gosec // G204: a fixed script and a file of this directory
	if err != nil {
		t.Fatalf("python3: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, `"D3-NI"`) || strings.Contains(text, `"D3-ARMA"`) || !strings.Contains(text, `"SC-7"`) {
		t.Fatalf("distill = %s, want D3-NI with SC-7 and no D3-ARMA", text)
	}
}
