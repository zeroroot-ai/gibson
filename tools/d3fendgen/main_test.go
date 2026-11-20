// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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
