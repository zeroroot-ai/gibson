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

// TestCommittedPackMatchesTheCatalog is the guard: the committed pack file
// is exactly the output of the generator over the pinned catalog.
func TestCommittedPackMatchesTheCatalog(t *testing.T) {
	root := repoRoot(t)
	generated, err := Generate(root)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Join(root, PackFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(committed, generated); err != nil {
		t.Fatal(err)
	}
}

// TestCheck_FailsOnAStaleFile is the failing fixture of the guard: a pack
// file with one changed title fails the check.
func TestCheck_FailsOnAStaleFile(t *testing.T) {
	generated, err := Generate(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	stale := bytes.Replace(generated, []byte(`"Account Management"`), []byte(`"Account Managment"`), 1)
	if bytes.Equal(stale, generated) {
		t.Fatal("fixture: the generated file has no title to change")
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

// fixtureCatalog has one family with an active control, a withdrawn
// control and an enhancement.
const fixtureCatalog = `{"catalog":{"groups":[{"id":"ac","title":"Access Control","controls":[
 {"id":"ac-1","title":" Policy and Procedures ","controls":[{"id":"ac-1.1","title":"Enhancement"}]},
 {"id":"ac-13","title":"Supervision and Review","props":[{"name":"status","value":"withdrawn"}]}
]}]}}`

func TestBuildPack_KeepsActiveBaseControlsOnly(t *testing.T) {
	raw := []byte(fixtureCatalog)
	cat, err := ReadCatalog(gzipBytes(t, raw), sha(raw))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := BuildPack(cat)
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.Controls) != 1 {
		t.Fatalf("controls = %+v, want only ac-1", pack.Controls)
	}
	c := pack.Controls[0]
	if c.ID != "ac-1" || c.Title != "Policy and Procedures" || c.Family != "ac" || c.FamilyTitle != "Access Control" {
		t.Fatalf("control = %+v", c)
	}
	if len(pack.MappingRules) != 0 {
		t.Fatal("the generator must write no mapping rule")
	}
}

func TestReadCatalog_RefusesAWrongChecksum(t *testing.T) {
	raw := []byte(fixtureCatalog)
	if _, err := ReadCatalog(gzipBytes(t, raw), sha([]byte("other"))); err == nil {
		t.Fatal("ReadCatalog accepted a catalog with a wrong SHA-256")
	}
}

func TestBuildPack_RefusesAnEmptyCatalog(t *testing.T) {
	raw := []byte(`{"catalog":{"groups":[]}}`)
	cat, err := ReadCatalog(gzipBytes(t, raw), sha(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildPack(cat); err == nil {
		t.Fatal("BuildPack accepted a catalog with no control")
	}
}
