// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package checks

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenImportsOf returns the forbidden Kubernetes imports of one file.
func forbiddenImportsOf(t *testing.T, path string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		for _, forbidden := range forbiddenK8sImportPrefixes {
			if strings.HasPrefix(p, forbidden) {
				out = append(out, p)
			}
		}
	}
	return out
}

// TestNoK8sAPIInDaemon_ExemptionsAreLive keeps the exemption list honest. An
// entry is a file that still breaks ADR-0023 and waits for its issue. An
// entry whose file is gone, or that no longer imports a forbidden package,
// exempts nothing and must be deleted. So the list only shrinks.
func TestNoK8sAPIInDaemon_ExemptionsAreLive(t *testing.T) {
	// tools/gibsoncheck/checks -> repository root.
	root := filepath.Join("..", "..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found from the test directory: %v", err)
	}
	seen := map[string]bool{}
	for _, rel := range noK8sAPIInDaemonExemptFiles {
		if seen[rel] {
			t.Errorf("%s is on the exemption list twice", rel)
		}
		seen[rel] = true
		if !strings.HasPrefix(rel, "internal/") && !strings.HasPrefix(rel, "pkg/") {
			t.Errorf("%s is outside internal/ and pkg/, which the analyzer does not check: delete the entry", rel)
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(rel))
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s is exempt and does not exist: delete the entry", rel)
			continue
		}
		if len(forbiddenImportsOf(t, path)) == 0 {
			t.Errorf("%s is exempt and imports no forbidden Kubernetes package: delete the entry", rel)
		}
	}
}

// TestNoK8sAPIInDaemon_StaleExemptionIsCaught is the failing fixture of the
// check above: a file with no forbidden import is recognized as one, and a
// file with a forbidden import is recognized as the other.
func TestNoK8sAPIInDaemon_StaleExemptionIsCaught(t *testing.T) {
	dir := t.TempDir()
	clean := filepath.Join(dir, "clean.go")
	dirty := filepath.Join(dir, "dirty.go")
	if err := os.WriteFile(clean, []byte("package x\n\nimport _ \"k8s.io/api/core/v1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dirty, []byte("package x\n\nimport _ \"k8s.io/client-go/dynamic\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := forbiddenImportsOf(t, clean); len(got) != 0 {
		t.Errorf("a type-only import was read as forbidden: %v", got)
	}
	if got := forbiddenImportsOf(t, dirty); len(got) != 1 || got[0] != "k8s.io/client-go/dynamic" {
		t.Errorf("a client import was not read as forbidden: %v", got)
	}
}
