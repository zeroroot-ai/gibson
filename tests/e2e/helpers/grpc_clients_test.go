// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build e2e
// +build e2e

package helpers

import (
	"os"
	"path/filepath"
	"testing"
)

// TestResolveSPIFFESocket is the gibson#14 fixture: a mounted socket
// directory that carries api.sock selects mTLS, a mounted directory with no
// socket is an error rather than a silent plaintext dial, the environment
// wins, and no mount at all is the one plaintext case.
func TestResolveSPIFFESocket(t *testing.T) {
	dir := t.TempDir()

	if got, err := resolveSPIFFESocket("unix:///elsewhere/x.sock", dir); err != nil || got != "unix:///elsewhere/x.sock" {
		t.Fatalf("env: got %q %v", got, err)
	}
	if _, err := resolveSPIFFESocket("", dir); err == nil {
		t.Fatal("a mounted directory with no socket must not fall back to plaintext")
	}
	if err := os.WriteFile(filepath.Join(dir, "api.sock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveSPIFFESocket("", dir); err != nil || got != "unix://"+filepath.Join(dir, "api.sock") {
		t.Fatalf("api.sock: got %q %v", got, err)
	}
	if got, err := resolveSPIFFESocket("", filepath.Join(dir, "absent")); err != nil || got != "" {
		t.Fatalf("no mount: got %q %v, want plaintext", got, err)
	}
}
