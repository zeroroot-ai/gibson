// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCertPEM = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUZ+B8zj5w2q0Y9wY8yQ2n8Q5w1kEwCgYIKoZIzj0EAwIw\nEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAw\nMDBaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\nAAQ=\n-----END CERTIFICATE-----\n"

func TestPlatformCAPEM(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	t.Run("a present certificate is handed over", func(t *testing.T) {
		p := filepath.Join(dir, "ca.crt")
		if err := os.WriteFile(p, []byte(testCertPEM), 0o600); err != nil { //nolint:gosec // t.TempDir() path
			t.Fatal(err)
		}
		if got := platformCAPEM(p, logger); got != testCertPEM {
			t.Fatalf("got %q, want the file's PEM", got)
		}
	})
	t.Run("a missing file is the public-roots case", func(t *testing.T) {
		buf.Reset()
		if got := platformCAPEM(filepath.Join(dir, "absent.crt"), logger); got != "" {
			t.Fatalf("got %q, want nothing", got)
		}
		if buf.Len() != 0 {
			t.Fatalf("a missing file must not warn: %s", buf.String())
		}
	})
	t.Run("an empty path hands nothing over", func(t *testing.T) {
		if got := platformCAPEM("", logger); got != "" {
			t.Fatalf("got %q, want nothing", got)
		}
	})
	t.Run("a file with no certificate is reported and treated as absent", func(t *testing.T) {
		buf.Reset()
		p := filepath.Join(dir, "key.pem")
		if err := os.WriteFile(p, []byte("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"), 0o600); err != nil { //nolint:gosec // t.TempDir() path
			t.Fatal(err)
		}
		if got := platformCAPEM(p, logger); got != "" {
			t.Fatalf("got %q, want nothing", got)
		}
		if !strings.Contains(buf.String(), "no platform CA") {
			t.Fatalf("a bad file must be reported, got: %s", buf.String())
		}
	})
	t.Run("an unreadable file is reported and treated as absent", func(t *testing.T) {
		buf.Reset()
		if got := platformCAPEM(dir, logger); got != "" { // a directory: read fails, not ErrNotExist
			t.Fatalf("got %q, want nothing", got)
		}
		if !strings.Contains(buf.String(), "unreadable") {
			t.Fatalf("an unreadable file must be reported, got: %s", buf.String())
		}
	})
}
