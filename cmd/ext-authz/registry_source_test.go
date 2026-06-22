package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// loadRegistryBytes is exercised here only on the file-fallback and
// configuration-guard paths; the mTLS fetch path needs a live daemon and is
// covered by the integration suite.

func TestLoadRegistryBytes_FileFallback(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "registry.yaml")
	want := []byte("entries: {}\n")
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXT_AUTHZ_REGISTRY_URL", "") // force file path
	t.Setenv("EXT_AUTHZ_REGISTRY_PATH", path)

	got, src, err := loadRegistryBytes(context.Background(), slog.Default(), nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("bytes mismatch: got %q want %q", got, want)
	}
	if src != "file:"+path {
		t.Fatalf("source label: got %q", src)
	}
}

func TestLoadRegistryBytes_URLRequiresDaemonSVID(t *testing.T) {
	t.Setenv("EXT_AUTHZ_REGISTRY_URL", "https://gibson-daemon:8086/authz/registry.yaml")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", "") // missing → must error, never fall through unpinned

	_, _, err := loadRegistryBytes(context.Background(), slog.Default(), nil)
	if err == nil {
		t.Fatal("expected error when EXT_AUTHZ_REGISTRY_URL set but EXT_AUTHZ_DAEMON_SVID missing")
	}
}

func TestLoadRegistryBytes_URLRejectsUnparseableSVID(t *testing.T) {
	t.Setenv("EXT_AUTHZ_REGISTRY_URL", "https://gibson-daemon:8086/authz/registry.yaml")
	t.Setenv("EXT_AUTHZ_DAEMON_SVID", "not-a-spiffe-id")

	_, _, err := loadRegistryBytes(context.Background(), slog.Default(), nil)
	if err == nil {
		t.Fatal("expected error for unparseable EXT_AUTHZ_DAEMON_SVID")
	}
}
