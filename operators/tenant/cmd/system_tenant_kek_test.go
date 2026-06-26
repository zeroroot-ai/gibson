// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-logr/logr/testr"
)

// TestLoadSystemTenantKEK_FileMount_RawBytes covers the deploy#173
// case: the chart mounts the Helm Secret as a file containing 32 raw
// bytes (matching the daemon's k8s key_provider contract).
func TestLoadSystemTenantKEK_FileMount_RawBytes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master-key")
	want := bytes.Repeat([]byte{0xAB}, 32)
	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK_PATH", path)
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK", "")

	got := loadSystemTenantKEK(testr.New(t))
	if !bytes.Equal(got, want) {
		t.Errorf("KEK mismatch: got % x want % x", got, want)
	}
}

// Raw bytes WITH a trailing newline (ConfigMap-style) must still parse
// to the 32-byte KEK.
func TestLoadSystemTenantKEK_FileMount_RawBytesWithNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master-key")
	want := bytes.Repeat([]byte{0xCD}, 32)
	if err := os.WriteFile(path, append(want, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK_PATH", path)
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK", "")

	got := loadSystemTenantKEK(testr.New(t))
	if !bytes.Equal(got, want) {
		t.Errorf("KEK mismatch after newline trim: got % x want % x", got, want)
	}
}

// File contains 44 base64-encoded chars (32 raw bytes + 1 '=' pad).
// Should decode and return the underlying 32 bytes.
func TestLoadSystemTenantKEK_FileMount_Base64(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master-key")
	raw := bytes.Repeat([]byte{0xEF}, 32)
	encoded := base64.StdEncoding.EncodeToString(raw) // 44 chars including pad
	if len(encoded) != 44 {
		t.Fatalf("test setup: expected 44-char base64, got %d", len(encoded))
	}
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK_PATH", path)
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK", "")

	got := loadSystemTenantKEK(testr.New(t))
	if !bytes.Equal(got, raw) {
		t.Errorf("base64 decode mismatch: got % x want % x", got, raw)
	}
}

// File contains the wrong length — graceful no-op (nil, nil), operator
// continues with WriteTenantBrokerConfig saga step disabled.
func TestLoadSystemTenantKEK_FileMount_WrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master-key")
	if err := os.WriteFile(path, []byte("not32bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK_PATH", path)
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK", "")

	got := loadSystemTenantKEK(testr.New(t))
	if got != nil {
		t.Errorf("expected nil KEK on wrong-length file, got % x", got)
	}
}

// Path env set but file doesn't exist — graceful no-op (don't crash the
// operator pod, the saga step just stays disabled).
func TestLoadSystemTenantKEK_FileMount_Missing(t *testing.T) {
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK_PATH", "/tmp/this-path-does-not-exist-"+t.Name())
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK", "")

	got := loadSystemTenantKEK(testr.New(t))
	if got != nil {
		t.Errorf("expected nil KEK on missing file, got % x", got)
	}
}

// Legacy env-var path still works for overlays that haven't migrated to
// file mount (backward compat is the explicit deploy#173 contract).
func TestLoadSystemTenantKEK_EnvVar_Backcompat(t *testing.T) {
	raw := bytes.Repeat([]byte{0x12}, 32)
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK_PATH", "")
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK", base64.StdEncoding.EncodeToString(raw))

	got := loadSystemTenantKEK(testr.New(t))
	if !bytes.Equal(got, raw) {
		t.Errorf("env-var path mismatch: got % x want % x", got, raw)
	}
}

// Neither set — graceful no-op (the existing default behaviour).
func TestLoadSystemTenantKEK_BothUnset(t *testing.T) {
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK_PATH", "")
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK", "")

	got := loadSystemTenantKEK(testr.New(t))
	if got != nil {
		t.Errorf("expected nil KEK when both unset, got % x", got)
	}
}

// PATH takes precedence over env even when both are set — operators
// migrating from env to file should not be surprised.
func TestLoadSystemTenantKEK_PathWinsOverEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master-key")
	fileKEK := bytes.Repeat([]byte{0x55}, 32)
	if err := os.WriteFile(path, fileKEK, 0o600); err != nil {
		t.Fatal(err)
	}
	envKEK := bytes.Repeat([]byte{0xAA}, 32)
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK_PATH", path)
	t.Setenv("GIBSON_SYSTEM_TENANT_KEK", base64.StdEncoding.EncodeToString(envKEK))

	got := loadSystemTenantKEK(testr.New(t))
	if !bytes.Equal(got, fileKEK) {
		t.Errorf("file should win: got % x want % x", got, fileKEK)
	}
}
