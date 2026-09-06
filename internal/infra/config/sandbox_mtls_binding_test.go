// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// TestSandboxSetecMTLS_YAMLKeysBind is the regression test for the unbound
// mTLS files: the chart writes cert_file/key_file/ca_file/server_name under
// sandbox.setec.mtls, and the daemon must decode them (mapstructure tags).
// Before, only `enabled` bound and the daemon dialed setec with the system
// trust store and no client certificate.
func TestSandboxSetecMTLS_YAMLKeysBind(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewBufferString(`
sandbox:
  enabled: true
  setec:
    address: "setec-frontend.setec-system.svc.cluster.local:50051"
    tenant: "primary"
    mtls:
      enabled: true
      cert_file: "/etc/gibson-setec-mtls/tls.crt"
      key_file: "/etc/gibson-setec-mtls/tls.key"
      ca_file: "/etc/gibson-setec-mtls/ca.crt"
      server_name: "setec-frontend.setec-system.svc"
`)); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatal(err)
	}
	m := cfg.Sandbox.Setec.MTLS
	if !m.Enabled || m.CertFile != "/etc/gibson-setec-mtls/tls.crt" || m.KeyFile != "/etc/gibson-setec-mtls/tls.key" ||
		m.CAFile != "/etc/gibson-setec-mtls/ca.crt" || m.ServerName != "setec-frontend.setec-system.svc" {
		t.Fatalf("mtls did not bind from YAML: %+v", m)
	}
}

// TestValidator_RefusesASandboxWithoutItsMTLSFiles: the validator now runs
// SandboxConfig.Validate, so a daemon whose mTLS files are unbound or missing
// refuses to start instead of failing at the first dispatch.
func TestValidator_RefusesASandboxWithoutItsMTLSFiles(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("no base config")
	}
	cfg.Sandbox = SandboxConfig{Enabled: true, Setec: SandboxSetecConfig{Address: "setec:50051", Tenant: "primary"}}
	cfg.Sandbox.Setec.MTLS.Enabled = true
	// The section's own check refuses unbound files.
	if err := cfg.Sandbox.Validate(); err == nil || !strings.Contains(err.Error(), "sandbox.setec.mtls") {
		t.Fatalf("Sandbox.Validate: err = %v, want a sandbox.setec.mtls refusal", err)
	}
	// And the top-level validator now reaches it (was never called before).
	err := NewValidator().Validate(cfg)
	if err == nil || !strings.Contains(err.Error(), "sandbox.setec.mtls") {
		t.Fatalf("Validate: err = %v, want the sandbox.setec.mtls refusal surfaced", err)
	}
	dir := t.TempDir()
	for _, f := range []string{"tls.crt", "tls.key", "ca.crt"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg.Sandbox.Setec.MTLS.CertFile = filepath.Join(dir, "tls.crt")
	cfg.Sandbox.Setec.MTLS.KeyFile = filepath.Join(dir, "tls.key")
	cfg.Sandbox.Setec.MTLS.CAFile = filepath.Join(dir, "ca.crt")
	if err := NewValidator().Validate(cfg); err != nil && strings.Contains(err.Error(), "sandbox.setec.mtls") {
		t.Fatalf("with the files present the sandbox section must pass: %v", err)
	}
}
