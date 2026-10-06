// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package config

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// The chart writes the fleet SPIFFE ID under sandbox.setec.spiffe_id, and the
// daemon decodes it (ADR-0142, gibson#756).
func TestSandboxSetecSpiffeID_YAMLKeyBinds(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewBufferString(`
sandbox:
  setec:
    address: "setec-frontend.setec-system.svc.cluster.local:50051"
    spiffe_id: "spiffe://example.org/ns/setec-system/sa/setec-frontend"
`)); err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Sandbox.Setec.SpiffeID; got != "spiffe://example.org/ns/setec-system/sa/setec-frontend" {
		t.Fatalf("spiffe_id did not bind: %q", got)
	}
}

// With an address set, the validator refuses a missing or invalid fleet
// SPIFFE ID and accepts a valid one.
func TestValidator_RefusesASandboxWithoutTheFleetSpiffeID(t *testing.T) {
	cfg := DefaultConfig()
	for _, id := range []string{"", "not-a-spiffe-id", "https://example.org/setec"} {
		cfg.Sandbox = SandboxConfig{Setec: SandboxSetecConfig{Address: "setec:50051", SpiffeID: id}}
		err := NewValidator().Validate(cfg)
		if err == nil || !strings.Contains(err.Error(), "sandbox.setec.spiffe_id") {
			t.Errorf("spiffe_id %q: err = %v, want a sandbox.setec.spiffe_id refusal", id, err)
		}
	}
	cfg.Sandbox = SandboxConfig{Setec: SandboxSetecConfig{Address: "setec:50051", SpiffeID: "spiffe://example.org/ns/setec-system/sa/setec-frontend"}}
	if err := cfg.Sandbox.Validate(); err != nil {
		t.Errorf("a valid fleet SPIFFE ID was refused: %v", err)
	}
}
