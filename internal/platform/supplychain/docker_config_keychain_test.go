// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package supplychain

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

func authFor(t *testing.T, k authn.Keychain, host string) authn.AuthConfig {
	t.Helper()
	reg, err := name.NewRegistry(host)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	a, err := k.Resolve(reg)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	cfg, err := a.Authorization()
	if err != nil {
		t.Fatalf("Authorization: %v", err)
	}
	return *cfg
}

// A tenant secret holds a docker config. Its credential goes to the registry
// that it names and to no other registry.
func TestNewDockerConfigKeychain_SendsTheCredentialOnlyToItsRegistry(t *testing.T) {
	k := NewDockerConfigKeychain([]byte(`{"auths":{"reg.example":{"username":"u","password":"p"}}}`), "secret x")
	if got := authFor(t, k, "reg.example"); got.Username != "u" || got.Password != "p" {
		t.Errorf("credential for reg.example = %+v", got)
	}
	if got := authFor(t, k, "other.example"); got.Username != "" || got.Password != "" {
		t.Errorf("credential for another registry = %+v, want anonymous", got)
	}
}

func TestNewDockerConfigKeychain_RefusesABadConfig(t *testing.T) {
	k := NewDockerConfigKeychain([]byte(`not json`), "secret x")
	reg, _ := name.NewRegistry("reg.example")
	if _, err := k.Resolve(reg); err == nil {
		t.Fatal("a secret that is not a docker config must be an error")
	}
}
