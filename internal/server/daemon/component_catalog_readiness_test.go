// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/supplychain"
)

// TestRegistryCredentialDir_DefaultsToTheProjectedMount pins where the daemon
// reads the credential the chart projects.
func TestRegistryCredentialDir_DefaultsToTheProjectedMount(t *testing.T) {
	t.Setenv("GIBSON_REGISTRY_CREDENTIAL_DIR", "")
	if got := registryAuthDir(); got != defaultRegistryAuthDir {
		t.Errorf("registryAuthDir() = %q, want %q", got, defaultRegistryAuthDir)
	}
	t.Setenv("GIBSON_REGISTRY_CREDENTIAL_DIR", "/somewhere/else")
	if got := registryAuthDir(); got != "/somewhere/else" {
		t.Errorf("registryAuthDir() = %q, want the override", got)
	}
}

// TestComponentImageVerifier_CarriesTheCredentialDir is the regression guard
// for gibson#1744: a refactor must not drop the credential on the floor.
func TestComponentImageVerifier_CarriesTheCredentialDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GIBSON_REGISTRY_CREDENTIAL_DIR", dir)
	if err := os.WriteFile(filepath.Join(dir, supplychain.DockerConfigFileName),
		[]byte(`{"auths":{"ghcr.io":{"username":"u","password":"p"}}}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	v := componentImageVerifier()
	sv, ok := v.(*supplychain.SigstoreVerifier)
	if !ok {
		t.Fatalf("verifier is %T, want a SigstoreVerifier", v)
	}
	auth, err := sv.RegistryCredentialFor("ghcr.io")
	if err != nil {
		t.Fatalf("resolve the credential: %v", err)
	}
	if auth.Username != "u" || auth.Password != "p" {
		t.Errorf("resolved %+v, want the mounted credential", auth)
	}
}

// TestComponentCatalogGateState_EveryImageVerifiedIsHealthy is the good state.
func TestComponentCatalogGateState_EveryImageVerifiedIsHealthy(t *testing.T) {
	s := newComponentCatalogGateState("/etc/gibson/registry-credential/config.json")
	got := s.status()
	if !got.IsHealthy() {
		t.Errorf("status = %+v, want healthy", got)
	}
}

// TestComponentCatalogGateState_AMountedCredentialThatStillRefusesIsDegraded:
// the token is wrong or the images are unsigned, and an operator must see it
// outside the log.
func TestComponentCatalogGateState_AMountedCredentialThatStillRefusesIsDegraded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, supplychain.DockerConfigFileName)
	if err := os.WriteFile(path, []byte(`{"auths":{}}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	s := newComponentCatalogGateState(path)
	s.recordRefusal(errors.New("cve-triage not offered"))

	got := s.status()
	if !got.IsDegraded() {
		t.Fatalf("status = %+v, want degraded", got)
	}
	if !strings.Contains(got.Message, path) {
		t.Errorf("message = %q, want the credential path named", got.Message)
	}
}

// TestComponentCatalogGateState_NoCredentialNamesTheMissingMount: the daemon
// stays in service, and the message tells an operator what to mount.
func TestComponentCatalogGateState_NoCredentialNamesTheMissingMount(t *testing.T) {
	path := filepath.Join(t.TempDir(), supplychain.DockerConfigFileName)
	s := newComponentCatalogGateState(path)
	s.recordRefusal(errors.New("cve-triage not offered"))

	got := s.status()
	if got.IsDegraded() {
		t.Fatal("a missing mount must not take every daemon out of service")
	}
	if !strings.Contains(got.Message, path) || !strings.Contains(got.Message, "cve-triage") {
		t.Errorf("message = %q, want the missing mount and the refusal", got.Message)
	}
}
