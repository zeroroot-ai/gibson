/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package flows

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// TestConfigureSecretsJWTAuthStep_Provision_Success verifies the saga
// step invokes the vault client's ConfigureTenantJWTAuth with the
// tenant ID and returns done=true on success. tenant-operator#189.
func TestConfigureSecretsJWTAuthStep_Provision_Success(t *testing.T) {
	t.Parallel()
	stub := &stubVaultAdmin{}
	deps := ProvisionDeps{Vault: stub}
	step := newConfigureSecretsJWTAuthStep(deps)
	tenant := newTestTenant("abcd")

	done, err := step.Provision(context.Background(), tenant, &saga.Deps{})
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !done {
		t.Errorf("done = false, want true")
	}
	if len(stub.jwtAuthConfigCalls) != 1 || stub.jwtAuthConfigCalls[0] != "abcd" {
		t.Errorf("ConfigureTenantJWTAuth calls = %v, want [abcd]", stub.jwtAuthConfigCalls)
	}
}

// TestConfigureSecretsJWTAuthStep_Idempotent verifies that re-running the
// step on the same tenant (the operator's reconcile loop fires the step
// repeatedly) doesn't produce a different outcome. The underlying vault
// write is itself idempotent (POST to auth/jwt/config is an overwrite),
// so the step's contract is: every call returns done=true with no error.
func TestConfigureSecretsJWTAuthStep_Idempotent(t *testing.T) {
	t.Parallel()
	stub := &stubVaultAdmin{}
	deps := ProvisionDeps{Vault: stub}
	step := newConfigureSecretsJWTAuthStep(deps)
	tenant := newTestTenant("abcd")

	for i := range 3 {
		done, err := step.Provision(context.Background(), tenant, &saga.Deps{})
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if !done {
			t.Errorf("call %d done = false, want true", i)
		}
	}
	if got := len(stub.jwtAuthConfigCalls); got != 3 {
		t.Errorf("ConfigureTenantJWTAuth call count = %d, want 3", got)
	}
}

// TestConfigureSecretsJWTAuthStep_PermanentErrorClassified verifies that
// an ErrInvalidInput from the vault client (the "missing JWTBoundIssuer"
// shape) gets wrapped as permanent so the saga runner stops retrying
// and surfaces SECRETS_NAMESPACE_FAILED to the dashboard immediately,
// rather than burning retries on a wiring bug.
func TestConfigureSecretsJWTAuthStep_PermanentErrorClassified(t *testing.T) {
	t.Parallel()
	stub := &stubVaultAdmin{jwtAuthConfigErr: clients.ErrInvalidInput}
	deps := ProvisionDeps{Vault: stub}
	step := newConfigureSecretsJWTAuthStep(deps)
	tenant := newTestTenant("abcd")

	done, err := step.Provision(context.Background(), tenant, &saga.Deps{})
	if done {
		t.Errorf("done = true on error, want false")
	}
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, clients.ErrInvalidInput) {
		t.Errorf("expected ErrInvalidInput wrapped, got %v", err)
	}
	if !clients.IsPermanent(err) {
		t.Errorf("expected permanent classification, got transient")
	}
}

// TestConfigureSecretsJWTAuthStep_RequiresProvisionSecretsBackend locks
// the step-dependency graph: ConfigureSecretsJWTAuth must run AFTER
// ProvisionSecretsBackend (the namespace + jwt mount + role must exist
// before the config write can land).
func TestConfigureSecretsJWTAuthStep_RequiresProvisionSecretsBackend(t *testing.T) {
	t.Parallel()
	step := newConfigureSecretsJWTAuthStep(ProvisionDeps{})
	got := step.Requires()
	if len(got) != 1 || got[0] != "ProvisionSecretsBackend" {
		t.Errorf("Requires = %v, want [ProvisionSecretsBackend]", got)
	}
}
