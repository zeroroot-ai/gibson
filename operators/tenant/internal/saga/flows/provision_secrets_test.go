/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package flows

// Tests for the ProvisionSecretsBackend / DeprovisionSecretsBackend saga
// steps introduced for spec secrets-broker Requirement 10.3 Task 31.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// stubVaultAdmin records EnsureTenantNamespace / DeleteTenantNamespace calls.
type stubVaultAdmin struct {
	ensureCalls        []string
	deleteCalls        []string
	pingCalls          int
	ensureErr          error
	deleteErr          error
	edition            vaultadmin.Edition
	jwtAuthConfigCalls []string
	jwtAuthConfigErr   error
}

func (s *stubVaultAdmin) EnsureTenantNamespace(_ context.Context, tenantID string) (vaultadmin.Edition, error) {
	s.ensureCalls = append(s.ensureCalls, tenantID)
	if s.ensureErr != nil {
		return s.edition, s.ensureErr
	}
	return s.edition, nil
}

func (s *stubVaultAdmin) DeleteTenantNamespace(_ context.Context, tenantID string) error {
	s.deleteCalls = append(s.deleteCalls, tenantID)
	return s.deleteErr
}

func (s *stubVaultAdmin) Ping(_ context.Context) error {
	s.pingCalls++
	return nil
}

func (s *stubVaultAdmin) VerifyJWTAuthMounted(_ context.Context) error {
	return nil
}

// ConfigureTenantJWTAuth satisfies the AdminClient surface added in
// tenant-operator#189 (per-tenant auth/jwt/config writer). Tests that
// don't exercise the new saga step leave this as a no-op; the
// dedicated TestConfigureTenantJWTAuth_* tests live in the vault
// package and exercise the real httpClient against a fake.
func (s *stubVaultAdmin) ConfigureTenantJWTAuth(_ context.Context, tenantID string) error {
	s.jwtAuthConfigCalls = append(s.jwtAuthConfigCalls, tenantID)
	return s.jwtAuthConfigErr
}

// WriteInfraNeo4j satisfies the updated vaultadmin.AdminClient interface
// (added by spec per-tenant-data-plane-completion Task 19a).
func (s *stubVaultAdmin) WriteInfraNeo4j(_ context.Context, _, _, _ string) error {
	return nil
}

// DeleteInfraNeo4j satisfies the updated vaultadmin.AdminClient interface
// (added by spec per-tenant-data-plane-completion Task 19a).
func (s *stubVaultAdmin) DeleteInfraNeo4j(_ context.Context, _ string) error {
	return nil
}

// WriteInfraNeo4jCredentials satisfies the typed-payload form added in
// spec tenant-provisioning-unification-phase2 Phase 6.3.
func (s *stubVaultAdmin) WriteInfraNeo4jCredentials(_ context.Context, _ string, _ pdataplane.Neo4jCredentials) error {
	return nil
}

// Per-store credential writers added in spec
// tenant-provisioning-unification-phase2 Phase 2.4 — stubbed as no-ops
// here since tests below are only checking the namespace-provisioning
// path, not the per-store writes.
func (s *stubVaultAdmin) WriteInfraPostgres(_ context.Context, _ string, _ pdataplane.PostgresCredentials) error {
	return nil
}
func (s *stubVaultAdmin) DeleteInfraPostgres(_ context.Context, _ string) error { return nil }
func (s *stubVaultAdmin) WriteInfraRedis(_ context.Context, _ string, _ pdataplane.RedisCredentials) error {
	return nil
}
func (s *stubVaultAdmin) DeleteInfraRedis(_ context.Context, _ string) error { return nil }
func (s *stubVaultAdmin) WriteInfraVector(_ context.Context, _ string, _ pdataplane.VectorCredentials) error {
	return nil
}
func (s *stubVaultAdmin) DeleteInfraVector(_ context.Context, _ string) error { return nil }

func newTestTenant(name string) *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: gibsonv1alpha1.TenantSpec{
			Owner:       "owner@example.com",
			DisplayName: "Display " + name,
		},
		Status: gibsonv1alpha1.TenantStatus{
			Conditions: []metav1.Condition{},
		},
	}
}

// TestProvisionSecretsBackend_NilVaultPanics documents the one-code-path
// invariant (tenant-operator#197): the step assumes deps.Vault is non-nil.
// The operator exits 1 at startup when Vault wiring is missing
// (cmd/main.go:buildVaultAdminClient), so this code path is unreachable
// in any well-formed install. The previous "nil Vault is a no-op" test
// was deleted along with the graceful-nil branch.
func TestProvisionSecretsBackend_NilVaultPanics(t *testing.T) {
	t.Parallel()
	tenant := newTestTenant("nil-vault-panics")
	deps := ProvisionDeps{} // Vault: nil — only possible in tests.

	step := newProvisionSecretsBackendStep(deps)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil Vault (one-code-path: tenant-operator#197)")
		}
	}()
	_, _ = step.Provision(context.Background(), tenant, nil)
}

func TestProvisionSecretsBackend_CallsEnsureWithTenantID(t *testing.T) {
	t.Parallel()
	stub := &stubVaultAdmin{edition: vaultadmin.EditionEnterprise}
	deps := ProvisionDeps{Vault: stub}
	tenant := newTestTenant("happy-path")

	step := newProvisionSecretsBackendStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("provisionSecretsBackend: %v", err)
	}
	if !done {
		t.Fatal("expected done=true on success")
	}
	if len(stub.ensureCalls) != 1 || stub.ensureCalls[0] != "happy-path" {
		t.Fatalf("expected one EnsureTenantNamespace call with %q, got %v",
			"happy-path", stub.ensureCalls)
	}
}

func TestProvisionSecretsBackend_PropagatesError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("upstream vault failure")
	stub := &stubVaultAdmin{ensureErr: wantErr, edition: vaultadmin.EditionEnterprise}
	deps := ProvisionDeps{Vault: stub}
	tenant := newTestTenant("err")

	step := newProvisionSecretsBackendStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if done {
		t.Fatal("expected done=false on error")
	}
	if err == nil || !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped wantErr, got %v", err)
	}
}

// TestIsPermanentSecretsBackendError covers the 403-classification contract.
// A plain ErrUnauthorized (bad/under-privileged token) is permanent and blocks
// the tenant; a token-expiry 403 (vault.ErrTokenExpired) is transient so the
// saga keeps retrying (tenant-operator#273).
func TestIsPermanentSecretsBackendError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unclassified", errors.New("boom"), false},
		{"permanent", clients.WrapPermanent(errors.New("boom")), true},
		{"invalid-input", clients.ErrInvalidInput, true},
		{"unauthorized", clients.ErrUnauthorized, true},
		{
			"unauthorized-token-expired",
			errors.Join(clients.ErrUnauthorized, vaultadmin.ErrTokenExpired),
			false,
		},
		{
			"wrapped-token-expired",
			fmt.Errorf("provisionSecretsBackend: %w: %w", vaultadmin.ErrTokenExpired, clients.ErrUnauthorized),
			false,
		},
	}
	for _, tc := range cases {
		if got := isPermanentSecretsBackendError(tc.err); got != tc.want {
			t.Errorf("%s: isPermanentSecretsBackendError(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// TestProvisionSecretsBackend_TokenExpiry_IsTransient asserts that an expired
// admin token (403 + ErrTokenExpired) does NOT get permanent-wrapped, so the
// saga runner requeues with backoff instead of marking the tenant Blocked.
func TestProvisionSecretsBackend_TokenExpiry_IsTransient(t *testing.T) {
	t.Parallel()
	expiredErr := fmt.Errorf("vault token rejected: %w: %w", vaultadmin.ErrTokenExpired, clients.ErrUnauthorized)
	stub := &stubVaultAdmin{ensureErr: expiredErr, edition: vaultadmin.EditionEnterprise}
	deps := ProvisionDeps{Vault: stub}
	tenant := newTestTenant("token-expired")

	step := newProvisionSecretsBackendStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if done {
		t.Fatal("expected done=false on error")
	}
	if err == nil {
		t.Fatal("expected an error")
	}
	if clients.IsPermanent(err) {
		t.Fatalf("token expiry must NOT be permanent-wrapped (saga must retry), got %v", err)
	}
	if !errors.Is(err, vaultadmin.ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired preserved in chain, got %v", err)
	}
}

func TestProvisionSecretsBackend_RejectsWrongType(t *testing.T) {
	t.Parallel()
	stub := &stubVaultAdmin{}
	deps := ProvisionDeps{Vault: stub}

	step := newProvisionSecretsBackendStep(deps)
	// Pass a non-Tenant ConditionedObject (AgentEnrollment satisfies the
	// interface but the step's type-assert to *Tenant must reject it).
	other := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "wrong-type"},
	}
	done, err := step.Provision(context.Background(), other, nil)
	if done {
		t.Fatal("expected done=false on bad type")
	}
	if err == nil {
		t.Fatal("expected error on non-Tenant object")
	}
	if len(stub.ensureCalls) != 0 {
		t.Fatalf("Vault should not have been called with bad type; got %v", stub.ensureCalls)
	}
}

// TestDeprovisionSecretsBackend_NilVaultPanics — see
// TestProvisionSecretsBackend_NilVaultPanics. One-code-path
// (tenant-operator#197): the operator exits 1 at startup when Vault
// wiring is missing.
func TestDeprovisionSecretsBackend_NilVaultPanics(t *testing.T) {
	t.Parallel()
	tenant := newTestTenant("teardown-nil-panics")
	deps := ProvisionDeps{}

	step := newDeprovisionSecretsBackendStep(deps)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on nil Vault (one-code-path: tenant-operator#197)")
		}
	}()
	_, _ = step.Provision(context.Background(), tenant, nil)
}

func TestDeprovisionSecretsBackend_CallsDelete(t *testing.T) {
	t.Parallel()
	stub := &stubVaultAdmin{}
	deps := ProvisionDeps{Vault: stub}
	tenant := newTestTenant("teardown-call")

	step := newDeprovisionSecretsBackendStep(deps)
	done, err := step.Provision(context.Background(), tenant, nil)
	if err != nil {
		t.Fatalf("deprovisionSecretsBackend: %v", err)
	}
	if !done {
		t.Fatal("expected done=true")
	}
	if len(stub.deleteCalls) != 1 || stub.deleteCalls[0] != "teardown-call" {
		t.Fatalf("expected one DeleteTenantNamespace call with %q, got %v",
			"teardown-call", stub.deleteCalls)
	}
}

// TestProvisionStepsOrdering verifies that ProvisionSecretsBackend sits
// AFTER EnsureZitadelOrg and BEFORE InitRedisKeyspace. The
// WriteInitialFGATuples step was removed (tenant-operator#215) because it
// wrote a malformed FGA tuple; ProvisionSecretsBackend now depends directly
// on EnsureZitadelOrg.
func TestProvisionStepsOrdering(t *testing.T) {
	t.Parallel()
	stub := &stubVaultAdmin{edition: vaultadmin.EditionEnterprise}
	deps := ProvisionDeps{Vault: stub}
	steps := ProvisionSteps(deps)

	want := []string{
		"EnsureZitadelOrg",
		"ProvisionSecretsBackend",
		"InitRedisKeyspace",
	}
	indices := map[string]int{}
	for i, s := range steps {
		indices[s.Name()] = i
	}
	for _, name := range want {
		if _, ok := indices[name]; !ok {
			t.Fatalf("expected step %q in ProvisionSteps; have %s",
				name, namesOf(steps))
		}
	}
	if indices["EnsureZitadelOrg"] >= indices["ProvisionSecretsBackend"] ||
		indices["ProvisionSecretsBackend"] >= indices["InitRedisKeyspace"] {
		t.Fatalf("ProvisionSecretsBackend must sit between EnsureZitadelOrg and InitRedisKeyspace; order=%s",
			namesOf(steps))
	}

	// Confirm the step has the expected condition type.
	for _, s := range steps {
		if s.Name() == "ProvisionSecretsBackend" {
			if s.Condition() != gibsonv1alpha1.ConditionSecretsBackendReady {
				t.Fatalf("expected Condition=%q, got %q",
					gibsonv1alpha1.ConditionSecretsBackendReady, s.Condition())
			}
			return
		}
	}
	t.Fatal("ProvisionSecretsBackend step not found")
}

// TestTeardownStepsContainsSecretsDeprovision verifies the teardown saga
// includes the new DeprovisionSecretsBackend step.
func TestTeardownStepsContainsSecretsDeprovision(t *testing.T) {
	t.Parallel()
	deps := ProvisionDeps{Vault: &stubVaultAdmin{}}
	steps := TeardownSteps(deps)
	for _, s := range steps {
		if s.Name() == "DeprovisionSecretsBackend" {
			return
		}
	}
	t.Fatalf("DeprovisionSecretsBackend not found in TeardownSteps; have %s", namesOf(steps))
}

func namesOf(steps []saga.Step) string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Name())
	}
	return strings.Join(out, ",")
}
