/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package flows

// Shared test helpers for the saga-flow contract tests plus the
// ProvisionSteps / TeardownSteps name-set assertions.
//
// E8/gibson#805 cutover: the per-step ProvisionSecretsBackend /
// DeprovisionSecretsBackend / ConfigureSecretsJWTAuth tests were removed
// along with those steps (their domains moved to the TenantSecretsBackend
// sub-CRD). The stubVaultAdmin / newTestTenant / namesOf helpers are retained
// here because other contract tests in this package depend on them.

import (
	"context"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
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

// TestProvisionStepsOrdering verifies that, after the E8/gibson#805 cutover,
// ProvisionSteps returns exactly the two retained foundation steps in order:
// InitRedisKeyspace then PublishTenantName. The identity / secrets-backend /
// grants / data-plane steps moved to the four owned sub-CRDs.
func TestProvisionStepsOrdering(t *testing.T) {
	t.Parallel()
	stub := &stubVaultAdmin{edition: vaultadmin.EditionEnterprise}
	deps := ProvisionDeps{Vault: stub}
	steps := ProvisionSteps(deps)

	want := []string{"InitRedisKeyspace", "PublishTenantName"}
	got := make([]string, 0, len(steps))
	for _, s := range steps {
		got = append(got, s.Name())
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ProvisionSteps order = %v, want %v", got, want)
	}
}

func namesOf(steps []saga.Step) string {
	out := make([]string, 0, len(steps))
	for _, s := range steps {
		out = append(out, s.Name())
	}
	return strings.Join(out, ",")
}
