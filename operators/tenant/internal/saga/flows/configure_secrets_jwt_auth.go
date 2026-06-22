/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// configure_secrets_jwt_auth.go implements the ConfigureSecretsJWTAuth
// saga step. It writes the per-tenant `auth/jwt/config` document inside
// the tenant's Vault namespace (bound_issuer + jwks_url + jwks_ca_pem),
// mirroring the root namespace's config set by the chart's
// openbao-jwt-auth-init Job.
//
// Without this step, the daemon's per-tenant `auth/jwt/login` returns
// 400 "could not load configuration" and the dashboard 412s on every
// API call. tenant-operator#189.
//
// Step placement: AFTER ProvisionSecretsBackend (the namespace + jwt
// auth mount + role have to exist before we can write the config). The
// step has its OWN condition (ConditionSecretsJWTAuthConfigured), so on
// existing tenants where ConditionSecretsBackendReady is already True
// but the new condition is unknown, the saga runner picks this step up
// fresh on the next reconcile — no manual intervention required for
// the in-flight tenant set.

package flows

import (
	"context"
	"errors"
	"fmt"
	"time"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/signupprogress"
	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// configureSecretsJWTAuthStep is the ConfigureSecretsJWTAuth saga step.
type configureSecretsJWTAuthStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newConfigureSecretsJWTAuthStep(deps ProvisionDeps) *configureSecretsJWTAuthStep {
	return &configureSecretsJWTAuthStep{
		StepBase: saga.StepBase{
			N:     "ConfigureSecretsJWTAuth",
			C:     gibsonv1alpha1.ConditionSecretsJWTAuthConfigured,
			Req:   []string{"ProvisionSecretsBackend"},
			Caps:  []saga.ClientCapability{saga.CapabilityVaultAdmin},
			Owner: "platform-vault",
			P99:   5 * time.Second,
		},
		deps: deps,
	}
}

func (s *configureSecretsJWTAuthStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}

	attemptID := signupAttemptID(t)
	progress := progressClient(s.deps)
	_ = progress.Advance(ctx, attemptID, signupprogress.StepProvisioningSecretsBackend)

	// s.deps.Vault is non-nil (one-code-path: tenant-operator#197 — startup
	// gate). ConfigureTenantJWTAuth is idempotent: POST to auth/jwt/config
	// is an overwrite on Vault, so re-running on an existing tenant is a
	// no-op.
	if err := s.deps.Vault.ConfigureTenantJWTAuth(ctx, t.Name); err != nil {
		wrapped := fmt.Errorf("configureSecretsJWTAuth tenant=%s: %w", t.Name, err)
		if isPermanentJWTAuthConfigError(err) {
			_ = progress.Fail(
				ctx,
				attemptID,
				signupprogress.StepProvisioningSecretsBackend,
				signupprogress.CodeSecretsNamespaceFailed,
				secretsBackendUserMessage,
			)
			if !clients.IsPermanent(err) {
				wrapped = clients.WrapPermanent(wrapped)
			}
			return false, wrapped
		}
		return false, wrapped
	}

	return true, nil
}

// Deprovision: no rollback action — `auth/jwt/config` lives inside the
// per-tenant namespace and is removed wholesale when the namespace is
// deleted by deprovisionSecretsBackend (teardown.go).
func (s *configureSecretsJWTAuthStep) Deprovision(_ context.Context, _ saga.ConditionedObject, _ *saga.Deps) error {
	return nil
}

// isPermanentJWTAuthConfigError mirrors isPermanentSecretsBackendError but
// keeps the classification local to this step. Same classes:
//   - clients.ErrPermanent
//   - clients.ErrInvalidInput (e.g. JWTBoundIssuer unset on the operator)
//   - clients.ErrUnauthorized, EXCEPT vault.ErrTokenExpired — an expired admin
//     token is a 403 too, but it is recoverable (pod restart / periodic-token
//     renewal), so the saga must keep retrying rather than block the tenant
//     (tenant-operator#273). This step uses the same admin token as
//     ProvisionSecretsBackend, so it is subject to the same expiry race.
func isPermanentJWTAuthConfigError(err error) bool {
	if err == nil {
		return false
	}
	if clients.IsPermanent(err) {
		return true
	}
	if errors.Is(err, clients.ErrInvalidInput) {
		return true
	}
	if errors.Is(err, clients.ErrUnauthorized) {
		return !errors.Is(err, vaultadmin.ErrTokenExpired)
	}
	return false
}
