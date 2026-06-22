/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package flows

// ensure_vault_namespace.go implements the ProvisionSecretsBackend saga
// step per spec secrets-tenant-lifecycle Task 19 (Requirement 7.1/7.2).
//
// Vault is non-negotiable (one-code-path: tenant-operator#197). The
// previous `deps.Vault == nil` "degraded mode for BYO/on-prem" branches
// were deleted. The operator exits 1 at startup if Vault wiring is
// missing (cmd/main.go:buildVaultAdminClient), so every Provision /
// Deprovision call here may assume s.deps.Vault is non-nil.
//
// Layered behaviour, in execution order on every reconcile:
//
//  1. Read the dashboard's signup-attempt-id annotation off the Tenant CR.
//     Tenants created via dashboard signup carry this; tenants created
//     out-of-band (kubectl apply, gitops-driven seeding, fixtures) do not.
//     Without it, progress publishing becomes a no-op — the saga still
//     runs end-to-end, only the dashboard's ProvisioningPanel does not
//     receive granular updates from the operator.
//
//  2. Publish step=provisioning_secrets_backend (in-flight) to
//     SignupProgressStore. Idempotent SET with TTL — safe on retry.
//
//  3. Call deps.Vault.EnsureTenantNamespace(t.Name). Per the underlying
//     httpClient, EnsureTenantNamespace is itself idempotent.
//
//  4a. On success: publish terminalState=ok and return done=true. The
//     saga runner sets ConditionSecretsBackendReady=True and proceeds.
//
//  4b. On transient error: publish nothing terminal (the in-flight event
//     from step 2 is still the most recent) and return the error
//     untransformed. The saga runner reclassifies via metrics.ClassifyError
//     and requeues with exponential backoff.
//
//  4c. On permanent error: publish terminalState=failed with code=
//     SECRETS_NAMESPACE_FAILED and a user-facing message. The dashboard
//     renders the retry CTA.

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

// secretsBackendUserMessage is the user-facing message published when
// the step has exhausted retries or hit a permanent error. Dashboard-
// rendered verbatim — keep short, generic, free of PII or low-level
// error text.
const secretsBackendUserMessage = "We couldn't provision your secrets backend. Our team has been notified — try again in a moment."

// provisionSecretsBackendStep is the ProvisionSecretsBackend saga step.
type provisionSecretsBackendStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newProvisionSecretsBackendStep(deps ProvisionDeps) *provisionSecretsBackendStep {
	return &provisionSecretsBackendStep{
		StepBase: saga.StepBase{
			N:     "ProvisionSecretsBackend",
			C:     gibsonv1alpha1.ConditionSecretsBackendReady,
			Req:   []string{"EnsureZitadelOrg"},
			Caps:  []saga.ClientCapability{saga.CapabilityVaultAdmin},
			Owner: "platform-vault",
			P99:   10 * time.Second,
		},
		deps: deps,
	}
}

func (s *provisionSecretsBackendStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}

	attemptID := signupAttemptID(t)
	progress := progressClient(s.deps)

	// Step 2 — publish in-flight. Best-effort.
	_ = progress.Advance(ctx, attemptID, signupprogress.StepProvisioningSecretsBackend)

	// Step 3 — the actual provisioning call. s.deps.Vault is non-nil
	// (one-code-path: tenant-operator#197 — buildVaultAdminClient exits 1
	// at startup when Vault wiring is missing).
	if _, err := s.deps.Vault.EnsureTenantNamespace(ctx, t.Name); err != nil {
		// Step 4c — permanent failure path.
		wrapped := fmt.Errorf("provisionSecretsBackend tenant=%s: %w", t.Name, err)
		if isPermanentSecretsBackendError(err) {
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
		// Step 4b — transient.
		return false, wrapped
	}

	// Step 4a — success.
	_ = progress.Complete(ctx, attemptID, signupprogress.StepProvisioningSecretsBackend)
	return true, nil
}

// Deprovision tears down the per-tenant Vault namespace on rollback.
// Mirrors deprovisionSecretsBackend in teardown.go for consistency.
// s.deps.Vault is non-nil (one-code-path: tenant-operator#197).
func (s *provisionSecretsBackendStep) Deprovision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) error {
	t, err := tenantOf(obj)
	if err != nil {
		return err
	}
	if err := s.deps.Vault.DeleteTenantNamespace(ctx, t.Name); err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("deprovisionSecretsBackend tenant=%s: %w", t.Name, err)
	}
	return nil
}

// progressClient returns the SignupProgress client.
//
// In production, Redis is required infrastructure (one-code-path epic /
// deploy#199) and deps.SignupProgress is guaranteed non-nil per the
// operator's startup gate (cmd/main.go exits 1 when REDIS_ADDR is
// unset). The previous NoopClient fallback that masked a missing Redis
// connection caused the dashboard's ProvisioningPanel to hang on signup
// attempts whose events were silently dropped — that fallback is
// deleted.
//
// The defensive nil-check below is retained ONLY for test-suite
// ergonomics: many saga-flow tests construct ProvisionDeps with only
// the deps the step under test needs, and a panic on .Advance / .Complete
// would force every caller to wire a stub even when the test isn't
// asserting against progress events. Returning a no-op shim here is
// safe because the production wiring never reaches this branch.
func progressClient(deps ProvisionDeps) signupprogress.Client {
	if deps.SignupProgress == nil {
		return noopProgressClient{}
	}
	return deps.SignupProgress
}

// noopProgressClient is a test-only no-op stand-in. Production code path
// guaranteed-non-nil per cmd/main.go startup gate (one-code-path epic /
// deploy#199). Kept here, NOT in clients/signupprogress, so it cannot be
// reached from main wiring.
type noopProgressClient struct{}

func (noopProgressClient) Advance(context.Context, string, signupprogress.Step) error {
	return nil
}
func (noopProgressClient) Complete(context.Context, string, signupprogress.Step) error {
	return nil
}
func (noopProgressClient) Fail(context.Context, string, signupprogress.Step, signupprogress.FailureCode, string) error {
	return nil
}
func (noopProgressClient) Ping(context.Context) error { return nil }

// signupAttemptID extracts the dashboard-supplied attempt-id from the
// Tenant CR's annotations, returning the empty string when absent.
func signupAttemptID(t *gibsonv1alpha1.Tenant) string {
	if t == nil {
		return ""
	}
	annotations := t.GetAnnotations()
	if annotations == nil {
		return ""
	}
	return annotations[AnnotationSignupAttemptID]
}

// isPermanentSecretsBackendError reports whether err should immediately
// surface SECRETS_NAMESPACE_FAILED to the dashboard rather than wait for
// retry.
//
// Permanent classes:
//   - clients.ErrPermanent — explicitly marked permanent upstream.
//   - clients.ErrInvalidInput — Vault rejected a malformed request.
//   - clients.ErrUnauthorized — the admin token is rejected, UNLESS the
//     rejection is an expired/non-renewable token (vault.ErrTokenExpired),
//     which is transient: a pod restart or periodic-token renewal recovers
//     it, so the saga must keep retrying with backoff rather than block the
//     tenant (tenant-operator#273).
func isPermanentSecretsBackendError(err error) bool {
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
		// Token expiry is a 403 too, but it is recoverable — keep retrying.
		return !errors.Is(err, vaultadmin.ErrTokenExpired)
	}
	return false
}
