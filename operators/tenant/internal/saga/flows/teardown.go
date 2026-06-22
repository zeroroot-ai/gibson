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
	"fmt"
	"time"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// TeardownSteps returns the ordered cleanup steps for a Tenant.
//
// Order matters: final backup first (safety net before any data deletion),
// then data plane (revoke data-layer access), then FGA (remove
// authorization tuples), then Zitadel org (remove identity), then the
// remaining tenant-name/Redis/secrets-backend resources.
func TeardownSteps(deps ProvisionDeps) []saga.Step {
	return []saga.Step{
		newFinalBackupStep(deps.FinalBackup),
		newDeprovisionDataPlaneStep(deps),
		newDeleteTenantFGAStep(deps),
		newRemoveZitadelOrgStep(deps),
		newDeleteTenantNameStep(deps),
		newDeleteRedisKeyspaceStep(deps),
		newDeprovisionSecretsBackendStep(deps),
	}
}

// ---------------------------------------------------------------------------
// DeprovisionDataPlane
// ---------------------------------------------------------------------------

type deprovisionDataPlaneStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newDeprovisionDataPlaneStep(deps ProvisionDeps) *deprovisionDataPlaneStep {
	return &deprovisionDataPlaneStep{
		StepBase: saga.StepBase{
			N: "DeprovisionDataPlane",
			C: "DataPlaneDeprovisioned",
			// Final backup must complete before any data-plane deletion
			// runs — see TeardownSteps doc and FinalNeo4jBackup contract.
			Req: []string{"FinalNeo4jBackup"},
			Caps: []saga.ClientCapability{
				saga.CapabilityPostgresAdmin,
				saga.CapabilityVaultTransit,
			},
			Owner: "platform-postgres",
			// Mirrors DataPlaneProvisioned (provision-side counterpart) —
			// Postgres + Vault namespace teardown is the slowest step.
			P99: 2 * time.Minute,
		},
		deps: deps,
	}
}

func (s *deprovisionDataPlaneStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	// s.deps.DataPlane is always non-nil: buildDataPlaneProvisioner (cmd/main.go)
	// always returns dataplane.New(cfg). A nil here is a programming error.
	if s.deps.DataPlane == nil {
		return false, fmt.Errorf("data-plane provisioner unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	if err := s.deps.DataPlane.Deprovision(ctx, t.Name); err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			return true, nil
		}
		return false, fmt.Errorf("deprovisionDataPlane: %w", err)
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// DeleteTenantFGATuples
// ---------------------------------------------------------------------------

type deleteTenantFGAStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newDeleteTenantFGAStep(deps ProvisionDeps) *deleteTenantFGAStep {
	return &deleteTenantFGAStep{
		StepBase: saga.StepBase{
			N:     "DeleteTenantFGATuples",
			C:     "FGATuplesDeleted",
			Req:   []string{"DeprovisionDataPlane"},
			Caps:  []saga.ClientCapability{saga.CapabilityFGA},
			Owner: "fga-integration",
			P99:   5 * time.Second,
		},
		deps: deps,
	}
}

func (s *deleteTenantFGAStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	// s.deps.FGA is guaranteed non-nil: cmd/main.go exits 1 when FGA_URL or
	// FGA_STORE_ID are unset (one-code-path epic, deploy#186).
	if s.deps.FGA == nil {
		return false, fmt.Errorf("fga client unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	tenantRef := fmt.Sprintf("tenant:%s", t.Name)
	// Delete every tuple referencing this tenant, both where the tenant is the
	// OBJECT (membership / role grants: user→tenant) and where it is the USER
	// (registration / ownership: tenant→system_tenant#parent, tenant→team#parent).
	// The latter set was previously leaked on teardown (deploy#782 / gibson#715).
	var tuples []fga.Tuple
	for _, filter := range []fga.Tuple{{Object: tenantRef}, {User: tenantRef}} {
		read, err := s.deps.FGA.Read(ctx, filter)
		if err != nil && !errors.Is(err, clients.ErrNotFound) {
			return false, err
		}
		tuples = append(tuples, read...)
	}
	if len(tuples) > 0 {
		if err := s.deps.FGA.Delete(ctx, tuples); err != nil {
			return false, err
		}
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// DeleteTenantName
// ---------------------------------------------------------------------------

type deleteTenantNameStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newDeleteTenantNameStep(deps ProvisionDeps) *deleteTenantNameStep {
	return &deleteTenantNameStep{
		StepBase: saga.StepBase{
			N: "DeleteTenantName",
			C: "TenantNameDeleted",
			// Runs after the Zitadel org delete (TenantNameDeleted lives in
			// the same Redis registry that PublishTenantName populated).
			Req:   []string{"RemoveZitadelOrg"},
			Caps:  []saga.ClientCapability{saga.CapabilityRedisAdmin},
			Owner: "platform-redis",
			P99:   1 * time.Second,
		},
		deps: deps,
	}
}

func (s *deleteTenantNameStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	// Redis is required infrastructure (one-code-path epic / deploy#199);
	// s.deps.Redis is guaranteed non-nil per the operator's startup gate.
	err = s.deps.Redis.DeleteTenantName(ctx, t.Name)
	if err == nil || errors.Is(err, clients.ErrNotFound) {
		return true, nil
	}
	return false, err
}

// ---------------------------------------------------------------------------
// DeleteRedisKeyspace
// ---------------------------------------------------------------------------

type deleteRedisKeyspaceStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newDeleteRedisKeyspaceStep(deps ProvisionDeps) *deleteRedisKeyspaceStep {
	return &deleteRedisKeyspaceStep{
		StepBase: saga.StepBase{
			N:     "DeleteRedisKeyspace",
			C:     "RedisDeleted",
			Req:   []string{"DeleteTenantName"},
			Caps:  []saga.ClientCapability{saga.CapabilityRedisAdmin},
			Owner: "platform-redis",
			P99:   5 * time.Second,
		},
		deps: deps,
	}
}

func (s *deleteRedisKeyspaceStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	// Redis is required infrastructure (one-code-path epic / deploy#199);
	// s.deps.Redis is guaranteed non-nil per the operator's startup gate.
	_, err = s.deps.Redis.DeleteTenantKeyspace(ctx, t.Name)
	if err == nil || errors.Is(err, clients.ErrNotFound) {
		return true, nil
	}
	return false, err
}

// ---------------------------------------------------------------------------
// DeprovisionSecretsBackend
// ---------------------------------------------------------------------------

type deprovisionSecretsBackendStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newDeprovisionSecretsBackendStep(deps ProvisionDeps) *deprovisionSecretsBackendStep {
	return &deprovisionSecretsBackendStep{
		StepBase: saga.StepBase{
			N:     "DeprovisionSecretsBackend",
			C:     "SecretsBackendDeleted",
			Req:   []string{"DeleteRedisKeyspace"},
			Caps:  []saga.ClientCapability{saga.CapabilityVaultTransit},
			Owner: "platform-vault",
			P99:   10 * time.Second,
		},
		deps: deps,
	}
}

func (s *deprovisionSecretsBackendStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	// s.deps.Vault is non-nil (one-code-path: tenant-operator#197 —
	// buildVaultAdminClient exits 1 at startup when Vault wiring is missing).
	if err := s.deps.Vault.DeleteTenantNamespace(ctx, t.Name); err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			return true, nil
		}
		return false, fmt.Errorf("deprovisionSecretsBackend tenant=%s: %w", t.Name, err)
	}
	return true, nil
}

// Confirm at compile-time that gibsonv1alpha1.Tenant satisfies the
// ConditionedObject interface — these teardown steps assert it everywhere.
var _ saga.ConditionedObject = (*gibsonv1alpha1.Tenant)(nil)
