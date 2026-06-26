// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package flows

import (
	"context"
	"errors"
	"time"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// TeardownSteps returns the ordered cleanup steps for a Tenant.
//
// E8/gibson#805 cutover: the imperative compensation steps that tore down the
// identity / secrets-backend / grants / data-plane domains (DeprovisionDataPlane,
// DeleteTenantFGATuples, RemoveZitadelOrg, DeprovisionSecretsBackend) were
// removed. Those domains are now owned by the four sub-CRDs, whose own
// finalizers tear them down. The Tenant reconciler's finalizer deletes the
// children in REVERSE dependency order (DataPlane → Grants → SecretsBackend →
// Identity) and waits for each child's finalizer to complete BEFORE running this
// teardown saga — so the namespace (deleted by DeleteNamespace, appended by
// TenantReconciler.teardownSteps) outlives the namespaced children.
//
// The retained teardown saga owns only the foundation cleanup with no owning
// sub-CRD: the final backup safety net, the tenant-name delete, and the Redis
// keyspace delete. Order: backup first (safety net before any data deletion),
// then tenant-name, then Redis keyspace.
func TeardownSteps(deps ProvisionDeps) []saga.Step {
	return []saga.Step{
		newFinalBackupStep(deps.FinalBackup),
		newDeleteTenantNameStep(deps),
		newDeleteRedisKeyspaceStep(deps),
	}
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
			// E8/gibson#805: previously Req'd RemoveZitadelOrg, a teardown step
			// that has moved to the TenantIdentity sub-CRD finalizer (which the
			// Tenant reconciler drains before this saga runs). The tenant-name
			// delete only touches the Redis registry PublishTenantName
			// populated; it Req's FinalNeo4jBackup so the safety-net backup
			// still precedes any data deletion.
			Req:   []string{"FinalNeo4jBackup"},
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

// Confirm at compile-time that gibsonv1alpha1.Tenant satisfies the
// ConditionedObject interface — these teardown steps assert it everywhere.
var _ saga.ConditionedObject = (*gibsonv1alpha1.Tenant)(nil)
