// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package flows contains the concrete saga.Step implementations for each
// Gibson CRD reconciler. Each step is a struct that satisfies
// gibson/pkg/platform/saga.Step (re-exported via the operator's saga
// package); psaga.Runner orchestrates them.
package flows

import (
	"context"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/redisstate"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/signupprogress"
	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/zitadel"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// AnnotationSignupAttemptID is the annotation key on Tenant CRs that
// carries the dashboard's signup-flow attempt ID. Stay in sync with the
// dashboard's tenants.ts when changing the value.
const AnnotationSignupAttemptID = "gibson.zeroroot.ai/signup-attempt-id"

// ProvisionDeps bundles the clients needed by the provisioning saga.
type ProvisionDeps struct {
	K8sClient client.Client
	FGA       fga.Client
	Redis     redisstate.Client
	Zitadel   zitadel.Client
	// DataPlane provisions per-tenant data-plane resources (Postgres, Neo4j,
	// Redis, etc.) as per-tenant K8s StatefulSets. Always non-nil:
	// buildDataPlaneProvisioner in cmd/main.go always returns dataplane.New(cfg).
	// A nil here is a programming error that now fails loud (one-code-path /
	// tenant-operator#95). This is the sole Neo4j provisioning path — the
	// legacy shared-cluster neo4jstate.Client step was deleted (#350).
	DataPlane dataplane.Provisioner

	// Vault is the operator's admin client to the Gibson SaaS Vault. When
	// non-nil, the provisioning saga issues an idempotent EnsureTenantNamespace
	// per spec secrets-broker Requirement 10.3.
	Vault vaultadmin.AdminClient

	// SignupProgress is the writer-side client to the dashboard's
	// SignupProgressStore (Redis-backed, polled by the ProvisioningPanel).
	SignupProgress signupprogress.Client

	// FinalBackup carries the configuration for the pre-deprovision Velero
	// backup step.
	FinalBackup FinalBackupDeps

	// WriteTenantBrokerConfig wires the new 11th saga step that writes a
	// row to the platform tenant_secrets_broker_config table after
	// data-plane provisioning completes. Without this row, the gibson
	// daemon returns FailedPrecondition on every authenticated list
	// call. Spec issue #45.
	WriteTenantBrokerConfig WriteTenantBrokerConfigDeps
}

// ProvisionSteps returns the ordered saga steps for provisioning a Tenant.
// These run after the foundation NamespaceProvisioner step.
//
// E8/gibson#805 cutover: the identity / secrets-backend / grants / data-plane
// domains are now provisioned declaratively by the four owned sub-CRDs
// (TenantIdentity #803, TenantSecretsBackend #802, TenantGrants #804,
// TenantDataPlane #801) that the Tenant reconciler creates in dependency order.
// The corresponding inline saga steps (EnsureZitadelOrg, ProvisionSecretsBackend,
// ConfigureSecretsJWTAuth, RegisterTenantWithPlatform, DataPlaneProvisioned,
// TenantBrokerConfigWritten) were removed here to avoid double-provisioning
// (ADR-0027: no parallel saga + CRD provisioning). The sub-CRD controllers
// delegate to the SAME provisioners those steps used, so behaviour is preserved.
//
// The retained saga owns only the foundation steps that have no owning sub-CRD:
// the per-tenant Redis keyspace (InitRedisKeyspace) and the tenant-name publish
// (PublishTenantName). The per-tenant namespace is contributed by the
// NamespaceProvisioner ahead of these (see TenantReconciler.provisioningSteps).
func ProvisionSteps(deps ProvisionDeps) []saga.Step {
	return []saga.Step{
		newInitRedisStep(deps),
		newPublishTenantNameStep(deps),
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func tenantOf(obj saga.ConditionedObject) (*gibsonv1alpha1.Tenant, error) {
	t, ok := obj.(*gibsonv1alpha1.Tenant)
	if !ok {
		return nil, fmt.Errorf("expected *Tenant, got %T", obj)
	}
	return t, nil
}

// ---------------------------------------------------------------------------
// InitRedisKeyspace
// ---------------------------------------------------------------------------

type initRedisStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newInitRedisStep(deps ProvisionDeps) *initRedisStep {
	return &initRedisStep{
		StepBase: saga.StepBase{
			N: "InitRedisKeyspace",
			C: gibsonv1alpha1.ConditionRedisReady,
			// E8/gibson#805: previously Req'd ProvisionSecretsBackend, a saga
			// step that has moved to the TenantSecretsBackend sub-CRD. Redis
			// keyspace init has no functional dependency on the Vault namespace
			// (the Req encoded only sequencing), so the edge is dropped — the
			// retained saga now starts at the Redis keyspace.
			Caps:  []saga.ClientCapability{saga.CapabilityRedisAdmin},
			Owner: "platform-redis",
			P99:   5 * time.Second,
		},
		deps: deps,
	}
}

func (s *initRedisStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	// Redis is required infrastructure (one-code-path epic / deploy#199):
	// the operator exits 1 at boot when REDIS_ADDR is unset, so s.deps.Redis
	// is guaranteed non-nil here. The previous graceful-nil branch silently
	// returned success when Redis was unreachable, which the dashboard's
	// ProvisioningPanel saw as a step that "succeeded" without producing
	// the per-tenant keyspace the daemon then required.
	return true, s.deps.Redis.InitTenantKeyspace(ctx, t.Name)
}

// ---------------------------------------------------------------------------
// PublishTenantName
// ---------------------------------------------------------------------------

type publishTenantNameStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newPublishTenantNameStep(deps ProvisionDeps) *publishTenantNameStep {
	return &publishTenantNameStep{
		StepBase: saga.StepBase{
			N:     "PublishTenantName",
			C:     gibsonv1alpha1.ConditionTenantNamePublished,
			Req:   []string{"InitRedisKeyspace"},
			Caps:  []saga.ClientCapability{saga.CapabilityRedisAdmin},
			Owner: "platform-redis",
			P99:   1 * time.Second,
		},
		deps: deps,
	}
}

func (s *publishTenantNameStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	// Redis is required infrastructure (one-code-path epic / deploy#199);
	// s.deps.Redis is guaranteed non-nil per the operator's startup gate.
	name := t.Spec.DisplayName
	if name == "" {
		name = t.Name
	}
	return true, s.deps.Redis.PublishTenantName(ctx, t.Name, name)
}
