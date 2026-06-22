/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

// Package flows contains the concrete saga.Step implementations for each
// Gibson CRD reconciler. Each step is a struct that satisfies
// gibson/pkg/platform/saga.Step (re-exported via the operator's saga
// package); psaga.Runner orchestrates them.
package flows

import (
	"context"
	"errors"
	"fmt"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
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
func ProvisionSteps(deps ProvisionDeps) []saga.Step {
	return []saga.Step{
		newEnsureZitadelOrgStep(deps),
		newProvisionSecretsBackendStep(deps),
		// ConfigureSecretsJWTAuth closes the gap left by EnsureTenantNamespace
		// (mounts auth/jwt + writes the role, but NEVER writes the mount's
		// config). Without it the daemon's per-tenant auth/jwt/login fails
		// with 400 "could not load configuration" and the dashboard 412s on
		// every API call. Owns its own condition
		// (ConditionSecretsJWTAuthConfigured) so existing Ready tenants
		// where ConditionSecretsBackendReady is already True still pick
		// this step up on the next reconcile. tenant-operator#189.
		newConfigureSecretsJWTAuthStep(deps),
		newInitRedisStep(deps),
		newPublishTenantNameStep(deps),
		// Register the tenant under the platform system tenant so the daemon's
		// catalog fan-out can enumerate it (deploy#782 / gibson#715). Needs only
		// the FGA client; placed here with the other lightweight publish steps.
		newRegisterTenantWithPlatformStep(deps),
		newProvisionDataPlaneStep(deps),
		// 11th step (#45): publish the per-tenant broker config row so
		// the daemon's secrets.Registry can route credential lookups
		// after the data plane is up. Must come AFTER
		// ProvisionDataPlane (Vault namespace + Postgres are live) and
		// AFTER ProvisionSecretsBackend (the Vault namespace itself
		// must exist before the daemon tries to dial it).
		newWriteTenantBrokerConfigStep(deps.WriteTenantBrokerConfig),
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
			N:     "InitRedisKeyspace",
			C:     gibsonv1alpha1.ConditionRedisReady,
			Req:   []string{"ProvisionSecretsBackend"},
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

// ---------------------------------------------------------------------------
// RegisterTenantWithPlatform
// ---------------------------------------------------------------------------

// registerTenantWithPlatformStep writes the
// `(tenant:<name>, parent, system_tenant:_system)` FGA tuple that registers
// the tenant under the platform's system tenant. The daemon's catalog fan-out
// reconciler enumerates `system_tenant:_system#parent@tenant:X` to seed the
// ADR-0046 `component:_system` baseline plus the platform catalog onto every
// tenant; without this tuple the tenant is invisible to the fan-out
// (deploy#782 / gibson#715).
//
// Idempotent via read-before-write, so the provision saga re-running this step
// on the next reconcile also backfills tenants provisioned before it existed.
//
// NOTE: this is NOT the removed WriteInitialFGATuples step (tenant-operator
// #215). That wrote a malformed *member* tuple keyed by base64(email);
// TenantMember.acceptInvitation owns member tuples. This writes a
// tenant→platform *registration* tuple, a distinct concern with a distinct
// step name (so the #215 absence contract is unaffected).
type registerTenantWithPlatformStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newRegisterTenantWithPlatformStep(deps ProvisionDeps) *registerTenantWithPlatformStep {
	return &registerTenantWithPlatformStep{
		StepBase: saga.StepBase{
			N:     "RegisterTenantWithPlatform",
			C:     "TenantRegisteredWithPlatform",
			Caps:  []saga.ClientCapability{saga.CapabilityFGA},
			Owner: "fga-integration",
			P99:   5 * time.Second,
		},
		deps: deps,
	}
}

func (s *registerTenantWithPlatformStep) parentTuple(name string) fga.Tuple {
	return fga.Tuple{
		User:     fmt.Sprintf("tenant:%s", name),
		Relation: "parent",
		Object:   "system_tenant:_system",
	}
}

func (s *registerTenantWithPlatformStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	// s.deps.FGA is guaranteed non-nil (cmd/main.go exits 1 when FGA_URL /
	// FGA_STORE_ID are unset, one-code-path epic deploy#186); guard anyway.
	if s.deps.FGA == nil {
		return false, fmt.Errorf("fga client unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	tuple := s.parentTuple(t.Name)
	// Read-before-write: OpenFGA rejects a duplicate write, so check existence
	// to keep the step idempotent across reconciles.
	existing, err := s.deps.FGA.Read(ctx, tuple)
	if err != nil && !errors.Is(err, clients.ErrNotFound) {
		return false, err
	}
	if len(existing) > 0 {
		return true, nil
	}
	if err := s.deps.FGA.Write(ctx, []fga.Tuple{tuple}); err != nil {
		return false, err
	}
	return true, nil
}

func (s *registerTenantWithPlatformStep) Deprovision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) error {
	t, err := tenantOf(obj)
	if err != nil {
		return err
	}
	// FGA is structurally required (cmd/main.go exits 1 if it can't construct
	// the client), so a nil here is operator misconfiguration — fail loud
	// rather than silently skipping the rollback cleanup (one-code-path).
	if s.deps.FGA == nil {
		return fmt.Errorf("fga client unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	// FGA.Delete is idempotent (treats a missing tuple as success). The
	// teardown DeleteTenantFGATuples step only removes tuples whose OBJECT is
	// tenant:<name>; this tuple has the tenant as the USER, so it must clean
	// itself up here.
	if err := s.deps.FGA.Delete(ctx, []fga.Tuple{s.parentTuple(t.Name)}); err != nil {
		return err
	}
	return nil
}

// ---------------------------------------------------------------------------
// DataPlaneProvisioned
// ---------------------------------------------------------------------------

type provisionDataPlaneStep struct {
	saga.StepBase
	deps ProvisionDeps
}

func newProvisionDataPlaneStep(deps ProvisionDeps) *provisionDataPlaneStep {
	return &provisionDataPlaneStep{
		StepBase: saga.StepBase{
			N:   "DataPlaneProvisioned",
			C:   "DataPlaneProvisioned",
			Req: []string{"PublishTenantName"},
			Caps: []saga.ClientCapability{
				saga.CapabilityPostgresAdmin,
				saga.CapabilityVaultTransit,
				// Neo4j is provisioned as a per-tenant K8s StatefulSet by the
				// data-plane pipeline (formerly the deleted InitNeo4jScope step).
				saga.CapabilityKubernetes,
			},
			Owner: "platform-postgres",
			P99:   2 * time.Minute,
		},
		deps: deps,
	}
}

func (s *provisionDataPlaneStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, err := tenantOf(obj)
	if err != nil {
		return false, err
	}
	// s.deps.DataPlane is always non-nil: buildDataPlaneProvisioner (cmd/main.go)
	// always returns dataplane.New(cfg) which is never nil. A nil here means
	// operator wiring code passed nil explicitly — that is a programming error.
	if s.deps.DataPlane == nil {
		return false, fmt.Errorf("data-plane provisioner unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	if err := s.deps.DataPlane.Provision(ctx, t.Name); err != nil {
		return false, fmt.Errorf("provisionDataPlane: %w", err)
	}
	return true, nil
}

func (s *provisionDataPlaneStep) Deprovision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) error {
	t, err := tenantOf(obj)
	if err != nil {
		return err
	}
	// s.deps.DataPlane is always non-nil (see Provision above).
	if s.deps.DataPlane == nil {
		return fmt.Errorf("data-plane provisioner unset (operator misconfigured): %w", clients.ErrInvalidInput)
	}
	if err := s.deps.DataPlane.Deprovision(ctx, t.Name); err != nil {
		if errors.Is(err, clients.ErrNotFound) {
			return nil
		}
		return err
	}
	return nil
}
