// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// entitlementsDB returns the *sql.DB used for tenant_quotas writes. The
// daemon wires this via WithPlatformDB; nil means the daemon booted without
// a dashboard Postgres connection (dev/kind clusters can still run the rest
// of the RPCs, but UpsertTenantQuota returns Unavailable).
func (s *DaemonServer) entitlementsDB() *sql.DB {
	return s.platformDB
}

// WriteAccessTuples atomically adds and/or deletes FGA tuples. The operator
// calls this via the dashboard's SPIFFE-authenticated provisioning endpoint.
// The FGA interceptor enforces the tenant admin / platform-operator relation
// before dispatch; this handler does the write itself.
//
// Audit wiring (task 49) will hook each write to produce one
// AccessTupleChange event per tuple; for now the RPC is a direct pass-through
// to the authorizer.
func (s *DaemonServer) WriteAccessTuples(ctx context.Context, req *daemonoperatorv1.WriteAccessTuplesRequest) (*daemonoperatorv1.WriteAccessTuplesResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	adds := make([]authz.Tuple, 0, len(req.GetAdd()))
	for _, t := range req.GetAdd() {
		if t.GetUser() == "" || t.GetRelation() == "" || t.GetObject() == "" {
			return nil, status.Errorf(codes.InvalidArgument, "empty field in add tuple")
		}
		adds = append(adds, authz.Tuple{User: t.GetUser(), Relation: t.GetRelation(), Object: t.GetObject()})
	}
	dels := make([]authz.Tuple, 0, len(req.GetDelete()))
	for _, t := range req.GetDelete() {
		if t.GetUser() == "" || t.GetRelation() == "" || t.GetObject() == "" {
			return nil, status.Errorf(codes.InvalidArgument, "empty field in delete tuple")
		}
		dels = append(dels, authz.Tuple{User: t.GetUser(), Relation: t.GetRelation(), Object: t.GetObject()})
	}
	if len(adds) > 0 {
		if err := s.authorizer.Write(ctx, adds); err != nil {
			return nil, status.Errorf(codes.Internal, "fga write: %v", err)
		}
	}
	if len(dels) > 0 {
		if err := s.authorizer.Delete(ctx, dels); err != nil {
			return nil, status.Errorf(codes.Internal, "fga delete: %v", err)
		}
	}

	// Audit emission: one event per tuple, non-blocking. Source classification
	// is derived from the caller identity; reason forwarded verbatim.
	actorSource := classifyActorSource(ctx)
	reason := req.GetReason()
	for _, t := range adds {
		emitAccessTupleChange(ctx, s.auditLogger, actorSource,
			struct{ User, Relation, Object string }{t.User, t.Relation, t.Object},
			"write", reason,
		)
	}
	for _, t := range dels {
		emitAccessTupleChange(ctx, s.auditLogger, actorSource,
			struct{ User, Relation, Object string }{t.User, t.Relation, t.Object},
			"delete", reason,
		)
	}

	s.logger.Info("entitlements: WriteAccessTuples",
		"added", len(adds), "deleted", len(dels), "reason", req.GetReason())
	return &daemonoperatorv1.WriteAccessTuplesResponse{Added: int32(len(adds)), Deleted: int32(len(dels))}, nil
}

// UpsertTenantQuota writes the per-tenant quota row. Creates the table on
// first use so deployments without a pre-run migration step still converge.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: gated at ext-authz on
// relation platform_operator / object_deriver system_tenant, plus the SPIFFE peer allowlist.
// Cross-tenant is the intended semantic (the operator writes quotas for every tenant).
func (s *DaemonServer) UpsertTenantQuota(ctx context.Context, req *daemonoperatorv1.UpsertTenantQuotaRequest) (*daemonoperatorv1.UpsertTenantQuotaResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "dashboard Postgres not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if err := ensureTenantQuotasTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}

	const q = `
		INSERT INTO tenant_quotas (tenant_id, concurrent_missions, concurrent_agents, concurrent_connectors, plan_id, updated_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			concurrent_missions = EXCLUDED.concurrent_missions,
			concurrent_agents = EXCLUDED.concurrent_agents,
			concurrent_connectors = EXCLUDED.concurrent_connectors,
			plan_id = EXCLUDED.plan_id,
			updated_at = NOW()
		RETURNING updated_at
	`
	var updatedAt time.Time
	if err := db.QueryRowContext(ctx, q,
		req.GetTenantId(),
		req.GetConcurrentMissions(),
		req.GetConcurrentAgents(),
		req.GetConcurrentConnectors(),
		req.GetPlanId(),
	).Scan(&updatedAt); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert: %v", err)
	}
	return &daemonoperatorv1.UpsertTenantQuotaResponse{UpdatedAt: updatedAt.UTC().Format(time.RFC3339Nano)}, nil
}

// ListFeatureTuples returns an empty relation list. Spec
// plans-and-quotas-simplification removed every has_* relation from the
// FGA model; operator code that still calls this method gets a no-op.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist.
func (s *DaemonServer) ListFeatureTuples(ctx context.Context, req *daemonoperatorv1.ListFeatureTuplesRequest) (*daemonoperatorv1.ListFeatureTuplesResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	return &daemonoperatorv1.ListFeatureTuplesResponse{Relations: nil}, nil
}

// SeedCatalogTenantEnabled writes tenant_enabled tuples for every catalog
// item currently platform_enabled. Idempotent via FGA's write semantics.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist.
func (s *DaemonServer) SeedCatalogTenantEnabled(ctx context.Context, req *daemonoperatorv1.SeedCatalogTenantEnabledRequest) (*daemonoperatorv1.SeedCatalogTenantEnabledResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	systemRef := "system_tenant:_system"
	ids, err := s.authorizer.ListObjects(ctx, systemRef, "platform_enabled", "component")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list platform_enabled: %v", err)
	}
	if len(ids) == 0 {
		return &daemonoperatorv1.SeedCatalogTenantEnabledResponse{}, nil
	}
	tenantRef := "tenant:" + tenantID
	tuples := make([]authz.Tuple, 0, len(ids))
	for _, obj := range ids {
		if obj == "" {
			continue
		}
		if !hasPrefix(obj, "component:") {
			obj = "component:" + obj
		}
		tuples = append(tuples, authz.Tuple{User: tenantRef, Relation: "tenant_enabled", Object: obj})
	}
	if err := s.authorizer.Write(ctx, tuples); err != nil {
		return nil, status.Errorf(codes.Internal, "fga write: %v", err)
	}
	return &daemonoperatorv1.SeedCatalogTenantEnabledResponse{}, nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// auditResultFailure is the result of the second record of a change that
// failed after its first record was written.
const auditResultFailure = "failure"

// EmitAuditEvent writes the audit record of a change that an operator
// workload makes outside the daemon (gibson#583). Only operator and platform
// workloads may call it, so a user or an agent cannot forge an audit trail.
// The actor is always the identity on ctx, never a request field.
//
// A record with no result is the record written before the change. It is
// durable in Postgres before the RPC answers, so the caller makes the change
// only after the record exists (D15, gibson#676). A record with the result
// "failure" is the second record of a change that failed.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: gated at
// ext-authz on relation platform_operator / object_deriver system_tenant, plus
// the SPIFFE peer allowlist. The operator records changes for every tenant.
func (s *DaemonServer) EmitAuditEvent(ctx context.Context, req *daemonoperatorv1.EmitAuditEventRequest) (*daemonoperatorv1.EmitAuditEventResponse, error) {
	if s.auditLogger == nil {
		return nil, status.Error(codes.Unavailable, "audit emitter not configured")
	}
	ev := req.GetEvent()
	if ev == nil {
		return nil, status.Error(codes.InvalidArgument, "event required")
	}
	if ev.GetType() == "" || ev.GetTargetType() == "" || ev.GetTargetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "type, target_type and target_id are required")
	}
	if ev.GetResult() != "" && ev.GetResult() != auditResultFailure {
		return nil, status.Errorf(codes.InvalidArgument, "result must be empty or %q", auditResultFailure)
	}
	tenant, err := auth.NewTenantID(ev.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id: %v", err)
	}
	actorSource := classifyActorSource(ctx)
	if actorSource != "operator" && actorSource != "platform" && actorSource != "system" {
		return nil, status.Error(codes.PermissionDenied, "only operator/platform workloads may emit audit events")
	}

	details := make(map[string]any, len(ev.GetFields())+2)
	for k, v := range ev.GetFields() {
		details[k] = v
	}
	details["actor_source"] = actorSource
	if ev.GetReason() != "" {
		details["reason"] = ev.GetReason()
	}

	// The record belongs to the tenant of the target, so the tenant's own
	// ListAuditEvents and the compliance reader return it.
	ctx = auth.ContextWithTenant(ctx, tenant)
	if ev.GetResult() == auditResultFailure {
		s.auditLogger.LogWithResult(ctx, ev.GetType(), ev.GetTargetType(), ev.GetTargetId(), auditResultFailure, details)
		return &daemonoperatorv1.EmitAuditEventResponse{}, nil
	}
	// The record is durable before the RPC answers, so the caller learns
	// when its audit record is lost and makes no change (gibson#676).
	if _, err := s.auditLogger.Record(ctx, ev.GetType(), ev.GetTargetType(), ev.GetTargetId(), details); err != nil {
		s.logger.ErrorContext(ctx, "EmitAuditEvent: durable write failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "the audit record could not be written; try again")
	}
	return &daemonoperatorv1.EmitAuditEventResponse{}, nil
}

// ensureTenantQuotasTable is an idempotent CREATE TABLE IF NOT EXISTS for
// deployments that haven't run the migration file
// (pkg/platform/migrations/postgres/platform/003_tenant_quotas_simplify.up.sql)
// yet. The
// migration is still the authoritative source in schema-managed environments.
func ensureTenantQuotasTable(ctx context.Context, db *sql.DB) error {
	const create = `
		CREATE TABLE IF NOT EXISTS tenant_quotas (
			tenant_id TEXT PRIMARY KEY,
			concurrent_missions INT NOT NULL DEFAULT 0,
			concurrent_agents INT NOT NULL DEFAULT 0,
			concurrent_connectors INT NOT NULL DEFAULT 0,
			plan_id TEXT NOT NULL DEFAULT '',
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("create tenant_quotas: %w", err)
	}
	// Forward-compat: ALTER TABLE ... ADD COLUMN IF NOT EXISTS catches
	// upgrades where the legacy schema already exists. Spec
	// plans-and-quotas-simplification.
	const ensure = `
		ALTER TABLE tenant_quotas
			ADD COLUMN IF NOT EXISTS concurrent_missions INT NOT NULL DEFAULT 0
	`
	if _, err := db.ExecContext(ctx, ensure); err != nil {
		return fmt.Errorf("alter tenant_quotas (concurrent_missions): %w", err)
	}
	// plan_id was added when the daemon began stamping the canonical plan
	// onto the quota row (so the billing page shows the plan name, not
	// "No plan assigned"). ADD COLUMN IF NOT EXISTS keeps pre-existing
	// tables forward-compatible.
	const ensurePlan = `
		ALTER TABLE tenant_quotas
			ADD COLUMN IF NOT EXISTS plan_id TEXT NOT NULL DEFAULT ''
	`
	if _, err := db.ExecContext(ctx, ensurePlan); err != nil {
		return fmt.Errorf("alter tenant_quotas (plan_id): %w", err)
	}
	// concurrent_connectors is the plan-tier hosted-connector instance budget
	// (ADR-0065). ADD COLUMN IF NOT EXISTS keeps pre-existing tables
	// forward-compatible.
	const ensureConnectors = `
		ALTER TABLE tenant_quotas
			ADD COLUMN IF NOT EXISTS concurrent_connectors INT NOT NULL DEFAULT 0
	`
	if _, err := db.ExecContext(ctx, ensureConnectors); err != nil {
		return fmt.Errorf("alter tenant_quotas (concurrent_connectors): %w", err)
	}
	return nil
}
