package api

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/reconciler"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/plugin/manifest"
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
func (s *DaemonServer) ListFeatureTuples(ctx context.Context, req *daemonoperatorv1.ListFeatureTuplesRequest) (*daemonoperatorv1.ListFeatureTuplesResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	return &daemonoperatorv1.ListFeatureTuplesResponse{Relations: nil}, nil
}

// SeedCatalogTenantEnabled writes tenant_enabled tuples for every catalog
// item currently platform_enabled. Idempotent via FGA's write semantics.
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
		return &daemonoperatorv1.SeedCatalogTenantEnabledResponse{TuplesWritten: 0}, nil
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
	return &daemonoperatorv1.SeedCatalogTenantEnabledResponse{TuplesWritten: int32(len(tuples))}, nil
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// EmitAuditEvent records a caller-supplied audit event onto the daemon's
// emitter. Only operator / platform actors are permitted to emit events
// with arbitrary subjects; all other callers (users, agents) are forbidden
// from this RPC entirely so they cannot forge an audit trail. The handler
// ignores the request's actor_subject field: the actor is always the
// SPIFFE identity already attached to ctx by the auth interceptor.
func (s *DaemonServer) EmitAuditEvent(ctx context.Context, req *daemonoperatorv1.EmitAuditEventRequest) (*daemonoperatorv1.EmitAuditEventResponse, error) {
	if s.auditLogger == nil {
		return nil, status.Error(codes.Unavailable, "audit emitter not configured")
	}
	ev := req.GetEvent()
	if ev == nil {
		return nil, status.Error(codes.InvalidArgument, "event required")
	}
	actorSource := classifyActorSource(ctx)
	if actorSource != "operator" && actorSource != "platform" && actorSource != "system" {
		return nil, status.Error(codes.PermissionDenied, "only operator/platform workloads may emit audit events")
	}

	details := make(map[string]any, len(ev.GetFields())+6)
	for k, v := range ev.GetFields() {
		details[k] = v
	}
	if ev.GetTuple() != "" {
		details["tuple"] = ev.GetTuple()
	}
	if ev.GetActionClass() != "" {
		details["action_class"] = ev.GetActionClass()
	}
	if ev.GetScopeType() != "" {
		details["scope_type"] = ev.GetScopeType()
	}
	if ev.GetOperation() != "" {
		details["operation"] = ev.GetOperation()
	}
	if ev.GetReason() != "" {
		details["reason"] = ev.GetReason()
	}
	details["actor_source"] = actorSource
	if ev.GetTimestamp() != "" {
		details["timestamp"] = ev.GetTimestamp()
	} else {
		details["timestamp"] = time.Now().UTC().Format(time.RFC3339Nano)
	}

	resource := ev.GetScopeType()
	if resource == "" {
		resource = "event"
	}
	resourceID := ""
	if ev.GetTuple() != "" {
		// For tuple events the object side is the resource id.
		if i := indexByte(ev.GetTuple(), '@'); i >= 0 {
			resourceID = ev.GetTuple()[i+1:]
		}
	}

	s.auditLogger.Log(ctx, ev.GetType(), resource, resourceID, details)
	return &daemonoperatorv1.EmitAuditEventResponse{}, nil
}

// indexByte returns the first index of c in s, or -1.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// ensureTenantQuotasTable is an idempotent CREATE TABLE IF NOT EXISTS for
// deployments that haven't run the migration file
// (internal/db/migrations/2026041801_create_tenant_quotas.sql) yet. The
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
	// (ADR-0047 facet 3). ADD COLUMN IF NOT EXISTS keeps pre-existing tables
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

// SetPlatformEnabled writes or deletes the FGA platform_enabled tuple for a
// component from system_tenant:_system — the shared-catalog publish path
// (gibson#682). Only the platform operator may publish a curated connector to
// the shared catalog; the catalog fan-out then seeds tenant_enabled per
// tenant. published=false unpublishes. Idempotent in both directions.
func (s *DaemonServer) SetPlatformEnabled(ctx context.Context, req *daemonoperatorv1.SetPlatformEnabledRequest) (*daemonoperatorv1.SetPlatformEnabledResponse, error) {
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorizer not configured")
	}
	if req.GetComponentRef() == "" {
		return nil, status.Error(codes.InvalidArgument, "component_ref required")
	}
	bareName := req.GetComponentRef()
	componentRef := bareName
	if hasPrefix(componentRef, "component:") {
		bareName = componentRef[len("component:"):]
	} else {
		componentRef = "component:" + componentRef
	}
	const systemRef = "system_tenant:_system"
	tuple := authz.Tuple{User: systemRef, Relation: "platform_enabled", Object: componentRef}

	// Validate a supplied connector manifest up front (no DB needed): a shared
	// connector is an mcp-bridge plugin (ADR-0049), and SetPlatformEnabled is
	// the only point an operator-published-only connector's definition is
	// captured (gibson#733). Non-connector components publish without a manifest.
	manifestYAML := req.GetManifestYaml()
	if req.GetPublished() && len(manifestYAML) > 0 {
		m, mErr := manifest.LoadBytes(manifestYAML)
		if mErr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "manifest_yaml is not a valid plugin manifest: %v", mErr)
		}
		if m.Spec.Runtime != manifest.RuntimeMCPBridge {
			return nil, status.Errorf(codes.InvalidArgument,
				"manifest_yaml must be a runtime: %q plugin manifest (a shared connector); got runtime %q",
				manifest.RuntimeMCPBridge, m.Spec.Runtime)
		}
	}

	present, err := s.authorizer.Check(ctx, systemRef, "platform_enabled", componentRef)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check platform_enabled: %v", err)
	}
	if req.GetPublished() {
		// Persist the shared component manifest first (before the present
		// early-return) so a re-publish that only updates the definition still
		// refreshes what the on-enable reconciler launches from.
		if len(manifestYAML) > 0 {
			if perr := s.putSharedConnectorManifest(ctx, bareName, manifestYAML); perr != nil {
				return nil, status.Errorf(codes.Internal, "persist shared connector manifest: %v", perr)
			}
		}
		if present {
			return &daemonoperatorv1.SetPlatformEnabledResponse{Written: false}, nil
		}
		if err := s.authorizer.Write(ctx, []authz.Tuple{tuple}); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Write platform_enabled: %v", err)
		}
		return &daemonoperatorv1.SetPlatformEnabledResponse{Written: true}, nil
	}
	// Unpublish clears the shared manifest alongside the tuple (idempotent), so
	// a pulled connector converges to no running sandboxes.
	if derr := s.deleteSharedConnectorManifest(ctx, bareName); derr != nil {
		return nil, status.Errorf(codes.Internal, "clear shared connector manifest: %v", derr)
	}
	if !present {
		return &daemonoperatorv1.SetPlatformEnabledResponse{Deleted: false}, nil
	}
	if err := s.authorizer.Delete(ctx, []authz.Tuple{tuple}); err != nil {
		return nil, status.Errorf(codes.Internal, "fga Delete platform_enabled: %v", err)
	}
	return &daemonoperatorv1.SetPlatformEnabledResponse{Deleted: true}, nil
}

// putSharedConnectorManifest persists a shared connector's component manifest
// under the system tenant so the on-enable reconciler can launch a per-tenant
// sandbox from it (gibson#733). A daemon without a platform DB logs and skips —
// on-enable orchestration for operator-published connectors is then unavailable.
func (s *DaemonServer) putSharedConnectorManifest(ctx context.Context, connector string, manifestYAML []byte) error {
	if s.platformDB == nil {
		if s.logger != nil {
			s.logger.Warn("SetPlatformEnabled: platform DB unavailable; shared connector manifest not persisted "+
				"(it will not launch on enable)", "connector", connector)
		}
		return nil
	}
	return reconciler.NewPostgresConnectorManifestStore(s.platformDB).PutShared(ctx, connector, manifestYAML)
}

// deleteSharedConnectorManifest clears a shared connector's component manifest
// on unpublish.
func (s *DaemonServer) deleteSharedConnectorManifest(ctx context.Context, connector string) error {
	if s.platformDB == nil {
		return nil
	}
	return reconciler.NewPostgresConnectorManifestStore(s.platformDB).DeleteShared(ctx, connector)
}
