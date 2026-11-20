// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

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

	s.logger.Info("WriteAccessTuples",
		"added", len(adds), "deleted", len(dels), "reason", req.GetReason())
	return &daemonoperatorv1.WriteAccessTuplesResponse{Added: int32(len(adds)), Deleted: int32(len(dels))}, nil
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

// auditResultSuccess is the result of the first record of a change.
const auditResultSuccess = "success"

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
	// A platform change (the platform operator) belongs to the system tenant.
	tenant := auth.SystemTenant
	if ev.GetTenantId() != auth.SystemTenantString {
		t, err := auth.NewTenantID(ev.GetTenantId())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "tenant_id: %v", err)
		}
		tenant = t
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
	// Each record is durable before the RPC answers, a failure record too.
	// The caller learns when its audit record is lost, and the operator
	// keeps its pending record until then (gibson#676).
	result := auditResultSuccess
	if ev.GetResult() == auditResultFailure {
		result = auditResultFailure
	}
	if _, err := s.auditLogger.RecordWithResult(ctx, ev.GetType(), ev.GetTargetType(), ev.GetTargetId(), result, details); err != nil {
		s.logger.ErrorContext(ctx, "EmitAuditEvent: durable write failed", "error", err.Error())
		return nil, status.Error(codes.Unavailable, "the audit record could not be written; try again")
	}
	return &daemonoperatorv1.EmitAuditEventResponse{}, nil
}
