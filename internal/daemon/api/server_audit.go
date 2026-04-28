// Package api — server_audit.go
//
// This file implements the audit log and batch grant RPC handlers:
//
//   - ListAuditEvents — queries the Redis audit stream (with optional Loki fallthrough)
//   - BatchGrantComponentAccess — bulk grant/revoke in a single RPC
//
// Authorization: both RPCs require FGA admin relation on the tenant.
//
// Error mapping follows the existing convention in server_admin.go:
//
//	FGA check failure  → codes.Internal (non-fatal: returns empty result)
//	caller not admin   → codes.PermissionDenied
//	invalid args       → codes.InvalidArgument
//	Loki unavailable   → codes.Unavailable (with informative message)
//	everything else    → codes.Internal
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/audit"
	tenantv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// DaemonServer field additions (wired via methods below)
// ---------------------------------------------------------------------------

// Note: these fields are declared here as doc pointers; the actual struct
// fields are added via the embedded approach — we extend the DaemonServer
// struct directly in the With* methods below.
//
// To avoid circular dependency the audit package is imported here, not in
// server.go which is already large.

// auditLoggerField is kept in DaemonServer; wired via WithAuditLogger.
// We declare the field by extending the DaemonServer struct at the bottom
// of this file via a pattern-compatible approach: since Go doesn't support
// partial struct declarations, we add the fields to server.go instead.
// See the NOTE below.
//
// NOTE: The fields `auditLogger` and `lokiQuerier` are declared in the
// DaemonServer struct in server.go, matching the pattern of `grantHandler`
// and `teamHandler`.

// ---------------------------------------------------------------------------
// Wiring helpers
// ---------------------------------------------------------------------------

// WithAuditLogger wires the Redis-backed AuditLogger into DaemonServer.
func (s *DaemonServer) WithAuditLogger(al *audit.AuditLogger) *DaemonServer {
	s.auditLogger = al
	return s
}

// WithLokiQuerier wires an optional LokiQuerier for audit event queries.
// When wired, ListAuditEvents queries Loki first; on ErrLokiUnavailable it
// falls back to the Redis audit stream via auditLogger.
func (s *DaemonServer) WithLokiQuerier(lq audit.LokiQuerier) *DaemonServer {
	s.lokiQuerier = lq
	return s
}

// ---------------------------------------------------------------------------
// ListAuditEvents handler
// ---------------------------------------------------------------------------

// ListAuditEvents returns audit events for a tenant.
//
// Authorization: caller must have FGA admin relation on the tenant.
// Data source: Loki (if wired) → Redis audit stream (fallback).
// Pagination: cursor = stream entry ID or Loki nanosecond timestamp.
func (s *DaemonServer) ListAuditEvents(ctx context.Context, req *tenantv1.ListAuditEventsRequest) (*tenantv1.ListAuditEventsResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Authorize: caller must be tenant admin.
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}

	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	// Parse time bounds.
	var fromTime, toTime time.Time
	if raw := req.GetFromTime(); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			fromTime = t
		}
	}
	if raw := req.GetToTime(); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			toTime = t
		}
	}

	filter := audit.AuditFilter{
		TenantID:    tenantID,
		EventTypes:  req.GetEventTypes(),
		ActorUserID: req.GetActorUserId(),
		TargetMatch: req.GetTargetMatch(),
		FromTime:    fromTime,
		ToTime:      toTime,
		Limit:       limit,
		Cursor:      req.GetCursor(),
	}

	// Try Loki first if wired.
	if s.lokiQuerier != nil {
		entries, nextCursor, err := s.lokiQuerier.QueryAuditEvents(ctx, filter)
		if err == nil {
			return s.auditEntriesToResponse(entries, nextCursor), nil
		}
		if !errors.Is(err, audit.ErrLokiUnavailable) {
			// Unexpected error — do not leak internals.
			s.logger.ErrorContext(ctx, "ListAuditEvents: Loki query failed",
				slog.String("tenant_id", tenantID),
				slog.String("error", err.Error()),
			)
			return nil, status_grpc.Error(codes.Internal, "audit query failed")
		}
		// ErrLokiUnavailable — fall through to Redis.
		s.logger.WarnContext(ctx, "ListAuditEvents: Loki unavailable, falling back to Redis audit stream",
			slog.String("tenant_id", tenantID),
		)
	}

	// Fallback: Redis audit stream.
	if s.auditLogger == nil {
		return nil, status_grpc.Error(codes.Unavailable, "audit log temporarily unavailable")
	}

	opts := audit.AuditQueryOptions{
		StartTime: fromTime,
		EndTime:   toTime,
		Limit:     limit,
	}
	if len(filter.EventTypes) > 0 {
		opts.Action = filter.EventTypes[0] // Redis stream filters by action prefix
	}
	if filter.ActorUserID != "" {
		opts.ActorID = filter.ActorUserID
	}

	entries, err := s.auditLogger.Query(ctx, tenantID, opts)
	if err != nil {
		s.logger.ErrorContext(ctx, "ListAuditEvents: Redis audit query failed",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "audit query failed")
	}

	// Redis audit stream doesn't support cursor pagination natively;
	// return empty cursor for now.
	return s.auditEntriesToResponse(entries, ""), nil
}

// auditEntriesToResponse converts AuditEntry slice to the proto response.
func (s *DaemonServer) auditEntriesToResponse(entries []audit.AuditEntry, nextCursor string) *tenantv1.ListAuditEventsResponse {
	events := make([]*tenantv1.AuditEvent, 0, len(entries))
	for _, e := range entries {
		// Convert Details map[string]any to map[string]string.
		details := make(map[string]string, len(e.Details))
		for k, v := range e.Details {
			details[k] = fmt.Sprintf("%v", v)
		}

		events = append(events, &tenantv1.AuditEvent{
			EventType:      e.Action,
			Timestamp:      e.Timestamp.Format(time.RFC3339),
			ActorUserId:    e.ActorID,
			ActorEmail:     e.ActorEmail,
			TenantId:       e.TenantID,
			TargetResource: e.ResourceID,
			Details:        details,
			TraceId:        e.ID,
		})
	}
	return &tenantv1.ListAuditEventsResponse{
		Events:     events,
		NextCursor: nextCursor,
	}
}

// ---------------------------------------------------------------------------
// BatchGrantComponentAccess has been removed along with the provisioner
// package. The proto RPC falls through to the Unimplemented* stub.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Authorization helper
// ---------------------------------------------------------------------------

// requireTenantAdmin checks that the caller (extracted from ctx) has FGA
// admin relation on the tenant.  Returns a gRPC status error on failure.
func (s *DaemonServer) requireTenantAdmin(ctx context.Context, tenantID string) error {
	if s.authorizer == nil {
		// When authz is disabled (noopAuthorizer not wired), allow through.
		// The FGA interceptor handles enforcement when enabled.
		return nil
	}

	id, idErr := auth.IdentityFromContext(ctx)
	if idErr != nil || id.Subject == "" {
		// Structured log (spec dashboard-admin-via-envoy, Req 8 criterion 3)
		// so operators can grep `admin_rpc_denied` for any unauthenticated
		// admin-path reject. No bearer tokens or claim payloads appear here —
		// only the extracted subject (empty when anonymous) + the reason.
		s.logger.InfoContext(ctx, "admin_rpc_denied",
			slog.String("reason", "unauthenticated"),
			slog.String("tenant_id", tenantID),
			slog.String("subject", ""),
		)
		return status_grpc.Error(codes.Unauthenticated, "authentication required")
	}

	isAdmin, err := s.authorizer.Check(ctx,
		fmt.Sprintf("user:%s", id.Subject),
		"admin",
		fmt.Sprintf("tenant:%s", tenantID),
	)
	if err != nil {
		s.logger.ErrorContext(ctx, "requireTenantAdmin: FGA check failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", id.Subject),
			slog.String("error", err.Error()),
		)
		return status_grpc.Error(codes.Internal, "authorization check failed")
	}
	if !isAdmin {
		s.logger.InfoContext(ctx, "admin_rpc_denied",
			slog.String("reason", "not_tenant_admin"),
			slog.String("tenant_id", tenantID),
			slog.String("subject", id.Subject),
			slog.String("relation", "admin"),
		)
		return status_grpc.Error(codes.PermissionDenied, "tenant admin required")
	}
	return nil
}
