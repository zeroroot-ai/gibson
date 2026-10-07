// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_alerts.go
//
// Implements the ListAlerts, MarkAlertRead, and MarkAllAlertsRead RPC handlers
// introduced by the prod-feature-wiring spec.
//
// Alerts are stored in Redis:
//   - Sorted set "tenant:alerts:{tenantID}:{userID}" sorted by created_at (Unix).
//   - Individual alert JSON at "tenant:alert:{tenantID}:{alertID}".
//
// Authorization:
//   - Users may only access their own alerts.
//   - Tenant admins may access any user's alerts.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/pagetoken"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// alertStoreIface is the narrow interface the alert handlers use for Redis operations.
type alertStoreIface interface {
	// ListAlerts returns one page of the alerts of a user, newest first: the
	// alerts among limit index entries after the first offset entries.
	// scanned is the number of index entries the page read, so the caller can
	// tell a full page from the last one when unreadOnly drops alerts.
	ListAlerts(ctx context.Context, tenantID, userID string, unreadOnly bool, offset, limit int) (alerts []*storedAlert, scanned int, err error)
	// MarkAlertRead marks a single alert as read, but only when it belongs to
	// callerUserID — alertDataKey is addressed by (tenant, alertID) alone, an
	// id any tenant member can supply, so this ownership check (not the
	// per-user index used by ListAlerts) is what stops one member from
	// flipping another member's alert.
	MarkAlertRead(ctx context.Context, tenantID, callerUserID, alertID string) error
	MarkAllAlertsRead(ctx context.Context, tenantID, userID string) (int32, error)
}

// storedAlert is the JSON-serializable alert record persisted in Redis.
type storedAlert struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	UserID        string `json:"user_id"`
	Title         string `json:"title"`
	Body          string `json:"body"`
	Severity      string `json:"severity"`
	Read          bool   `json:"read"`
	CreatedAtUnix int64  `json:"created_at_unix"`
	Source        string `json:"source"`
	SourceID      string `json:"source_id"`
}

// redisAlertStore implements alertStoreIface using a raw Redis client.
type redisAlertStore struct {
	client goredis.UniversalClient
	logger *slog.Logger
}

const (
	// alertsDefaultPageSize is the page size of ListAlerts when page_size is 0.
	alertsDefaultPageSize = 50
	// alertsMaxPageSize is the largest page of ListAlerts.
	alertsMaxPageSize = 200
)

func alertIndexKey(tenantID, userID string) string {
	return fmt.Sprintf("tenant:alerts:%s:%s", tenantID, userID)
}

func alertDataKey(tenantID, alertID string) string {
	return fmt.Sprintf("tenant:alert:%s:%s", tenantID, alertID)
}

func (s *redisAlertStore) ListAlerts(ctx context.Context, tenantID, userID string, unreadOnly bool, offset, limit int) ([]*storedAlert, int, error) {
	if limit <= 0 {
		limit = alertsDefaultPageSize
	}
	limit = min(limit, alertsMaxPageSize)
	offset = max(offset, 0)

	// ZREVRANGE returns IDs sorted descending by score (created_at timestamp).
	alertIDs, err := s.client.ZRevRange(ctx, alertIndexKey(tenantID, userID), int64(offset), int64(offset+limit-1)).Result()
	if err == goredis.Nil || len(alertIDs) == 0 {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("alerts ZREVRANGE failed: %w", err)
	}

	alerts := make([]*storedAlert, 0, len(alertIDs))
	for _, alertID := range alertIDs {
		raw, err := s.client.Get(ctx, alertDataKey(tenantID, alertID)).Result()
		if err == goredis.Nil {
			continue // Alert data removed; skip stale index entry.
		}
		if err != nil {
			s.logger.WarnContext(ctx, "alerts: failed to fetch alert data",
				slog.String("alert_id", alertID),
				slog.String("error", err.Error()),
			)
			continue
		}
		var a storedAlert
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			continue
		}
		if unreadOnly && a.Read {
			continue
		}
		alerts = append(alerts, &a)
	}
	return alerts, len(alertIDs), nil
}

func (s *redisAlertStore) MarkAlertRead(ctx context.Context, tenantID, callerUserID, alertID string) error {
	key := alertDataKey(tenantID, alertID)
	raw, err := s.client.Get(ctx, key).Result()
	if err == goredis.Nil {
		return fmt.Errorf("alert not found")
	}
	if err != nil {
		return fmt.Errorf("alert GET failed: %w", err)
	}
	var a storedAlert
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		return fmt.Errorf("alert unmarshal failed: %w", err)
	}
	// Ownership check: alertDataKey is addressed by (tenant, alertID) alone,
	// so without this comparison any tenant member could mark any other
	// member's alert read by supplying its id.
	if a.UserID != callerUserID {
		return errors.New("alert not found")
	}
	a.Read = true
	data, err := json.Marshal(&a)
	if err != nil {
		return fmt.Errorf("alert marshal failed: %w", err)
	}
	return s.client.Set(ctx, key, string(data), 0).Err()
}

func (s *redisAlertStore) MarkAllAlertsRead(ctx context.Context, tenantID, userID string) (int32, error) {
	alertIDs, err := s.client.ZRevRange(ctx, alertIndexKey(tenantID, userID), 0, -1).Result()
	if err == goredis.Nil || len(alertIDs) == 0 {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("alerts ZREVRANGE failed: %w", err)
	}

	var count int32
	pipe := s.client.Pipeline()
	getResults := make([]*goredis.StringCmd, len(alertIDs))
	for i, alertID := range alertIDs {
		getResults[i] = pipe.Get(ctx, alertDataKey(tenantID, alertID))
	}
	if _, err := pipe.Exec(ctx); err != nil && err != goredis.Nil {
		return 0, fmt.Errorf("pipeline GET failed: %w", err)
	}

	setPipe := s.client.Pipeline()
	for i, alertID := range alertIDs {
		raw, err := getResults[i].Result()
		if err == goredis.Nil {
			continue
		}
		if err != nil {
			continue
		}
		var a storedAlert
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			continue
		}
		if a.Read {
			continue
		}
		a.Read = true
		data, err := json.Marshal(&a)
		if err != nil {
			continue
		}
		setPipe.Set(ctx, alertDataKey(tenantID, alertID), string(data), 0)
		count++
	}
	if count > 0 {
		if _, err := setPipe.Exec(ctx); err != nil {
			return 0, fmt.Errorf("pipeline SET failed: %w", err)
		}
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// ListAlerts handler
// ---------------------------------------------------------------------------

// ListAlerts returns platform alerts for a tenant user.
func (s *DaemonServer) ListAlerts(ctx context.Context, req *tenantv1.ListAlertsRequest) (*tenantv1.ListAlertsResponse, error) {
	// Scope is the authenticated caller's tenant; req.tenant_id is not read.
	// ext-authz derives this RPC's authorization object from the caller's own
	// identity, so a body tenant id is authorized by nothing.
	tenantID := auth.TenantStringFromContext(ctx)

	// Nil store: short-circuit if tenant is unavailable (graceful degradation).
	if s.alertStore == nil && tenantID == "" {
		return &tenantv1.ListAlertsResponse{Alerts: []*tenantv1.Alert{}}, nil
	}

	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Alerts are per-user; the subject is the caller, never a body field.
	userID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		userID = id.Subject
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	if s.alertStore == nil {
		return &tenantv1.ListAlertsResponse{Alerts: []*tenantv1.Alert{}}, nil
	}

	offset, limit, err := pagetoken.Window(req.GetPageSize(), req.GetPageToken())
	if err != nil {
		return nil, status_grpc.Error(codes.InvalidArgument, err.Error())
	}
	if req.GetPageSize() <= 0 {
		limit = alertsDefaultPageSize
	}
	limit = min(limit, alertsMaxPageSize)
	stored, scanned, err := s.alertStore.ListAlerts(ctx, tenantID, userID, req.GetUnreadOnly(), offset, limit)
	if err != nil {
		s.logger.ErrorContext(ctx, "ListAlerts: store read failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "alerts read failed")
	}

	alerts := make([]*tenantv1.Alert, 0, len(stored))
	for _, a := range stored {
		alerts = append(alerts, &tenantv1.Alert{
			Id:            a.ID,
			TenantId:      a.TenantID,
			UserId:        a.UserID,
			Title:         a.Title,
			Body:          a.Body,
			Severity:      a.Severity,
			Read:          a.Read,
			CreatedAtUnix: a.CreatedAtUnix,
			Source:        a.Source,
			SourceId:      a.SourceID,
		})
	}

	return &tenantv1.ListAlertsResponse{
		Alerts:        alerts,
		NextPageToken: pagetoken.Next(offset, limit, scanned, -1),
	}, nil
}

// ---------------------------------------------------------------------------
// MarkAlertRead handler
// ---------------------------------------------------------------------------

// MarkAlertRead marks a single alert as read, scoped to the caller: alertID
// is caller-supplied and addressed by (tenant, alertID) alone, so the store
// compares it against the alert's own stored user_id before writing —
// otherwise any tenant member could mark any other member's alert read.
func (s *DaemonServer) MarkAlertRead(ctx context.Context, req *tenantv1.MarkAlertReadRequest) (*tenantv1.MarkAlertReadResponse, error) {
	// Scope is the authenticated caller's tenant; req.tenant_id is not read.
	// ext-authz derives this RPC's authorization object from the caller's own
	// identity, so a body tenant id is authorized by nothing.
	tenantID := auth.TenantStringFromContext(ctx)

	// Nil store: short-circuit if tenant is unavailable (no-op).
	if s.alertStore == nil && tenantID == "" {
		return &tenantv1.MarkAlertReadResponse{}, nil
	}

	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.GetAlertId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "alert_id is required")
	}

	// Alerts are per-user; the subject is the caller, never a body field.
	userID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		userID = id.Subject
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	if s.alertStore == nil {
		return &tenantv1.MarkAlertReadResponse{}, nil
	}

	if err := s.alertStore.MarkAlertRead(ctx, tenantID, userID, req.GetAlertId()); err != nil {
		s.logger.WarnContext(ctx, "MarkAlertRead: store update failed",
			slog.String("tenant_id", tenantID),
			slog.String("alert_id", req.GetAlertId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "mark read failed")
	}

	return &tenantv1.MarkAlertReadResponse{}, nil
}

// ---------------------------------------------------------------------------
// MarkAllAlertsRead handler
// ---------------------------------------------------------------------------

// MarkAllAlertsRead marks all alerts for a user as read.
func (s *DaemonServer) MarkAllAlertsRead(ctx context.Context, req *tenantv1.MarkAllAlertsReadRequest) (*tenantv1.MarkAllAlertsReadResponse, error) {
	// Scope is the authenticated caller's tenant; req.tenant_id is not read.
	// ext-authz derives this RPC's authorization object from the caller's own
	// identity, so a body tenant id is authorized by nothing.
	tenantID := auth.TenantStringFromContext(ctx)

	// Nil store: short-circuit if tenant is unavailable (no-op).
	if s.alertStore == nil && tenantID == "" {
		return &tenantv1.MarkAllAlertsReadResponse{Count: 0}, nil
	}

	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Alerts are per-user; the subject is the caller, never a body field.
	userID := ""
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		userID = id.Subject
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	if s.alertStore == nil {
		return &tenantv1.MarkAllAlertsReadResponse{Count: 0}, nil
	}

	count, err := s.alertStore.MarkAllAlertsRead(ctx, tenantID, userID)
	if err != nil {
		s.logger.ErrorContext(ctx, "MarkAllAlertsRead: store update failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "mark all read failed")
	}

	return &tenantv1.MarkAllAlertsReadResponse{Count: count}, nil
}
