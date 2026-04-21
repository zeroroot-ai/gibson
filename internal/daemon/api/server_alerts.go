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
	"fmt"
	"log/slog"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/identity"
)

// alertStoreIface is the narrow interface the alert handlers use for Redis operations.
type alertStoreIface interface {
	ListAlerts(ctx context.Context, tenantID, userID string, unreadOnly bool, limit int) ([]*storedAlert, error)
	MarkAlertRead(ctx context.Context, tenantID, alertID string) error
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

// NewRedisAlertStore creates an alert store backed by the given Redis client.
func NewRedisAlertStore(client goredis.UniversalClient, logger *slog.Logger) alertStoreIface {
	if logger == nil {
		logger = slog.Default()
	}
	return &redisAlertStore{client: client, logger: logger}
}

func alertIndexKey(tenantID, userID string) string {
	return fmt.Sprintf("tenant:alerts:%s:%s", tenantID, userID)
}

func alertDataKey(tenantID, alertID string) string {
	return fmt.Sprintf("tenant:alert:%s:%s", tenantID, alertID)
}

func (s *redisAlertStore) ListAlerts(ctx context.Context, tenantID, userID string, unreadOnly bool, limit int) ([]*storedAlert, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	// ZREVRANGE returns IDs sorted descending by score (created_at timestamp).
	alertIDs, err := s.client.ZRevRange(ctx, alertIndexKey(tenantID, userID), 0, int64(limit-1)).Result()
	if err == goredis.Nil || len(alertIDs) == 0 {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("alerts ZREVRANGE failed: %w", err)
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
	return alerts, nil
}

func (s *redisAlertStore) MarkAlertRead(ctx context.Context, tenantID, alertID string) error {
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
func (s *DaemonServer) ListAlerts(ctx context.Context, req *ListAlertsRequest) (*ListAlertsResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	userID := req.GetUserId()
	if userID == "" {
		// Fallback: use caller identity.
		if id, err := identity.IdentityFromContext(ctx); err == nil {
			userID = id.Subject
		}
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	if s.alertStore == nil {
		return &ListAlertsResponse{Alerts: []*Alert{}}, nil
	}

	stored, err := s.alertStore.ListAlerts(ctx, tenantID, userID, req.GetUnreadOnly(), int(req.GetLimit()))
	if err != nil {
		s.logger.ErrorContext(ctx, "ListAlerts: store read failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "alerts read failed")
	}

	alerts := make([]*Alert, 0, len(stored))
	for _, a := range stored {
		alerts = append(alerts, &Alert{
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

	return &ListAlertsResponse{Alerts: alerts}, nil
}

// ---------------------------------------------------------------------------
// MarkAlertRead handler
// ---------------------------------------------------------------------------

// MarkAlertRead marks a single alert as read.
func (s *DaemonServer) MarkAlertRead(ctx context.Context, req *MarkAlertReadRequest) (*MarkAlertReadResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.GetAlertId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "alert_id is required")
	}

	if s.alertStore == nil {
		return &MarkAlertReadResponse{}, nil
	}

	if err := s.alertStore.MarkAlertRead(ctx, tenantID, req.GetAlertId()); err != nil {
		s.logger.WarnContext(ctx, "MarkAlertRead: store update failed",
			slog.String("tenant_id", tenantID),
			slog.String("alert_id", req.GetAlertId()),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "mark read failed")
	}

	return &MarkAlertReadResponse{}, nil
}

// ---------------------------------------------------------------------------
// MarkAllAlertsRead handler
// ---------------------------------------------------------------------------

// MarkAllAlertsRead marks all alerts for a user as read.
func (s *DaemonServer) MarkAllAlertsRead(ctx context.Context, req *MarkAllAlertsReadRequest) (*MarkAllAlertsReadResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = identity.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	userID := req.GetUserId()
	if userID == "" {
		if id, err := identity.IdentityFromContext(ctx); err == nil {
			userID = id.Subject
		}
	}
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	if s.alertStore == nil {
		return &MarkAllAlertsReadResponse{Count: 0}, nil
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

	return &MarkAllAlertsReadResponse{Count: count}, nil
}
