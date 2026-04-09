// Package api — server_quota.go
//
// Implements the GetTenantQuota and SetTenantQuota RPC handlers introduced by
// the prod-feature-wiring spec.  Quota configuration is stored as JSON in Redis
// under the key "tenant:quota:{tenantID}".
//
// Authorization:
//   - GetTenantQuota requires FGA admin relation on the tenant.
//   - SetTenantQuota requires FGA admin relation on the tenant.
//
// Error conventions follow server_audit.go.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
)

// quotaStoreIface is the narrow Redis interface used by the quota handlers.
// This allows tests to inject a mock without spinning up Redis.
type quotaStoreIface interface {
	GetQuota(ctx context.Context, tenantID string) (*storedQuota, error)
	SetQuota(ctx context.Context, tenantID string, q *storedQuota) error
}

// storedQuota is the JSON-serializable quota record persisted in Redis.
type storedQuota struct {
	MaxMissions int32  `json:"max_missions"`
	MaxAgents   int32  `json:"max_agents"`
	MaxFindings int64  `json:"max_findings"`
	PlanTier    string `json:"plan_tier"`
}

// redisQuotaStore implements quotaStoreIface using a raw Redis client.
type redisQuotaStore struct {
	client goredis.UniversalClient
	logger *slog.Logger
}

// NewRedisQuotaStore creates a quota store backed by the given Redis client.
func NewRedisQuotaStore(client goredis.UniversalClient, logger *slog.Logger) quotaStoreIface {
	if logger == nil {
		logger = slog.Default()
	}
	return &redisQuotaStore{client: client, logger: logger}
}

func quotaKey(tenantID string) string {
	return fmt.Sprintf("tenant:quota:%s", tenantID)
}

func (s *redisQuotaStore) GetQuota(ctx context.Context, tenantID string) (*storedQuota, error) {
	raw, err := s.client.Get(ctx, quotaKey(tenantID)).Result()
	if err == goredis.Nil {
		// No quota stored — return zero values (no limits set).
		return &storedQuota{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("quota GET failed: %w", err)
	}
	var q storedQuota
	if err := json.Unmarshal([]byte(raw), &q); err != nil {
		return nil, fmt.Errorf("quota unmarshal failed: %w", err)
	}
	return &q, nil
}

func (s *redisQuotaStore) SetQuota(ctx context.Context, tenantID string, q *storedQuota) error {
	data, err := json.Marshal(q)
	if err != nil {
		return fmt.Errorf("quota marshal failed: %w", err)
	}
	if err := s.client.Set(ctx, quotaKey(tenantID), string(data), 0).Err(); err != nil {
		return fmt.Errorf("quota SET failed: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// GetTenantQuota handler
// ---------------------------------------------------------------------------

// GetTenantQuota retrieves the quota configuration for a tenant.
func (s *DaemonServer) GetTenantQuota(ctx context.Context, req *GetTenantQuotaRequest) (*GetTenantQuotaResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}

	if s.quotaStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "quota store not configured")
	}

	q, err := s.quotaStore.GetQuota(ctx, tenantID)
	if err != nil {
		s.logger.ErrorContext(ctx, "GetTenantQuota: store read failed",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "quota read failed")
	}

	return &GetTenantQuotaResponse{
		Quota: &TenantQuota{
			MaxMissions: q.MaxMissions,
			MaxAgents:   q.MaxAgents,
			MaxFindings: q.MaxFindings,
			PlanTier:    q.PlanTier,
		},
	}, nil
}

// ---------------------------------------------------------------------------
// SetTenantQuota handler
// ---------------------------------------------------------------------------

// SetTenantQuota sets the quota configuration for a tenant.
func (s *DaemonServer) SetTenantQuota(ctx context.Context, req *SetTenantQuotaRequest) (*SetTenantQuotaResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if req.GetQuota() == nil {
		return nil, status_grpc.Error(codes.InvalidArgument, "quota is required")
	}

	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}

	if s.quotaStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "quota store not configured")
	}

	q := &storedQuota{
		MaxMissions: req.GetQuota().GetMaxMissions(),
		MaxAgents:   req.GetQuota().GetMaxAgents(),
		MaxFindings: req.GetQuota().GetMaxFindings(),
		PlanTier:    req.GetQuota().GetPlanTier(),
	}

	if err := s.quotaStore.SetQuota(ctx, tenantID, q); err != nil {
		s.logger.ErrorContext(ctx, "SetTenantQuota: store write failed",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "quota write failed")
	}

	s.logger.InfoContext(ctx, "tenant quota updated",
		slog.String("tenant_id", tenantID),
		slog.String("plan_tier", q.PlanTier),
		slog.Int("max_missions", int(q.MaxMissions)),
	)

	return &SetTenantQuotaResponse{
		Quota: &TenantQuota{
			MaxMissions: q.MaxMissions,
			MaxAgents:   q.MaxAgents,
			MaxFindings: q.MaxFindings,
			PlanTier:    q.PlanTier,
		},
	}, nil
}
