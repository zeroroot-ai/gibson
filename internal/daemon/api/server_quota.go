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
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	platformv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/platform/v1"
	tenantv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
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
func (s *DaemonServer) GetTenantQuota(ctx context.Context, req *tenantv1.GetTenantQuotaRequest) (*tenantv1.GetTenantQuotaResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}

	// Nil store: return Unavailable regardless of tenant validation.
	if s.quotaStore == nil {
		return nil, status_grpc.Error(codes.Unavailable, "quota store not configured")
	}

	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}

	q, err := s.quotaStore.GetQuota(ctx, tenantID)
	if err != nil {
		s.logger.ErrorContext(ctx, "GetTenantQuota: store read failed",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "quota read failed")
	}

	resp := &tenantv1.GetTenantQuotaResponse{
		Quota: &tenantv1.TenantQuota{
			MaxMissions: q.MaxMissions,
			MaxAgents:   q.MaxAgents,
			MaxFindings: q.MaxFindings,
			PlanTier:    q.PlanTier,
		},
	}

	// Plan-based limits from Postgres tenant_quotas. The dashboard Postgres
	// is optional in dev; when absent we leave the extended fields at zero
	// rather than failing the RPC.
	if db := s.platformDB; db != nil {
		limits, err := readTenantQuotasRow(ctx, db, tenantID)
		if err != nil {
			s.logger.WarnContext(ctx, "GetTenantQuota: postgres read failed (continuing with zero limits)",
				slog.String("tenant_id", tenantID),
				slog.String("error", err.Error()),
			)
		} else if limits != nil {
			resp.Seats = limits.seats
			resp.ConcurrentAgents = limits.concurrentAgents
			resp.StorageGb = limits.storageGb
			resp.RetentionDays = limits.retentionDays
			resp.SandboxLaunchesPerMonth = limits.sandboxLaunchesPerMonth
			resp.UpdatedAt = limits.updatedAt
		}
	}

	// Usage snapshot from Redis counters. Missing counters are treated as
	// zero; callers render "0 / limit" in that case.
	if usage := s.readTenantUsageSnapshot(ctx, tenantID); usage != nil {
		resp.CurrentSeats = usage.currentSeats
		resp.CurrentConcurrentAgents = usage.currentConcurrentAgents
		resp.CurrentStorageGb = usage.currentStorageGb
		resp.CurrentSandboxLaunchesThisMonth = usage.currentSandboxLaunchesThisMonth
	}

	return resp, nil
}

type tenantQuotaRow struct {
	seats                   int32
	concurrentAgents        int32
	storageGb               int32
	retentionDays           int32
	sandboxLaunchesPerMonth int32
	updatedAt               string
}

func readTenantQuotasRow(ctx context.Context, db *sql.DB, tenantID string) (*tenantQuotaRow, error) {
	const q = `
		SELECT seats, concurrent_agents, storage_gb, retention_days,
			sandbox_launches_per_month, updated_at
		FROM tenant_quotas
		WHERE tenant_id = $1
	`
	var r tenantQuotaRow
	var updatedAt time.Time
	err := db.QueryRowContext(ctx, q, tenantID).Scan(
		&r.seats, &r.concurrentAgents, &r.storageGb, &r.retentionDays,
		&r.sandboxLaunchesPerMonth, &updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.updatedAt = updatedAt.UTC().Format(time.RFC3339Nano)
	return &r, nil
}

type tenantUsageSnapshot struct {
	currentSeats                    int32
	currentConcurrentAgents         int32
	currentStorageGb                int32
	currentSandboxLaunchesThisMonth int32
}

// tenantUsageReader is a narrow interface injected via WithTenantUsageReader.
// Implementations read live usage counters (Redis keys owned by the quota
// manager). A nil reader degrades silently to zero-valued usage so
// dashboards continue to render a valid Plan & Usage section for brand-new
// tenants.
type tenantUsageReader interface {
	ReadTenantUsage(ctx context.Context, tenantID string) (seats, concurrentAgents, storageGb, sandboxLaunchesThisMonth int32, err error)
}

// redisTenantUsageReader implements tenantUsageReader over a raw Redis client
// using the `tenant:usage:<id>:<metric>` key convention. Missing keys return
// zero without error.
type redisTenantUsageReader struct {
	client goredis.UniversalClient
}

// NewRedisTenantUsageReader builds a tenantUsageReader backed by the given
// Redis client.
func NewRedisTenantUsageReader(client goredis.UniversalClient) *redisTenantUsageReader {
	return &redisTenantUsageReader{client: client}
}

func (r *redisTenantUsageReader) ReadTenantUsage(ctx context.Context, tenantID string) (int32, int32, int32, int32, error) {
	read := func(metric string) int32 {
		v, err := r.client.Get(ctx, fmt.Sprintf("tenant:usage:%s:%s", tenantID, metric)).Int()
		if err != nil {
			return 0
		}
		return int32(v)
	}
	return read("seats"), read("concurrent_agents"), read("storage_gb"), read("sandbox_launches_month"), nil
}

// readTenantUsageSnapshot pulls the four per-tenant usage counters through
// the injected reader. Missing reader or missing counters degrade to zero.
func (s *DaemonServer) readTenantUsageSnapshot(ctx context.Context, tenantID string) *tenantUsageSnapshot {
	if s.tenantUsage == nil {
		return nil
	}
	seats, concurrent, storage, sandbox, err := s.tenantUsage.ReadTenantUsage(ctx, tenantID)
	if err != nil {
		s.logger.WarnContext(ctx, "GetTenantQuota: usage read failed (treating as zero)",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
		return nil
	}
	return &tenantUsageSnapshot{
		currentSeats:                    seats,
		currentConcurrentAgents:         concurrent,
		currentStorageGb:                storage,
		currentSandboxLaunchesThisMonth: sandbox,
	}
}

// ---------------------------------------------------------------------------
// SetTenantQuota handler
// ---------------------------------------------------------------------------

// SetTenantQuota sets the quota configuration for a tenant.
func (s *DaemonServer) SetTenantQuota(ctx context.Context, req *platformv1.SetTenantQuotaRequest) (*platformv1.SetTenantQuotaResponse, error) {
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

	return &platformv1.SetTenantQuotaResponse{
		Quota: &platformv1.TenantQuota{
			MaxMissions: q.MaxMissions,
			MaxAgents:   q.MaxAgents,
			MaxFindings: q.MaxFindings,
			PlanTier:    q.PlanTier,
		},
	}, nil
}
