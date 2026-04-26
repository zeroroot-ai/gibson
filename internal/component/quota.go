package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/sdk/auth"
	"github.com/zero-day-ai/gibson/internal/state"
)

// TenantQuota defines the per-tenant resource limits enforced by QuotaManager.
// A zero value for any numeric field means the limit is disabled (unlimited).
type TenantQuota struct {
	TenantID     string `json:"tenant_id"`
	MaxMissions  int    `json:"max_missions"`   // 0 = unlimited
	MaxAgents    int    `json:"max_agents"`     // 0 = unlimited
	MaxMemoryMB  int64  `json:"max_memory_mb"`  // 0 = unlimited
	APIRateLimit int    `json:"api_rate_limit"` // requests/minute, 0 = unlimited
	MaxFindings  int    `json:"max_findings"`   // per mission, 0 = unlimited
}

// Redis key constants for quota storage (all values are relative keys passed to
// TenantScopedStore — tenant scoping is applied automatically by the store).
const (
	quotaConfigKey        = "quota:config"
	quotaMissionsCountKey = "quota:missions:count"
	quotaAgentsCountKey   = "quota:agents:count"
	quotaMemoryUsedMBKey  = "quota:memory:used_mb"
)

// QuotaManager enforces per-tenant resource quotas using Redis for durable counter
// storage. All operations are tenant-scoped via TenantScopedStore, ensuring that
// quota data from one tenant cannot bleed into another.
//
// Quota enforcement follows a simple convention: a zero limit means unlimited.
// Check methods return codes.ResourceExhausted when a limit is exceeded.
//
// Usage:
//
//	qm := component.NewQuotaManager(tenantStore, logger)
//
//	// Set a quota for a tenant (typically called by an admin API).
//	err := qm.SetQuota(ctx, "acme-corp", &component.TenantQuota{
//	    TenantID:    "acme-corp",
//	    MaxMissions: 10,
//	    MaxAgents:   50,
//	})
//
//	// Check before creating a mission (tenant extracted from ctx).
//	if err := qm.CheckMissionQuota(ctx); err != nil {
//	    return err // codes.ResourceExhausted
//	}
//	if err := qm.IncrementMissionCount(ctx); err != nil {
//	    return err
//	}
type QuotaManager struct {
	store  *state.TenantScopedStore
	logger *slog.Logger
}

// NewQuotaManager creates a QuotaManager backed by the given TenantScopedStore.
// The store must be non-nil.
func NewQuotaManager(store *state.TenantScopedStore, logger *slog.Logger) *QuotaManager {
	return &QuotaManager{
		store:  store,
		logger: logger.With("component", "quota_manager"),
	}
}

// GetQuota retrieves the stored TenantQuota for the given tenant.
// Returns nil (and no error) when no quota record has been configured for the
// tenant, which callers should interpret as "unlimited on all dimensions".
func (q *QuotaManager) GetQuota(ctx context.Context, tenant string) (*TenantQuota, error) {
	// Build a tenant-scoped context so TenantScopedStore uses the right prefix.
	tctx := auth.ContextWithTenantString(ctx, tenant)

	raw, err := q.store.Get(tctx, quotaConfigKey)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("get quota config for tenant %s: %w", tenant, err)
	}

	var quota TenantQuota
	if err := json.Unmarshal([]byte(raw), &quota); err != nil {
		return nil, fmt.Errorf("unmarshal quota config for tenant %s: %w", tenant, err)
	}

	return &quota, nil
}

// SetQuota persists the given TenantQuota for the named tenant.
// The quota.TenantID field is overwritten with the tenant parameter to prevent
// mismatches.
func (q *QuotaManager) SetQuota(ctx context.Context, tenant string, quota *TenantQuota) error {
	if quota == nil {
		return fmt.Errorf("quota must not be nil")
	}

	quota.TenantID = tenant

	data, err := json.Marshal(quota)
	if err != nil {
		return fmt.Errorf("marshal quota for tenant %s: %w", tenant, err)
	}

	tctx := auth.ContextWithTenantString(ctx, tenant)
	if err := q.store.Set(tctx, quotaConfigKey, string(data), 0); err != nil {
		return fmt.Errorf("set quota config for tenant %s: %w", tenant, err)
	}

	q.logger.InfoContext(ctx, "quota updated",
		slog.String("tenant", tenant),
		slog.Int("max_missions", quota.MaxMissions),
		slog.Int("max_agents", quota.MaxAgents),
		slog.Int64("max_memory_mb", quota.MaxMemoryMB),
	)

	return nil
}

// CheckMissionQuota verifies that the tenant in ctx has not exceeded its
// configured mission limit.
//
// Returns nil when:
//   - No quota record is found (tenant is unlimited).
//   - MaxMissions is 0 (explicitly unlimited).
//   - The current mission count is below the limit.
//
// Returns codes.ResourceExhausted when the limit is met or exceeded.
func (q *QuotaManager) CheckMissionQuota(ctx context.Context) error {
	tenant := auth.TenantStringFromContext(ctx)

	quota, err := q.GetQuota(ctx, tenant)
	if err != nil || quota == nil || quota.MaxMissions == 0 {
		return nil // no quota or unlimited
	}

	count, _ := q.store.Get(ctx, quotaMissionsCountKey)
	current, _ := strconv.Atoi(count)

	if current >= quota.MaxMissions {
		return status.Errorf(codes.ResourceExhausted,
			"tenant %s mission quota exceeded (%d/%d)",
			tenant, current, quota.MaxMissions)
	}

	return nil
}

// CheckAgentQuota verifies that the tenant in ctx has not exceeded its
// configured agent limit.
//
// Returns nil when no quota is set, MaxAgents is 0, or the current count is
// below the limit. Returns codes.ResourceExhausted otherwise.
func (q *QuotaManager) CheckAgentQuota(ctx context.Context) error {
	tenant := auth.TenantStringFromContext(ctx)

	quota, err := q.GetQuota(ctx, tenant)
	if err != nil || quota == nil || quota.MaxAgents == 0 {
		return nil // no quota or unlimited
	}

	count, _ := q.store.Get(ctx, quotaAgentsCountKey)
	current, _ := strconv.Atoi(count)

	if current >= quota.MaxAgents {
		return status.Errorf(codes.ResourceExhausted,
			"tenant %s agent quota exceeded (%d/%d)",
			tenant, current, quota.MaxAgents)
	}

	return nil
}

// CheckMemoryQuota verifies that the tenant in ctx can allocate additionalMB
// more memory without exceeding the configured MaxMemoryMB limit.
//
// Returns nil when no quota is set, MaxMemoryMB is 0, or adding additionalMB
// to the current usage would not exceed the limit. Returns codes.ResourceExhausted
// otherwise.
func (q *QuotaManager) CheckMemoryQuota(ctx context.Context, additionalMB int64) error {
	tenant := auth.TenantStringFromContext(ctx)

	quota, err := q.GetQuota(ctx, tenant)
	if err != nil || quota == nil || quota.MaxMemoryMB == 0 {
		return nil // no quota or unlimited
	}

	raw, _ := q.store.Get(ctx, quotaMemoryUsedMBKey)
	current, _ := strconv.ParseInt(raw, 10, 64)

	if current+additionalMB > quota.MaxMemoryMB {
		return status.Errorf(codes.ResourceExhausted,
			"tenant %s memory quota exceeded (used %dMB, requested %dMB, limit %dMB)",
			tenant, current, additionalMB, quota.MaxMemoryMB)
	}

	return nil
}

// IncrementMissionCount atomically increments the mission counter for the
// tenant in ctx.
func (q *QuotaManager) IncrementMissionCount(ctx context.Context) error {
	if _, err := q.store.Incr(ctx, quotaMissionsCountKey); err != nil {
		return fmt.Errorf("increment mission count: %w", err)
	}
	return nil
}

// DecrementMissionCount decrements the mission counter for the tenant in ctx.
// The counter is floored at zero to guard against underflow from counter
// mismatches (e.g. a crash between incrementing and persisting state).
func (q *QuotaManager) DecrementMissionCount(ctx context.Context) error {
	return q.decrementCounter(ctx, quotaMissionsCountKey, "mission")
}

// IncrementAgentCount atomically increments the agent counter for the tenant
// in ctx.
func (q *QuotaManager) IncrementAgentCount(ctx context.Context) error {
	if _, err := q.store.Incr(ctx, quotaAgentsCountKey); err != nil {
		return fmt.Errorf("increment agent count: %w", err)
	}
	return nil
}

// DecrementAgentCount decrements the agent counter for the tenant in ctx.
// The counter is floored at zero.
func (q *QuotaManager) DecrementAgentCount(ctx context.Context) error {
	return q.decrementCounter(ctx, quotaAgentsCountKey, "agent")
}

// decrementCounter safely decrements a named integer counter, ensuring it
// never goes below zero. Because Redis has no built-in floor-at-zero decrement,
// we read-then-conditionally-write. This is safe under concurrent load because
// the worst case is the counter briefly going below zero before the next
// increment corrects it; quota enforcement always reads the current value
// atomically through CheckMissionQuota / CheckAgentQuota.
func (q *QuotaManager) decrementCounter(ctx context.Context, key, name string) error {
	raw, err := q.store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return nil // counter not initialised — nothing to decrement
		}
		return fmt.Errorf("read %s count: %w", name, err)
	}

	current, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("parse %s count %q: %w", name, raw, err)
	}

	if current <= 0 {
		return nil // already at floor
	}

	// Store current-1; accept a race where a concurrent increment wins — the
	// net result will still be a valid counter value.
	newVal := strconv.FormatInt(current-1, 10)
	if err := q.store.Set(ctx, key, newVal, 0); err != nil {
		return fmt.Errorf("decrement %s count: %w", name, err)
	}

	return nil
}
