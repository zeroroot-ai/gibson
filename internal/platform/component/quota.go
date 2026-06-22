package component

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/billing/entitlements"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/sdk/auth"
)

// TenantQuota defines the per-tenant resource limits enforced by QuotaManager.
// A zero value for any numeric field means the limit is disabled (unlimited).
//
// Spec plans-and-quotas-simplification reduces enforcement to two quotas:
// concurrent_missions and concurrent_agents. The "concurrent" semantics are
// strict: missions count while in non-terminal execution state, agents count
// only while bound to an in-flight task (idle agents do not count).
type TenantQuota struct {
	TenantID           string `json:"tenant_id"`
	ConcurrentMissions int    `json:"concurrent_missions"`
	ConcurrentAgents   int    `json:"concurrent_agents"`
	// ConcurrentConnectors caps the hosted MCP connector instances a tenant
	// may have running at once (ADR-0047 facet 3). 0 = unlimited. Unlike the
	// mission/agent counters, the live count is read from the component
	// registry (heartbeat liveness) at launch time, so there is no separate
	// active counter to keep in sync.
	ConcurrentConnectors int `json:"concurrent_connectors"`
}

// Redis active-counter keys (relative — TenantScopedStore prefixes
// tenant:{id}: at runtime). Renamed from :count → :active by the spec to
// make the runtime-state semantic unambiguous.
const (
	quotaMissionsActiveKey = "quota:missions:active"
	quotaAgentsActiveKey   = "quota:agents:active"
)

// QuotaManager enforces per-tenant resource quotas.
//
// Architecture (post ADR-0003 entitlements seam):
//   - Limits (config) come exclusively from the entitlements.Provider. The
//     QuotaManager never reads plans, Stripe, or the tenant_quotas row
//     directly — it asks the Provider "what are this tenant's limits?" The
//     OSS default provider (entitlements.NewConfigProvider) derives those
//     limits from admin-set quota config; the commercial layer swaps in a
//     plan/subscription-driven provider behind the same interface.
//   - Active counters (runtime state) live in Redis. Written by the daemon
//     on mission state transitions and agent task lifecycle.
//
// The previous Redis `quota:config` JSON store and the SetQuota RPC are
// deleted. Memory enforcement (CheckMemoryQuota / quota:memory:used_mb) is
// likewise deleted — if it ever returns it ships in its own spec.
type QuotaManager struct {
	store    *state.TenantScopedStore
	provider entitlements.Provider
	logger   *slog.Logger

	cacheMu sync.RWMutex
	cache   map[string]quotaCacheEntry // test-priming / direct seeding only
}

type quotaCacheEntry struct {
	q TenantQuota
}

// NewQuotaManager creates a QuotaManager backed by the given TenantScopedStore
// (Redis active counters) and entitlements Provider (limits). The store must
// be non-nil; provider may be nil, in which case every tenant is unlimited
// (entitlements.Resolve degrades a nil Provider to UnlimitedProvider).
func NewQuotaManager(store *state.TenantScopedStore, provider entitlements.Provider, logger *slog.Logger) *QuotaManager {
	return &QuotaManager{
		store:    store,
		provider: entitlements.Resolve(provider),
		logger:   logger.With("component", "quota_manager"),
		cache:    make(map[string]quotaCacheEntry),
	}
}

// GetQuota retrieves the configured limits for a tenant from the entitlements
// Provider. Returns nil (and no error) when the provider reports no limits
// (every dimension unlimited). Callers interpret nil as "unlimited on all
// dimensions".
//
// A directly-seeded cache entry (tests, future push sources) takes
// precedence over the provider.
func (q *QuotaManager) GetQuota(ctx context.Context, tenant string) (*TenantQuota, error) {
	if tenant == "" {
		return nil, fmt.Errorf("tenant must not be empty")
	}

	// Test/seed override: an explicitly-primed cache entry wins.
	q.cacheMu.RLock()
	if entry, ok := q.cache[tenant]; ok {
		out := entry.q
		q.cacheMu.RUnlock()
		return &out, nil
	}
	q.cacheMu.RUnlock()

	lim, err := q.provider.Limits(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if lim == (entitlements.Limits{}) {
		return nil, nil
	}
	return &TenantQuota{
		TenantID:             tenant,
		ConcurrentMissions:   lim.ConcurrentMissions,
		ConcurrentAgents:     lim.ConcurrentAgents,
		ConcurrentConnectors: lim.ConcurrentConnectors,
	}, nil
}

// InvalidateCache drops any seeded quota entry for one tenant and, when the
// Provider supports it, invalidates the Provider's own cache so a subsequent
// read reflects a just-written quota change immediately.
func (q *QuotaManager) InvalidateCache(tenant string) {
	q.cacheMu.Lock()
	delete(q.cache, tenant)
	q.cacheMu.Unlock()
	if inv, ok := q.provider.(entitlements.Invalidator); ok {
		inv.Invalidate(tenant)
	}
}

// CheckMissionQuota verifies that the tenant in ctx has not exceeded its
// configured concurrent-mission limit. Returns nil when no quota is set,
// ConcurrentMissions == 0, or the active count is below the limit.
// Returns codes.ResourceExhausted otherwise.
func (q *QuotaManager) CheckMissionQuota(ctx context.Context) error {
	tenant := auth.TenantStringFromContext(ctx)
	quota, err := q.GetQuota(ctx, tenant)
	if err != nil || quota == nil || quota.ConcurrentMissions == 0 {
		return nil
	}
	count, _ := q.store.Get(ctx, quotaMissionsActiveKey)
	current, _ := strconv.Atoi(count)
	if current >= quota.ConcurrentMissions {
		return status.Errorf(codes.ResourceExhausted,
			"tenant %s concurrent_missions quota exceeded (%d/%d)",
			tenant, current, quota.ConcurrentMissions)
	}
	return nil
}

// CheckAgentQuota verifies that the tenant in ctx has not exceeded its
// configured concurrent-agent limit. The "agent" counter only includes
// agents currently bound to an in-flight mission task — idle-but-connected
// agents do NOT count.
func (q *QuotaManager) CheckAgentQuota(ctx context.Context) error {
	tenant := auth.TenantStringFromContext(ctx)
	quota, err := q.GetQuota(ctx, tenant)
	if err != nil || quota == nil || quota.ConcurrentAgents == 0 {
		return nil
	}
	count, _ := q.store.Get(ctx, quotaAgentsActiveKey)
	current, _ := strconv.Atoi(count)
	if current >= quota.ConcurrentAgents {
		return status.Errorf(codes.ResourceExhausted,
			"tenant %s concurrent_agents quota exceeded (%d/%d)",
			tenant, current, quota.ConcurrentAgents)
	}
	return nil
}

// CheckConnectorQuota verifies that launching one more hosted connector for the
// tenant in ctx would not exceed its configured concurrent-connector limit.
// currentInstances is the tenant's live connector-instance count, read by the
// caller from the component registry (heartbeat liveness) — there is no separate
// active counter, so a connector that dies frees its slot automatically when its
// registry entry expires. Returns nil when no quota is set, the limit is 0
// (unlimited), or the count is below the limit; codes.ResourceExhausted
// otherwise.
func (q *QuotaManager) CheckConnectorQuota(ctx context.Context, currentInstances int) error {
	tenant := auth.TenantStringFromContext(ctx)
	quota, err := q.GetQuota(ctx, tenant)
	if err != nil || quota == nil || quota.ConcurrentConnectors == 0 {
		return nil
	}
	if currentInstances >= quota.ConcurrentConnectors {
		return status.Errorf(codes.ResourceExhausted,
			"tenant %s concurrent_connectors quota exceeded (%d/%d)",
			tenant, currentInstances, quota.ConcurrentConnectors)
	}
	return nil
}

// IncrementMissionCount atomically increments the active-mission counter
// for the tenant in ctx. Called when a mission transitions queued → running.
func (q *QuotaManager) IncrementMissionCount(ctx context.Context) error {
	if _, err := q.store.Incr(ctx, quotaMissionsActiveKey); err != nil {
		return fmt.Errorf("increment mission count: %w", err)
	}
	return nil
}

// DecrementMissionCount decrements the active-mission counter for the tenant
// in ctx. Called when a mission transitions to a terminal state. Floored at
// zero — see decrementCounter.
func (q *QuotaManager) DecrementMissionCount(ctx context.Context) error {
	return q.decrementCounter(ctx, quotaMissionsActiveKey, "mission")
}

// IncrementAgentCount atomically increments the busy-agent counter for the
// tenant in ctx. Called when a per-agent inFlightTasks counter transitions
// 0 → 1 (the agent becomes busy).
func (q *QuotaManager) IncrementAgentCount(ctx context.Context) error {
	if _, err := q.store.Incr(ctx, quotaAgentsActiveKey); err != nil {
		return fmt.Errorf("increment agent count: %w", err)
	}
	return nil
}

// DecrementAgentCount decrements the busy-agent counter for the tenant in
// ctx. Called when a per-agent inFlightTasks transitions 1 → 0 (idle), or
// when an agent disconnects WHILE busy. Floored at zero.
func (q *QuotaManager) DecrementAgentCount(ctx context.Context) error {
	return q.decrementCounter(ctx, quotaAgentsActiveKey, "agent")
}

// ReadActiveCounters returns the live counter values for both quotas. Used
// by the GetTenantQuotaUsage RPC to populate the dashboard's in-app usage UX.
// Missing keys return zero without error.
func (q *QuotaManager) ReadActiveCounters(ctx context.Context, tenant string) (missions, agents int64, err error) {
	if tenant == "" {
		return 0, 0, fmt.Errorf("tenant must not be empty")
	}
	tctx := auth.ContextWithTenantString(ctx, tenant)
	missions = readInt64(tctx, q.store, quotaMissionsActiveKey)
	agents = readInt64(tctx, q.store, quotaAgentsActiveKey)
	return missions, agents, nil
}

func readInt64(ctx context.Context, store *state.TenantScopedStore, key string) int64 {
	raw, err := store.Get(ctx, key)
	if err != nil || raw == "" {
		return 0
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// decrementCounter safely decrements a named integer counter, ensuring it
// never goes below zero. Read-then-conditionally-write — safe under
// concurrent load because the worst case is the counter briefly going below
// zero before the next increment corrects it; quota enforcement always reads
// the current value atomically through CheckMissionQuota / CheckAgentQuota.
func (q *QuotaManager) decrementCounter(ctx context.Context, key, name string) error {
	raw, err := q.store.Get(ctx, key)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("read %s count: %w", name, err)
	}
	current, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("parse %s count %q: %w", name, raw, err)
	}
	if current <= 0 {
		return nil
	}
	newVal := strconv.FormatInt(current-1, 10)
	if err := q.store.Set(ctx, key, newVal, 0); err != nil {
		return fmt.Errorf("decrement %s count: %w", name, err)
	}
	return nil
}
