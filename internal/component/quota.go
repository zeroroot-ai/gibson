package component

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/sdk/auth"
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
// Architecture (post spec plans-and-quotas-simplification):
//   - Limits (config) live in the platform Postgres `tenant_quotas` row.
//     Written exclusively by the operator's UpsertTenantQuota RPC.
//   - Active counters (runtime state) live in Redis. Written by the daemon
//     on mission state transitions and agent task lifecycle.
//
// The previous Redis `quota:config` JSON store and the SetQuota RPC are
// deleted. Memory enforcement (CheckMemoryQuota / quota:memory:used_mb) is
// likewise deleted — if it ever returns it ships in its own spec.
type QuotaManager struct {
	store  *state.TenantScopedStore
	db     *sql.DB
	logger *slog.Logger

	cacheTTL time.Duration
	cacheMu  sync.RWMutex
	cache    map[string]quotaCacheEntry
	flight   sync.Map // tenantID → *flightToken
}

type quotaCacheEntry struct {
	q        TenantQuota
	expireAt time.Time
}

type flightToken struct {
	once sync.Once
	q    TenantQuota
	err  error
}

// NewQuotaManager creates a QuotaManager backed by the given TenantScopedStore
// (Redis active counters) and platform Postgres pool (limits). The store must
// be non-nil; db may be nil in dev/kind setups, in which case GetQuota
// returns nil (unlimited) for every tenant.
func NewQuotaManager(store *state.TenantScopedStore, db *sql.DB, logger *slog.Logger) *QuotaManager {
	return &QuotaManager{
		store:    store,
		db:       db,
		logger:   logger.With("component", "quota_manager"),
		cacheTTL: 60 * time.Second,
		cache:    make(map[string]quotaCacheEntry),
	}
}

// GetQuota retrieves the configured limits for a tenant from the platform
// Postgres `tenant_quotas` row, with a 60s in-process LRU cache. Returns nil
// (and no error) when:
//   - the daemon was started without a platform Postgres pool, or
//   - no row exists for the tenant.
//
// Callers interpret nil as "unlimited on all dimensions".
func (q *QuotaManager) GetQuota(ctx context.Context, tenant string) (*TenantQuota, error) {
	if tenant == "" {
		return nil, fmt.Errorf("tenant must not be empty")
	}
	if q.db == nil {
		return nil, nil
	}

	// Fast path: cache hit.
	q.cacheMu.RLock()
	if entry, ok := q.cache[tenant]; ok && time.Now().Before(entry.expireAt) {
		out := entry.q
		q.cacheMu.RUnlock()
		return &out, nil
	}
	q.cacheMu.RUnlock()

	// Slow path: singleflight DB read so concurrent callers share one query.
	tokenIface, _ := q.flight.LoadOrStore(tenant, &flightToken{})
	tok := tokenIface.(*flightToken)
	tok.once.Do(func() {
		defer q.flight.Delete(tenant)
		quota, err := q.readQuotaRow(ctx, tenant)
		if err != nil {
			tok.err = err
			return
		}
		if quota != nil {
			tok.q = *quota
			q.cacheMu.Lock()
			q.cache[tenant] = quotaCacheEntry{q: *quota, expireAt: time.Now().Add(q.cacheTTL)}
			q.cacheMu.Unlock()
		}
	})
	if tok.err != nil {
		return nil, tok.err
	}
	if tok.q.TenantID == "" {
		return nil, nil
	}
	out := tok.q
	return &out, nil
}

// readQuotaRow performs the SELECT against tenant_quotas. Returns nil + nil
// when the row is absent.
func (q *QuotaManager) readQuotaRow(ctx context.Context, tenant string) (*TenantQuota, error) {
	const sqlQuery = `
		SELECT concurrent_missions, concurrent_agents
		FROM tenant_quotas
		WHERE tenant_id = $1
	`
	var quota TenantQuota
	quota.TenantID = tenant
	err := q.db.QueryRowContext(ctx, sqlQuery, tenant).Scan(
		&quota.ConcurrentMissions,
		&quota.ConcurrentAgents,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read tenant_quotas for %s: %w", tenant, err)
	}
	return &quota, nil
}

// InvalidateCache drops the cached quota entry for one tenant. Intended for
// callers that have just written a new quota record and want subsequent reads
// to reflect the change immediately.
func (q *QuotaManager) InvalidateCache(tenant string) {
	q.cacheMu.Lock()
	delete(q.cache, tenant)
	q.cacheMu.Unlock()
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
