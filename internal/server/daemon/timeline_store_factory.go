package daemon

import (
	"context"
	"fmt"
	"log/slog"

	goredis "github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// timelinePoolForer is the narrow interface timelineStoreFactory needs from
// the data-plane pool. It is satisfied by *datapool.pool (pool_impl.go) and
// can be faked cheaply in tests without constructing a full Pool.
type timelinePoolForer interface {
	For(ctx context.Context, tenant auth.TenantID) (*datapool.Conn, error)
}

// timelineStoreFactory returns a brain.Registry StoreFactory closure backed by
// pool. The returned factory is called lazily by brain.Registry.For on first
// tenant touch. It preserves the exact runtime behavior that was previously
// inlined in daemon.go:
//
//   - Invalid tenant string (fails auth.NewTenantID) → logs a warning, returns nil
//     (engine operates in-memory only for that tenant).
//   - pool.For probe fails → logs a warning, returns nil (same fallback).
//   - Probe succeeds → builds a per-op acquire closure and returns a
//     *datapool.RedisTimelineStore so the idle evictor can never close the
//     client underneath a long-lived reference (gibson#1114, ADR-0011).
//
// Extraction rationale: moving the closure body here makes it directly
// testable without launching a full daemon (the factory only needs a
// timelinePoolForer, not a *daemonImpl).
func timelineStoreFactory(pool timelinePoolForer, log *slog.Logger) func(ctx context.Context, tenant string) brain.TimelineStore {
	return func(storeCtx context.Context, tenant string) brain.TimelineStore {
		tenantID, idErr := auth.NewTenantID(tenant)
		if idErr != nil {
			log.WarnContext(storeCtx, "brain/registry: store factory: invalid tenant id; engine will run in-memory only",
				"tenant", tenant,
				"err", idErr,
			)
			return nil
		}

		// Validate that the tenant's data-plane is provisioned by doing a probe
		// acquire now; if pool.For fails we surface the error immediately and
		// fall back to in-memory mode for this tenant (matching pre-#1113 behavior).
		probeConn, probeErr := pool.For(storeCtx, tenantID)
		if probeErr != nil {
			log.WarnContext(storeCtx, "brain/registry: store factory: pool.For probe failed; engine will run in-memory only",
				"tenant", tenant,
				"err", probeErr,
			)
			return nil
		}
		probeConn.Release()

		// Build a per-op acquire closure. Each Timeline operation
		// (Append, LoadForReplay, WriteSnapshot, LoadSnapshot, TrimTo)
		// calls this closure to obtain a fresh Conn and releases it when
		// the operation completes. This ensures the idle evictor can never
		// close the client underneath a long-lived reference (gibson#1114, ADR-0011).
		acquire := func(opCtx context.Context) (*goredis.Client, func(), error) {
			conn, err := pool.For(opCtx, tenantID)
			if err != nil {
				return nil, nil, fmt.Errorf("brain/timeline: pool.For tenant %q: %w", tenant, err)
			}
			return conn.Redis, conn.Release, nil
		}
		return datapool.NewRedisTimelineStore(acquire)
	}
}
