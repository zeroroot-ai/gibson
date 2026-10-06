// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// assertTimelineDurability is the daemon boot guard for the durable Timeline
// (gibson#1119, ADR-0163, PRD gibson#1112): a Timeline is only durable if the
// data-plane Redis persists an append-only file, so before the Timeline store
// factory is wired the daemon asserts CONFIG GET appendonly == "yes" once
// against the data-plane Redis server (AOF is server-level, so one check
// covers every per-tenant logical DB).
//
// Fail-fast semantics: any non-"yes" answer — including an unreachable server
// or a Redis that refuses CONFIG — returns an error and the daemon MUST
// refuse to start. A mis-configured Redis (e.g. a manually-applied override
// with AOF off) must not silently produce a Timeline that looks durable but
// is lost on the next Redis restart. deploy#1063 owns the chart side
// (appendonly=yes on the shared redis-stack).
//
// redisAddr == "" is the one tolerated skip: with no data-plane Redis
// configured there is no Redis-backed Timeline to guard — engines run
// in-memory only, which is already loud in the store-factory logs.
//
// check is the actual AOF probe — production passes
// datapool.AssertTimelineAOF; tests substitute a stub because miniredis
// cannot answer CONFIG GET appendonly=yes.
func assertTimelineDurability(ctx context.Context, redisAddr, redisPassword string, check func(ctx context.Context, addr, password string) error, log *slog.Logger) error {
	if redisAddr == "" {
		log.WarnContext(ctx, "timeline durability boot guard skipped: no data-plane redis addr configured; engines will run in-memory only")
		return nil
	}
	if err := check(ctx, redisAddr, redisPassword); err != nil {
		log.ErrorContext(ctx, "timeline durability boot guard FAILED: cannot confirm Redis AOF persistence; refusing to start rather than serve a Timeline that would be lost on Redis restart (gibson#1119, ADR-0163)",
			"redis_addr", redisAddr,
			"err", err,
		)
		return fmt.Errorf("timeline durability boot guard (gibson#1119): %w", err)
	}
	log.InfoContext(ctx, "timeline durability boot guard: Redis AOF persistence confirmed (appendonly=yes)",
		"redis_addr", redisAddr,
	)
	return nil
}

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
//   - Invalid tenant string (fails auth.NewTenantID) → returns the error, and
//     brain.Registry.For builds no serving engine for that tenant (gibson#726).
//   - pool.For probe fails → returns the error (same result).
//   - Probe succeeds → builds a per-op acquire closure and returns a
//     *datapool.TimelineStore so the idle evictor can never close the
//     client underneath a long-lived reference (gibson#1114, ADR-0163).
//
// Extraction rationale: moving the closure body here makes it directly
// testable without launching a full daemon (the factory only needs a
// timelinePoolForer, not a *daemonImpl).
func timelineStoreFactory(pool timelinePoolForer, log *slog.Logger) brain.StoreFactory {
	return func(storeCtx context.Context, tenant string) (brain.TimelineStore, error) {
		tenantID, idErr := auth.NewTenantID(tenant)
		if idErr != nil {
			log.WarnContext(storeCtx, "brain/registry: store factory: invalid tenant id; no engine for the tenant",
				"tenant", tenant,
				"err", idErr,
			)
			return nil, fmt.Errorf("brain/timeline: invalid tenant id %q: %w", tenant, idErr)
		}

		// Validate that the tenant's data-plane is provisioned by doing a probe
		// acquire now; if pool.For fails we surface the error immediately and
		// return it, so the registry builds no serving engine (gibson#726).
		probeConn, probeErr := pool.For(storeCtx, tenantID)
		if probeErr != nil {
			log.WarnContext(storeCtx, "brain/registry: store factory: pool.For probe failed; no engine for the tenant",
				"tenant", tenant,
				"err", probeErr,
			)
			return nil, fmt.Errorf("brain/timeline: pool.For probe of tenant %q: %w", tenant, probeErr)
		}
		probeConn.Release()

		// Build a per-op acquire closure. Each Timeline operation
		// (Append, LoadForReplay, WriteSnapshot, LoadSnapshot, TrimTo)
		// calls this closure to obtain a fresh Conn and releases it when
		// the operation completes. This ensures the idle evictor can never
		// close the client underneath a long-lived reference (gibson#1114, ADR-0163).
		acquire := func(opCtx context.Context) (datapool.TimelineConn, func(), error) {
			conn, err := pool.For(opCtx, tenantID)
			if err != nil {
				return datapool.TimelineConn{}, nil, fmt.Errorf("brain/timeline: pool.For tenant %q: %w", tenant, err)
			}
			// Redis holds the live tail and Postgres holds the full history
			// (ADR-0163, gibson#786).
			return datapool.TimelineConn{Redis: conn.Redis, SQL: conn.SQL()}, conn.Release, nil
		}
		return datapool.NewTimelineStore(acquire), nil
	}
}
