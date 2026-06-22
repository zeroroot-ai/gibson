// quota_cleanup.go — single-use boot-time Redis sweep for legacy quota
// keys. Spec plans-and-quotas-simplification deleted the Redis quota:config
// JSON store, the quota:memory:used_mb counter, and renamed the active
// counters from :count → :active. This file removes the leftover keys on
// the daemon's first boot under the new chart, gated by a sentinel so
// subsequent boots are a no-op.
//
// SAFE TO DELETE in the chart release after this one — nothing in steady
// state should ever read these keys again.
package component

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	goredis "github.com/redis/go-redis/v9"
)

// quotaCleanupSentinelKey is the global Redis key flipped after a successful
// sweep. Versioned so a future cleanup pass (e.g. removing yet another key
// family) can run independently.
const quotaCleanupSentinelKey = "gibson:meta:quota_cleanup_done_v1"

// legacyQuotaKeyPatterns are the Redis SCAN patterns deleted by the sweep.
// All three are fully prefixed (TenantScopedStore prefixes tenant:{id}:
// at write time, so the keys live at "tenant:{id}:quota:..." by then).
var legacyQuotaKeyPatterns = []string{
	"tenant:*:quota:config",
	"tenant:*:quota:memory:used_mb",
	"tenant:*:quota:missions:count",
	"tenant:*:quota:agents:count",
}

// CleanupLegacyQuotaKeys runs once per daemon boot. On first run it scans
// the four legacy patterns above, deletes every match, and sets the
// sentinel; subsequent calls observe the sentinel and short-circuit.
//
// Non-fatal: any per-pattern failure logs a warning and the sweep continues.
// The sentinel is only set if the entire pass completes without an
// unrecoverable error.
func CleanupLegacyQuotaKeys(ctx context.Context, client goredis.UniversalClient, logger *slog.Logger) error {
	if client == nil {
		return nil
	}
	if logger == nil {
		logger = slog.Default()
	}

	// Fast path: sentinel already set.
	exists, err := client.Exists(ctx, quotaCleanupSentinelKey).Result()
	if err != nil && !errors.Is(err, goredis.Nil) {
		logger.WarnContext(ctx, "quota cleanup: sentinel check failed (continuing)", "error", err)
	} else if exists > 0 {
		return nil
	}

	totalDeleted := int64(0)
	for _, pattern := range legacyQuotaKeyPatterns {
		n, err := scanAndDelete(ctx, client, pattern)
		if err != nil {
			logger.WarnContext(ctx, "quota cleanup: pattern failed (continuing)",
				"pattern", pattern, "error", err)
			continue
		}
		totalDeleted += n
	}

	if err := client.Set(ctx, quotaCleanupSentinelKey, "1", 0).Err(); err != nil {
		return fmt.Errorf("quota cleanup: set sentinel: %w", err)
	}
	logger.InfoContext(ctx, "quota cleanup: legacy keys swept",
		"deleted", totalDeleted,
		"patterns", len(legacyQuotaKeyPatterns),
	)
	return nil
}

// scanAndDelete walks all keys matching pattern via SCAN and DELETEs them
// in batches. Non-blocking; safe to run alongside live traffic.
func scanAndDelete(ctx context.Context, client goredis.UniversalClient, pattern string) (int64, error) {
	const scanCount = 1000
	var (
		cursor  uint64
		deleted int64
	)
	for {
		keys, next, err := client.Scan(ctx, cursor, pattern, scanCount).Result()
		if err != nil {
			return deleted, fmt.Errorf("scan %q: %w", pattern, err)
		}
		if len(keys) > 0 {
			n, err := client.Del(ctx, keys...).Result()
			if err != nil {
				return deleted, fmt.Errorf("del %q batch: %w", pattern, err)
			}
			deleted += n
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return deleted, nil
}
