package manifest

import (
	"context"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

// invalidationChannelPrefix + tenantID + invalidationChannelSuffix is the
// Redis pubsub channel the Invalidator publishes to and that
// WatchManifestInvalidations (Task 14) subscribes to.
const invalidationChannelPrefix = "tenant:"
const invalidationChannelSuffix = ":manifest_invalidated"

// RedisPublishClient is the narrow Redis surface the Invalidator
// requires. Implemented by redis.UniversalClient and mockable in tests.
type RedisPublishClient interface {
	Publish(ctx context.Context, channel string, message any) *redis.IntCmd
}

// redisInvalidator implements Invalidator over Redis pubsub. Failures
// are logged and swallowed so the originating write is never blocked.
type redisInvalidator struct {
	rdb RedisPublishClient
	log *slog.Logger
}

// NewInvalidator constructs a best-effort Invalidator. If log is nil,
// slog.Default() is used.
func NewInvalidator(rdb RedisPublishClient, log *slog.Logger) Invalidator {
	if log == nil {
		log = slog.Default()
	}
	return &redisInvalidator{rdb: rdb, log: log}
}

// Publish emits a tenant invalidation. Errors never propagate — the
// TTL-based manifest refresh is the correctness backstop, so a
// transient Redis blip must not fail the caller's write.
func (i *redisInvalidator) Publish(ctx context.Context, tenantID string, reason string) {
	if tenantID == "" {
		i.log.Warn("manifest: Invalidator.Publish called with empty tenantID", "reason", reason)
		return
	}
	ch := invalidationChannel(tenantID)
	if _, err := i.rdb.Publish(ctx, ch, reason).Result(); err != nil {
		i.log.Warn("manifest: invalidation publish failed (non-fatal — TTL refresh will catch up)",
			"channel", ch, "reason", reason, "error", err)
	}
}

// InvalidationChannel returns the Redis pubsub channel name for a
// tenant. Exported so Task 14 (WatchManifestInvalidations) can compose
// a psubscribe pattern from the prefix.
func InvalidationChannel(tenantID string) string { return invalidationChannel(tenantID) }

// InvalidationPattern is the psubscribe pattern matching every tenant's
// invalidation channel. Consumed by the server-streaming RPC.
const InvalidationPattern = invalidationChannelPrefix + "*" + invalidationChannelSuffix

func invalidationChannel(tenantID string) string {
	return invalidationChannelPrefix + tenantID + invalidationChannelSuffix
}
