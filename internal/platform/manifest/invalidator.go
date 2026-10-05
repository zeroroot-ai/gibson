// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

// InvalidationPattern is the psubscribe pattern matching every tenant's
// invalidation channel. Consumed by the server-streaming RPC.
const InvalidationPattern = invalidationChannelPrefix + "*" + invalidationChannelSuffix
