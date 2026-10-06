// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

import (
	"context"

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

// InvalidationPattern is the psubscribe pattern matching every tenant's
// invalidation channel. Consumed by the server-streaming RPC.
const InvalidationPattern = invalidationChannelPrefix + "*" + invalidationChannelSuffix
