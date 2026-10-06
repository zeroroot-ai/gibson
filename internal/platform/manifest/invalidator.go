// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package manifest

// invalidationChannelPrefix + tenantID + invalidationChannelSuffix is the
// Redis pubsub channel the Invalidator publishes to and that
// WatchManifestInvalidations (Task 14) subscribes to.
const invalidationChannelPrefix = "tenant:"
const invalidationChannelSuffix = ":manifest_invalidated"

// InvalidationPattern is the psubscribe pattern matching every tenant's
// invalidation channel. Consumed by the server-streaming RPC.
const InvalidationPattern = invalidationChannelPrefix + "*" + invalidationChannelSuffix
