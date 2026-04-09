package cutoverv4

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

const (
	// auditStreamSuffix mirrors the unexported constant in internal/audit/logger.go.
	// Full Redis key: "tenant:{tenant_id}:audit:log"
	// This constant is duplicated here (not imported) because audit.auditStreamSuffix
	// is unexported; the package doc for audit confirms the key format is stable.
	auditStreamSuffix = "audit:log"

	// deleteBatchSize is the maximum number of keys removed in a single DEL pipeline
	// call. Keeping this at 100 limits memory usage and avoids blocking Redis.
	deleteBatchSize = 100
)

// auditStreamKey constructs the full Redis key for a tenant's audit log stream.
// This key is EXPLICITLY PRESERVED and must never be deleted.
func auditStreamKey(tenantID string) string {
	return fmt.Sprintf("tenant:%s:%s", tenantID, auditStreamSuffix)
}

// FlushTenantState deletes ephemeral Redis state for one tenant while preserving
// the immutable audit log stream.
//
// Patterns deleted:
//
//	tenant:{tenantID}:mission:*
//	tenant:{tenantID}:run:*
//	tenant:{tenantID}:agent:*
//
// Explicitly preserved:
//
//	tenant:{tenantID}:audit:log  (the Redis Streams legal substrate)
//
// Iteration uses SCAN to avoid blocking Redis with a KEYS command.
// Deletions are batched in groups of deleteBatchSize per pipeline call.
//
// The caller is responsible for providing an open Redis client; this function
// creates no new connections.
//
// Returns the total count of deleted keys.
func FlushTenantState(ctx context.Context, client redis.UniversalClient, tenantID string) (int, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("FlushTenantState: tenantID must not be empty")
	}

	preserve := auditStreamKey(tenantID)

	patterns := []string{
		fmt.Sprintf("tenant:%s:mission:*", tenantID),
		fmt.Sprintf("tenant:%s:run:*", tenantID),
		fmt.Sprintf("tenant:%s:agent:*", tenantID),
	}

	total := 0
	for _, pattern := range patterns {
		n, err := scanAndDelete(ctx, client, pattern, preserve)
		if err != nil {
			return total, fmt.Errorf("FlushTenantState: scan pattern %q: %w", pattern, err)
		}
		total += n
	}

	return total, nil
}

// scanAndDelete iterates all keys matching pattern using SCAN and deletes them
// in batches of deleteBatchSize, skipping preserveKey unconditionally.
func scanAndDelete(ctx context.Context, client redis.UniversalClient, pattern, preserveKey string) (int, error) {
	var cursor uint64
	var toDelete []string
	total := 0

	for {
		keys, nextCursor, err := client.Scan(ctx, cursor, pattern, deleteBatchSize).Result()
		if err != nil {
			return total, fmt.Errorf("SCAN cursor=%d pattern=%q: %w", cursor, pattern, err)
		}

		for _, key := range keys {
			if key == preserveKey {
				// Never delete the audit log stream — it is the immutable legal substrate.
				continue
			}
			toDelete = append(toDelete, key)
		}

		// Flush accumulated keys when we hit the batch limit.
		for len(toDelete) >= deleteBatchSize {
			batch := toDelete[:deleteBatchSize]
			toDelete = toDelete[deleteBatchSize:]

			n, err := deleteBatch(ctx, client, batch)
			if err != nil {
				return total, err
			}
			total += n
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}

		// Check context cancellation between SCAN pages.
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("context cancelled after deleting %d keys: %w", total, err)
		}
	}

	// Delete any remaining keys that didn't fill a full batch.
	if len(toDelete) > 0 {
		n, err := deleteBatch(ctx, client, toDelete)
		if err != nil {
			return total, err
		}
		total += n
	}

	return total, nil
}

// deleteBatch deletes keys using a Redis pipeline. Returns the count actually
// deleted (i.e. keys that existed at delete time).
func deleteBatch(ctx context.Context, client redis.UniversalClient, keys []string) (int, error) {
	pipe := client.Pipeline()
	for _, key := range keys {
		pipe.Del(ctx, key)
	}

	cmds, err := pipe.Exec(ctx)
	if err != nil {
		// If Exec returns an error it is typically a connection error rather than
		// a per-key error; surface it directly.
		return 0, fmt.Errorf("pipeline DEL: %w", err)
	}

	deleted := 0
	for _, cmd := range cmds {
		if cmd.Err() != nil {
			// Individual DEL failures are rare but non-fatal; count what succeeded.
			continue
		}
		if delCmd, ok := cmd.(*redis.IntCmd); ok {
			deleted += int(delCmd.Val())
		}
	}

	return deleted, nil
}
