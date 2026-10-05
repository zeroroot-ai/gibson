// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// SetIfAbsent writes key with value and an expiry, only when the key does
// not exist. It reports whether this call wrote the key. Redis runs the
// command (SET NX) atomically, so exactly one of many concurrent callers
// gets true.
//
// ttl must be positive: a key with no expiry would stay for ever.
func (c *StateClient) SetIfAbsent(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	if ttl <= 0 {
		return false, fmt.Errorf("state: SetIfAbsent %s: ttl must be positive", key)
	}
	err := c.client.SetArgs(ctx, key, value, redis.SetArgs{Mode: "NX", TTL: ttl}).Err()
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, redis.Nil):
		// SET NX answers nil when the key exists.
		return false, nil
	default:
		return false, fmt.Errorf("state: SetIfAbsent %s: %w", key, err)
	}
}
