// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// scanJSONRecords reads each JSON record whose key matches pattern. A key
// that expires during the scan is skipped. A record that does not decode is
// skipped. A Redis error stops the scan and returns the error. kind names the
// record in each error message.
func scanJSONRecords[T any](ctx context.Context, client *redis.Client, pattern, kind string) ([]T, error) {
	var results []T
	var cursor uint64

	for {
		keys, next, err := client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan %s keys: %w", kind, err)
		}

		for _, key := range keys {
			data, err := client.Get(ctx, key).Bytes()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					continue
				}
				return nil, fmt.Errorf("get %s %s: %w", kind, key, err)
			}

			var record T
			if err := json.Unmarshal(data, &record); err != nil {
				continue
			}
			results = append(results, record)
		}

		cursor = next
		if cursor == 0 {
			return results, nil
		}
	}
}
