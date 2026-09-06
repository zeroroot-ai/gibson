// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"strings"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// TestRedisQueueAdapter_HSet pins the behaviour of handing the field map
// straight to go-redis (gibson#1444). The adapter used to flatten the map
// into an interleaved []interface{} by hand; go-redis does that itself, so
// the round-trip must be identical — including the empty-map case, where
// Redis rejects HSET with no field/value pairs.
func TestRedisQueueAdapter_HSet(t *testing.T) {
	srv := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	a := &redisQueueAdapter{client: client}
	ctx := context.Background()

	t.Run("writes every field", func(t *testing.T) {
		fields := map[string]string{
			"name":        "nmap",
			"version":     "1.2.3",
			"description": "port scanner",
		}
		if err := a.HSet(ctx, "tool:nmap:meta", fields); err != nil {
			t.Fatalf("HSet: %v", err)
		}

		got, err := client.HGetAll(ctx, "tool:nmap:meta").Result()
		if err != nil {
			t.Fatalf("HGetAll: %v", err)
		}
		if len(got) != len(fields) {
			t.Fatalf("got %d fields, want %d: %v", len(got), len(fields), got)
		}
		for k, want := range fields {
			if got[k] != want {
				t.Errorf("field %q = %q, want %q", k, got[k], want)
			}
		}
	})

	t.Run("single field", func(t *testing.T) {
		if err := a.HSet(ctx, "tool:one:meta", map[string]string{"k": "v"}); err != nil {
			t.Fatalf("HSet: %v", err)
		}
		if got := srv.HGet("tool:one:meta", "k"); got != "v" {
			t.Errorf("k = %q, want v", got)
		}
	})

	t.Run("empty map surfaces a wrapped error", func(t *testing.T) {
		err := a.HSet(ctx, "tool:empty:meta", map[string]string{})
		if err == nil {
			t.Fatal("expected an error for HSET with no fields, got nil")
		}
		// wrapcheck-compliant wrapping must name the key so the failure is
		// attributable in daemon logs.
		if !strings.Contains(err.Error(), "tool:empty:meta") {
			t.Errorf("error must name the key, got: %v", err)
		}
	})
}
