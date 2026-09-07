// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package helpers — test_target.go
//
// Test-only target registration for the cluster-bound e2e suites. Gibson has
// no public gRPC CreateTarget RPC: targets are created through the dashboard
// or by operators. The exit tests write the minimal target document directly
// into the daemon's Redis targetStore, using the same key convention as
// internal/infra/database/redis targets:
//   - Document:    gibson:target:{uuid}
//   - Name lookup: gibson:target:by_name:{name}
//
// This is intentionally a test-only path. It writes directly to Redis.
package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// testRedisClient dials the cluster's Redis for the target helpers below.
//
// The sanctioned profile runs Redis WITH authentication, so an address alone is
// not enough: an unauthenticated client gets "NOAUTH Authentication required"
// and every test that registers a target fails before the test it belongs to
// has begun. REDIS_PASSWORD carries the credential; the exit-test workflows read
// it out of the cluster secret and export it.
func testRedisClient() *redis.Client {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	return redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: os.Getenv("REDIS_PASSWORD"),
	})
}

// RegisterTestTarget inserts a test target record directly into the daemon's
// Redis targetStore so that RunMission / CreateMission can reference it by UUID.
//
// The function reads the REDIS_ADDR env var (default: "localhost:6379") to
// connect. It returns the assigned target UUID string.
func RegisterTestTarget(ctx context.Context, name, targetURL string) (string, error) {
	rdb := testRedisClient()
	defer rdb.Close()

	if err := rdb.Ping(ctx).Err(); err != nil {
		return "", fmt.Errorf("test_target: RegisterTestTarget: ping Redis %s: %w", rdb.Options().Addr, err)
	}

	targetID := uuid.New().String()
	now := time.Now().UnixMilli()

	doc := map[string]interface{}{
		"id":         targetID,
		"name":       name,
		"type":       "web",
		"url":        targetURL,
		"status":     "active",
		"created_at": now,
		"updated_at": now,
		"connection": map[string]interface{}{
			"url": targetURL,
		},
		"tags": []string{"e2e", "test-fixture"},
	}

	docJSON, err := json.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("test_target: RegisterTestTarget: marshal target doc: %w", err)
	}

	docKey := fmt.Sprintf("gibson:target:%s", targetID)
	if err := rdb.Set(ctx, docKey, docJSON, 0).Err(); err != nil {
		return "", fmt.Errorf("test_target: RegisterTestTarget: write target doc to Redis: %w", err)
	}

	nameKey := fmt.Sprintf("gibson:target:by_name:%s", name)
	if err := rdb.Set(ctx, nameKey, targetID, 0).Err(); err != nil {
		return "", fmt.Errorf("test_target: RegisterTestTarget: write target name lookup to Redis: %w", err)
	}

	return targetID, nil
}

// DeleteTestTarget removes a test target from Redis by UUID.
// Tolerates missing keys. Idempotent.
func DeleteTestTarget(ctx context.Context, targetID, name string) {
	rdb := testRedisClient()
	defer rdb.Close()

	_ = rdb.Del(ctx, fmt.Sprintf("gibson:target:%s", targetID))
	_ = rdb.Del(ctx, fmt.Sprintf("gibson:target:by_name:%s", name))
}
