// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package store_test

import (
	"bytes"
	"context"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/store"
)

// TestRedisBackupRestoreRoundtrip uses miniredis to verify that RedisBackup
// followed by RedisRestore produces an identical key set.
//
// Note: miniredis DUMP only supports string keys (same as the real Redis DUMP
// command for v2.37.0). The test therefore only exercises string keys.
// Non-string types (hash, list, set, zset) would require the full Redis DUMP
// RDB encoding, which is beyond miniredis's scope. Real Redis DUMP does support
// all types; this limitation is miniredis-specific.
func TestRedisBackupRestoreRoundtrip(t *testing.T) {
	// Start source miniredis instance.
	src := miniredis.RunT(t)
	if err := src.Set("key1", "value1"); err != nil {
		t.Fatalf("set key1: %v", err)
	}
	if err := src.Set("key2", "value2"); err != nil {
		t.Fatalf("set key2: %v", err)
	}

	ctx := context.Background()
	srcDSN := "redis://" + src.Addr() + "/0"

	// Backup.
	var buf bytes.Buffer
	_, digest, err := store.RedisBackup(ctx, srcDSN, &buf)
	if err != nil {
		t.Fatalf("RedisBackup: %v", err)
	}
	if digest == "" {
		t.Fatal("RedisBackup: empty digest")
	}
	if buf.Len() == 0 {
		t.Fatal("RedisBackup: empty output")
	}

	// Start destination miniredis instance.
	dst := miniredis.RunT(t)
	dstDSN := "redis://" + dst.Addr() + "/0"

	// Restore.
	if err := store.RedisRestore(ctx, dstDSN, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("RedisRestore: %v", err)
	}

	// Verify string keys were restored.
	for _, key := range []string{"key1", "key2"} {
		got, err := dst.Get(key)
		if err != nil {
			t.Errorf("restored key %q not found: %v", key, err)
			continue
		}
		srcVal, _ := src.Get(key)
		if got != srcVal {
			t.Errorf("key %q: got %q, want %q", key, got, srcVal)
		}
	}
}

// TestRedisBackupInvalidDSN verifies that a bad DSN returns an error.
func TestRedisBackupInvalidDSN(t *testing.T) {
	ctx := context.Background()
	_, _, err := store.RedisBackup(ctx, "://bad-dsn", &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for invalid DSN, got nil")
	}
}

// Integration tests are guarded with //go:build integration.
// Run with: go test -tags integration -v ./cmd/gibson-backup/internal/store/...
