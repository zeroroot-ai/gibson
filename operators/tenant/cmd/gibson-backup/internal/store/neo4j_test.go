// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package store_test

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/store"
)

// TestNeo4jBackupInvalidDSN verifies that an invalid DSN returns a parse error
// before any network connection is attempted.
func TestNeo4jBackupInvalidDSN(t *testing.T) {
	ctx := context.Background()
	// Missing database component in path should produce an error.
	_, _, err := store.Neo4jBackup(ctx, "bolt://user:pass@localhost:7687", nil)
	if err == nil {
		t.Fatal("expected error for DSN missing database path, got nil")
	}
}

// TestNeo4jAPOCUnavailableError verifies that ErrNeo4jAPOCNotAvailable is a
// non-nil sentinel that callers can identify.
func TestNeo4jAPOCUnavailableError(t *testing.T) {
	if store.ErrNeo4jAPOCNotAvailable == nil {
		t.Fatal("ErrNeo4jAPOCNotAvailable must not be nil")
	}
}

// Integration tests are guarded with //go:build integration.
// Run with: go test -tags integration -v ./cmd/gibson-backup/internal/store/...
//
// Integration tests require:
//   - Neo4j 5.x with APOC plugin at BOLT_URI (env var)
//   - Credentials in NEO4J_USERNAME / NEO4J_PASSWORD
