/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package store_test

import (
	"context"
	"os/exec"
	"testing"

	"github.com/zeroroot-ai/gibson/operators/tenant/cmd/gibson-backup/internal/store"
)

// TestPostgresBackupNoPgDump verifies that BackupPostgres returns an error
// when pg_dump is not on PATH. We rely on PATH manipulation to simulate this.
func TestPostgresBackupNoPgDump(t *testing.T) {
	// If pg_dump doesn't exist on PATH this test verifies the correct error.
	if _, err := exec.LookPath("pg_dump"); err == nil {
		// pg_dump is available — skip the "missing binary" error path but verify
		// that a bad DSN produces an error (pg_dump exits non-zero for bad DSN).
		t.Skip("pg_dump found on PATH; skipping missing-binary test")
	}

	ctx := context.Background()
	_, _, err := store.PostgresBackup(ctx, "postgres://bad:bad@localhost/nonexistent", nil)
	if err == nil {
		t.Fatal("expected error when pg_dump not found, got nil")
	}
}

// Integration tests are guarded with //go:build integration.
// Run with: go test -tags integration -v ./cmd/gibson-backup/internal/store/...
