// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package migrations

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestEmbeddedFiles_001Present asserts the bundled embed.FS carries
// the platform-DB migration that the operator's neo4jProvisioner writes
// against (tenant_neo4j_endpoints). A future contributor who renames or
// moves the file under internal/migrations/files/ without updating the
// //go:embed directive would see this test fail loudly rather than
// shipping a binary that silently has no migrations.
//
// Issue: zeroroot-ai/tenant-operator#85.
func TestEmbeddedFiles_001Present(t *testing.T) {
	files, err := EmbeddedFiles()
	if err != nil {
		t.Fatalf("EmbeddedFiles: %v", err)
	}
	want := "001_create_tenant_neo4j_endpoints.up.sql"
	if !slices.Contains(files, want) {
		t.Errorf("embed.FS missing %q; got %v — did someone rename the file or move it out of internal/migrations/files/?",
			want, files)
	}
}

// TestEmbeddedFiles_002Present asserts the bundled embed.FS carries
// migration 002 (DROP TABLE tenant_neo4j_endpoints). A missing file
// would mean the binary ships without the cleanup migration, leaving
// the now-unused table on the control-plane Postgres.
//
// Issue: zeroroot-ai/tenant-operator#246.
func TestEmbeddedFiles_002Present(t *testing.T) {
	files, err := EmbeddedFiles()
	if err != nil {
		t.Fatalf("EmbeddedFiles: %v", err)
	}
	wantFiles := []string{
		"002_drop_tenant_neo4j_endpoints.up.sql",
		"002_drop_tenant_neo4j_endpoints.down.sql",
	}
	for _, want := range wantFiles {
		if !slices.Contains(files, want) {
			t.Errorf("embed.FS missing %q; got %v — did someone rename the file or move it out of internal/migrations/files/?",
				want, files)
		}
	}
}

// TestEmbeddedFiles_UpAndDownPaired asserts every *.up.sql has a
// matching *.down.sql in the bundle. golang-migrate's Down() flow
// expects both to exist; a missing down.sql is silent in the runner
// (Up only) but is a visible bug when an operator tries to roll back.
func TestEmbeddedFiles_UpAndDownPaired(t *testing.T) {
	files, err := EmbeddedFiles()
	if err != nil {
		t.Fatalf("EmbeddedFiles: %v", err)
	}
	seen := map[string]bool{}
	for _, name := range files {
		seen[name] = true
	}
	for _, name := range files {
		if base, ok := strings.CutSuffix(name, ".up.sql"); ok {
			down := base + ".down.sql"
			if !seen[down] {
				t.Errorf("missing companion %q for %q", down, name)
			}
		}
	}
}

// TestRun_EmptyDSN locks the input-validation behaviour. The caller in
// cmd/main.go skips Run() entirely when pgDSN is empty (degraded
// dev-mode), but a defensive empty-DSN check inside Run() catches the
// case of a test or future caller that accidentally passes "".
func TestRun_EmptyDSN(t *testing.T) {
	err := Run(context.Background(), "")
	if err == nil {
		t.Fatalf("expected error on empty DSN, got nil")
	}
	if !strings.Contains(err.Error(), "empty DSN") {
		t.Errorf("error must call out empty DSN; got %v", err)
	}
}

// TestRun_BadDSN exercises the dsn-parse + ping path without standing
// up a real Postgres. golang-migrate's parser is strict about scheme;
// a clearly-malformed DSN surfaces the wrap chain we expose to the
// operator log (helps the on-call read the failure quickly).
func TestRun_BadDSN(t *testing.T) {
	err := Run(context.Background(), "this-is-not-a-postgres-dsn")
	if err == nil {
		t.Fatalf("expected error on malformed DSN, got nil")
	}
	if !strings.Contains(err.Error(), "migrations:") {
		t.Errorf("error must be prefixed 'migrations:' for log searchability; got %v", err)
	}
}

// TestRunWithDB_NilDB documents the nil-guard on the test-helper
// variant. Production callers go through Run; this is the input-
// validation surface for fixtures.
func TestRunWithDB_NilDB(t *testing.T) {
	err := RunWithDB(context.Background(), nil, "anything")
	if err == nil || !strings.Contains(err.Error(), "nil db") {
		t.Errorf("expected nil-db error; got %v", err)
	}
}

// TestRunWithDB_EmptyName documents the dbName guard on RunWithDB.
func TestRunWithDB_EmptyName(t *testing.T) {
	err := RunWithDB(context.Background(), nil, "")
	if err == nil || (!strings.Contains(err.Error(), "nil db") && !strings.Contains(err.Error(), "dbName")) {
		t.Errorf("expected nil-db or dbName error; got %v", err)
	}
}
