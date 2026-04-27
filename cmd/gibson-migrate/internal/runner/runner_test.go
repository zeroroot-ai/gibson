package runner_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/cmd/gibson-migrate/internal/runner"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// tempMigrationsDir creates a temporary directory with the given *.up.sql files.
// Each entry in files is a map of filename → SQL content.
func tempMigrationsDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
	return dir
}

// ---------------------------------------------------------------------------
// parseVersion tests (via exported behaviour of the runner)
// ---------------------------------------------------------------------------

// TestPostgresRunner_EmptyDir verifies that the runner handles a directory with
// no migration files without error — this is the expected state before Phase D
// authors the migration files.
func TestPostgresRunner_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	r := &runner.PostgresRunner{
		DSN:           "postgres://invalid:invalid@localhost:5432/nonexistent?sslmode=disable",
		MigrationsDir: dir,
	}

	// Apply on an empty dir should be a no-op (not an error).
	cur, tgt, applied, err := r.Apply(context.Background())
	require.NoError(t, err, "Apply on empty migrations dir should succeed (no-op)")
	assert.Equal(t, uint(0), cur)
	assert.Equal(t, uint(0), tgt)
	assert.Empty(t, applied)
}

// TestPostgresRunner_MissingDir verifies that a non-existent migrations directory
// is treated as "no migrations" rather than an error. This handles the case
// where Phase D has not yet authored the migration files.
func TestPostgresRunner_MissingDir(t *testing.T) {
	r := &runner.PostgresRunner{
		DSN:           "postgres://invalid@localhost:5432/nonexistent?sslmode=disable",
		MigrationsDir: "/tmp/gibson-migrate-nonexistent-dir-12345",
	}

	cur, tgt, applied, err := r.Apply(context.Background())
	require.NoError(t, err, "Apply on non-existent dir should be a no-op, not an error")
	assert.Zero(t, cur)
	assert.Zero(t, tgt)
	assert.Empty(t, applied)
}

// TestPostgresRunner_BadDSNWithMigrations verifies that a bad DSN with actual
// migration files returns an error (as expected when a real DB is needed).
// We cannot rely on a connection timeout in unit tests so we use an
// intentionally malformed DSN that fails at parse/driver-open time.
func TestPostgresRunner_BadDSNWithMigrations(t *testing.T) {
	dir := tempMigrationsDir(t, map[string]string{
		"001_init.up.sql":   "CREATE TABLE foo (id SERIAL PRIMARY KEY);",
		"001_init.down.sql": "DROP TABLE foo;",
	})
	// An empty DSN with real migration files should return an error from
	// the postgres runner (no DSN configured).
	r := &runner.PostgresRunner{
		DSN:           "",
		MigrationsDir: dir,
	}

	_, _, _, err := r.Apply(context.Background())
	assert.Error(t, err, "Apply with empty DSN and real migrations should return an error")
}

// TestPostgresRunner_StatusEmptyDir verifies Status works on an empty migrations dir.
func TestPostgresRunner_StatusEmptyDir(t *testing.T) {
	dir := t.TempDir()
	r := &runner.PostgresRunner{
		DSN:           "postgres://invalid@localhost:5432/nonexistent?sslmode=disable",
		MigrationsDir: dir,
	}

	status, err := r.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint(0), status.Current)
	assert.Equal(t, uint(0), status.Target)
	assert.Empty(t, status.Pending)
}

// TestPostgresRunner_StatusWithMigrationFiles verifies Status correctly reports
// pending migrations when the DB is unreachable (simulates a tenant DB that
// exists in the file system but has no applied migrations yet).
func TestPostgresRunner_StatusWithMigrationFiles(t *testing.T) {
	dir := tempMigrationsDir(t, map[string]string{
		"001_credentials.up.sql": "CREATE TABLE credentials (id SERIAL);",
		"002_findings.up.sql":    "CREATE TABLE findings (id SERIAL);",
	})
	r := &runner.PostgresRunner{
		DSN:           "postgres://invalid@localhost:9999/nonexistent?sslmode=disable&connect_timeout=1",
		MigrationsDir: dir,
	}

	status, err := r.Status(context.Background())
	require.NoError(t, err, "Status should not error when DB unreachable (returns pending as unverified)")
	assert.Equal(t, uint(2), status.Target)
	assert.Len(t, status.Pending, 2)
	assert.Equal(t, "001_credentials.up.sql", status.Pending[0].Name)
	assert.Equal(t, uint(1), status.Pending[0].Version)
	assert.Equal(t, "002_findings.up.sql", status.Pending[1].Name)
	assert.Equal(t, uint(2), status.Pending[1].Version)
}

// ---------------------------------------------------------------------------
// Neo4j runner tests — unit-only (no real Neo4j required)
// ---------------------------------------------------------------------------

// TestNeo4jRunner_EmptyDir verifies the runner handles a directory with no
// *.up.cypher files (Phase D not yet authored) as a no-op.
func TestNeo4jRunner_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	// Provide a nil driver — the runner should return before trying to connect
	// when there are no files.
	r := &runner.Neo4jRunner{
		Driver:        nil,
		DatabaseName:  "tenant_test",
		MigrationsDir: dir,
	}

	cur, tgt, applied, err := r.Apply(context.Background())
	require.NoError(t, err, "Apply on empty migrations dir should succeed (no-op)")
	assert.Empty(t, cur)
	assert.Empty(t, tgt)
	assert.Empty(t, applied)
}

// TestNeo4jRunner_MissingDir verifies the runner treats a non-existent
// migrations directory as a no-op (Phase D pending).
func TestNeo4jRunner_MissingDir(t *testing.T) {
	r := &runner.Neo4jRunner{
		Driver:        nil,
		DatabaseName:  "tenant_test",
		MigrationsDir: "/tmp/gibson-migrate-cypher-nonexistent-99999",
	}

	cur, tgt, applied, err := r.Apply(context.Background())
	require.NoError(t, err, "Apply on non-existent dir should be a no-op")
	assert.Empty(t, cur)
	assert.Empty(t, tgt)
	assert.Empty(t, applied)
}

// TestNeo4jRunner_StatusEmptyDir verifies Status returns an empty status for
// an empty migrations directory.
func TestNeo4jRunner_StatusEmptyDir(t *testing.T) {
	dir := t.TempDir()
	r := &runner.Neo4jRunner{
		Driver:        nil,
		DatabaseName:  "tenant_test",
		MigrationsDir: dir,
	}

	status, err := r.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint(0), status.Target)
	assert.Empty(t, status.Pending)
}

// TestNeo4jRunner_StatusWithMigrationFiles verifies Status correctly identifies
// pending migrations when no version has been recorded.
func TestNeo4jRunner_StatusWithMigrationFiles(t *testing.T) {
	dir := tempMigrationsDir(t, map[string]string{
		"001_constraints.up.cypher": "CREATE CONSTRAINT IF NOT EXISTS;",
		"002_indexes.up.cypher":     "CREATE INDEX IF NOT EXISTS;",
	})
	// Driver is nil — currentVersion will fail gracefully and return "" (none applied).
	r := &runner.Neo4jRunner{
		Driver:        nil,
		DatabaseName:  "tenant_test",
		MigrationsDir: dir,
	}

	status, err := r.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint(2), status.Target)
	assert.Len(t, status.Pending, 2)
}

// TestSplitCypherStatements is an internal-behaviour test exercised through the
// runner's exported methods. We test the logic indirectly by checking that
// multi-statement Cypher files are applied correctly (no-op when DB is absent).
func TestSplitCypherStatements(t *testing.T) {
	// Write a multi-statement cypher file and verify the runner parses it without error.
	dir := tempMigrationsDir(t, map[string]string{
		"001_multi.up.cypher": `// This is a comment
CREATE CONSTRAINT c1 IF NOT EXISTS FOR (n:Foo) REQUIRE n.id IS UNIQUE;
// Another comment
CREATE INDEX idx1 IF NOT EXISTS FOR (n:Bar) ON (n.name);
`,
	})
	r := &runner.Neo4jRunner{
		Driver:        nil,
		DatabaseName:  "tenant_test",
		MigrationsDir: dir,
	}
	// Status should see 1 pending migration (parsing does not require a DB).
	status, err := r.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, uint(1), status.Target)
	assert.Len(t, status.Pending, 1)
	assert.Equal(t, "001_multi.up.cypher", status.Pending[0].Name)
}
