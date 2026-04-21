package schema

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"log/slog"
)

// ---------------------------------------------------------------------------
// Expected tenant-scoped labels
// ---------------------------------------------------------------------------

// expectedLabels lists every label that must appear in migration 0003.
// This is derived from the GraphLoader (loader/loader.go) node type strings
// and the taxonomy (core/sdk/taxonomy/core.yaml v4.0.0).
// If the loader gains a new node type it must also appear here (and in the
// migration file) — this test acts as the sentinel.
var expectedLabels = []string{
	"host",
	"port",
	"service",
	"endpoint",
	"domain",
	"subdomain",
	"technology",
	"certificate",
	"finding",
	"evidence",
	"technique",
	"compliance_signal",
}

// ---------------------------------------------------------------------------
// Migration file content assertions
// ---------------------------------------------------------------------------

// TestMigration0003_ContainsConstraintAndIndexForEveryLabel verifies that the
// embedded Cypher file 0003_tenant_id_constraints.cypher contains both a
// CREATE CONSTRAINT and a CREATE RANGE INDEX statement for every expected label.
// No live Neo4j instance is required.
func TestMigration0003_ContainsConstraintAndIndexForEveryLabel(t *testing.T) {
	data, err := migrationsFS.ReadFile("migrations/0003_tenant_id_constraints.cypher")
	require.NoError(t, err, "migration file must be readable from the embedded FS")

	content := string(data)

	for _, label := range expectedLabels {
		t.Run(label, func(t *testing.T) {
			constraintPattern := fmt.Sprintf("CREATE CONSTRAINT IF NOT EXISTS FOR (n:%s) REQUIRE n.tenant_id IS NOT NULL", label)
			assert.True(t,
				strings.Contains(content, constraintPattern),
				"migration must contain NOT NULL constraint for label %q; expected pattern:\n  %s", label, constraintPattern,
			)

			indexPattern := fmt.Sprintf("CREATE RANGE INDEX IF NOT EXISTS FOR (n:%s) ON (n.tenant_id)", label)
			assert.True(t,
				strings.Contains(content, indexPattern),
				"migration must contain RANGE INDEX for label %q; expected pattern:\n  %s", label, indexPattern,
			)
		})
	}
}

// TestMigration0003_StatementCount verifies the parser extracts the right number
// of statements (2 per label: one CONSTRAINT + one INDEX).
func TestMigration0003_StatementCount(t *testing.T) {
	data, err := migrationsFS.ReadFile("migrations/0003_tenant_id_constraints.cypher")
	require.NoError(t, err)

	statements := parseCypherStatements(string(data))
	expected := len(expectedLabels) * 2 // one CONSTRAINT + one INDEX per label
	assert.Equal(t, expected, len(statements),
		"expected %d statements (2 per label × %d labels), got %d",
		expected, len(expectedLabels), len(statements),
	)
}

// ---------------------------------------------------------------------------
// Migrator registration assertions
// ---------------------------------------------------------------------------

// TestMigrator_RegistersM0003 verifies that the migrations slice includes the
// 0003_tenant_id_constraints entry so it will actually be applied on startup.
func TestMigrator_RegistersM0003(t *testing.T) {
	const target = "migrations/0003_tenant_id_constraints.cypher"
	found := false
	for _, m := range migrations {
		if m == target {
			found = true
			break
		}
	}
	assert.True(t, found, "migrations slice must contain %q", target)
}

// ---------------------------------------------------------------------------
// Migrator behaviour with a mock graph client
// ---------------------------------------------------------------------------

// TestMigrator_AppliesMigrationsOnFreshDB verifies that Run() executes all
// migration statements on an empty database (no applied migrations recorded).
func TestMigrator_AppliesMigrationsOnFreshDB(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()
	_ = mock.Connect(ctx)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := NewSchemaMigrator(mock, logger)

	err := m.Run(ctx)
	assert.NoError(t, err)

	// ensureMigrationTable + appliedMigrations + each statement in 0003 +
	// recordApplied = more than zero Query calls.
	calls := mock.GetCallsByMethod("Query")
	assert.NotEmpty(t, calls, "Run() must issue Query calls against the graph client")
}

// TestMigrator_SkipsAlreadyAppliedMigration verifies that when the applied-
// migrations ledger already contains 0003, no Cypher statements from that
// migration are re-executed.
func TestMigrator_SkipsAlreadyAppliedMigration(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()
	_ = mock.Connect(ctx)

	// First result: ensureMigrationTable (empty)
	// Second result: appliedMigrations — reports 0003 already applied
	mock.SetQueryResults([]graph.QueryResult{
		{Records: []map[string]any{}, Columns: []string{}}, // ensureMigrationTable
		{
			Records: []map[string]any{
				{"migration_id": "0003_tenant_id_constraints"},
			},
			Columns: []string{"migration_id"},
		},
	})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := NewSchemaMigrator(mock, logger)
	err := m.Run(ctx)
	assert.NoError(t, err)

	// Only 2 queries should have been issued (ensureMigrationTable + appliedMigrations).
	// No migration-statement queries should follow.
	calls := mock.GetCallsByMethod("Query")
	assert.Equal(t, 2, len(calls),
		"when migration already applied, only 2 queries should run (tracking table + list)")
}

// TestMigrator_ReturnsConstraintViolationError verifies that when Neo4j
// returns a ConstraintValidationFailed error, Run() returns an error that
// IsConstraintViolationError identifies as such — so the daemon knows to
// fail readiness rather than liveness.
func TestMigrator_ReturnsConstraintViolationError(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()
	_ = mock.Connect(ctx)

	// Stub: no previously applied migrations.
	// The migration file execution will hit the queryError path on the first
	// CONSTRAINT statement.
	constraintErr := fmt.Errorf("ConstraintValidationFailed: unable to create constraint, existing nodes without tenant_id")
	// First call: ensureMigrationTable — succeed
	// Second call: appliedMigrations — return empty (none applied)
	// Third call: first statement of 0003 — return constraint violation
	mock.SetQueryResults([]graph.QueryResult{
		{Records: []map[string]any{}, Columns: []string{}}, // ensureMigrationTable
		{Records: []map[string]any{}, Columns: []string{}}, // appliedMigrations
	})
	// After the first two succeed, set the error for the migration statements.
	mock.SetQueryError(constraintErr)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := NewSchemaMigrator(mock, logger)
	err := m.Run(ctx)

	require.Error(t, err, "Run() must return an error on constraint violation")
	assert.True(t, IsConstraintViolationError(err),
		"error must be identifiable as a constraint violation so daemon can fail readiness not liveness")
}

// ---------------------------------------------------------------------------
// parseCypherStatements unit tests
// ---------------------------------------------------------------------------

func TestParseCypherStatements(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single statement",
			input: "CREATE CONSTRAINT IF NOT EXISTS FOR (n:foo) REQUIRE n.tenant_id IS NOT NULL;",
			want:  []string{"CREATE CONSTRAINT IF NOT EXISTS FOR (n:foo) REQUIRE n.tenant_id IS NOT NULL;"},
		},
		{
			name: "two statements separated by blank line",
			input: `CREATE CONSTRAINT IF NOT EXISTS FOR (n:foo) REQUIRE n.tenant_id IS NOT NULL;

CREATE RANGE INDEX IF NOT EXISTS FOR (n:foo) ON (n.tenant_id);`,
			want: []string{
				"CREATE CONSTRAINT IF NOT EXISTS FOR (n:foo) REQUIRE n.tenant_id IS NOT NULL;",
				"CREATE RANGE INDEX IF NOT EXISTS FOR (n:foo) ON (n.tenant_id);",
			},
		},
		{
			name: "comment lines stripped",
			input: `// This is a comment
CREATE CONSTRAINT IF NOT EXISTS FOR (n:bar) REQUIRE n.tenant_id IS NOT NULL;`,
			want: []string{
				"CREATE CONSTRAINT IF NOT EXISTS FOR (n:bar) REQUIRE n.tenant_id IS NOT NULL;",
			},
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "only comments",
			input: "// comment one\n// comment two\n",
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCypherStatements(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// migrationID unit tests
// ---------------------------------------------------------------------------

func TestMigrationID(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"migrations/0003_tenant_id_constraints.cypher", "0003_tenant_id_constraints"},
		{"0001_initial.cypher", "0001_initial"},
		{"migrations/sub/0002_foo.cypher", "0002_foo"},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			assert.Equal(t, tt.want, migrationID(tt.filename))
		})
	}
}

// ---------------------------------------------------------------------------
// IsConstraintViolationError unit tests
// ---------------------------------------------------------------------------

func TestIsConstraintViolationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "unrelated error", err: fmt.Errorf("connection refused"), want: false},
		{
			name: "ConstraintValidationFailed",
			err:  fmt.Errorf("ConstraintValidationFailed: cannot create constraint"),
			want: true,
		},
		{
			name: "ConstraintViolation",
			err:  fmt.Errorf("ConstraintViolation: node missing property"),
			want: true,
		},
		{
			name: "wrapped constraint violation message",
			err:  fmt.Errorf("schema migrator: 0003: constraint violation on existing data: %w", fmt.Errorf("inner")),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsConstraintViolationError(tt.err))
		})
	}
}
