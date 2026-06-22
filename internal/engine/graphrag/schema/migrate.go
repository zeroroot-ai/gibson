// Package schema — migrate.go
//
// SchemaMigrator applies versioned Cypher migrations to the Neo4j graph
// database. Each migration lives in internal/engine/graphrag/schema/migrations/ as
// a .cypher file named <version>_<description>.cypher.
//
// Statements within a migration file are separated by blank lines.
// Line comments starting with // are stripped before execution.
//
// Migrations are identified by their basename (e.g., "0003_tenant_id_constraints").
// The migrator tracks which migrations have been applied in Neo4j via the node
// label :_GibsonSchemaMigration. Every statement uses IF NOT EXISTS guards so
// individual statements are safe to replay; the overall migration is considered
// applied when all its statements execute without returning an error that is not
// a constraint-violation on existing data.
//
// Failure modes:
//
//   - Constraint violation on existing data (legacy rows missing tenant_id):
//     The migrator records the violation count in the metric
//     gibson_graphrag_tenant_constraint_violations_total and returns an error
//     that the daemon wires into the /readyz probe (Degraded, not Unhealthy).
//
//   - All other Neo4j errors are returned as fatal errors that prevent startup.
//
// # Usage
//
//	m := schema.NewSchemaMigrator(client, logger)
//	if err := m.Run(ctx); err != nil {
//	    // readiness probe should fail, liveness probe should stay healthy
//	}
package schema

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
)

// ---------------------------------------------------------------------------
// Prometheus metrics (registered once per process)
// ---------------------------------------------------------------------------

var (
	metricsOnce                sync.Once
	tenantConstraintViolations prometheus.Counter
)

// initMigratorMetrics registers the Prometheus counter for tenant constraint
// violations. Uses sync.Once so it is safe to call from multiple test instances.
func initMigratorMetrics() {
	metricsOnce.Do(func() {
		tenantConstraintViolations = promauto.NewCounter(prometheus.CounterOpts{
			Name: "gibson_graphrag_tenant_constraint_violations_total",
			Help: "Total number of Neo4j constraint violations on tenant_id during schema migration. " +
				"A non-zero value means legacy rows without tenant_id exist and must be cleaned up " +
				"before the daemon passes its readiness probe.",
		})
	})
}

// ---------------------------------------------------------------------------
// Embedded migrations
// ---------------------------------------------------------------------------

//go:embed migrations/*.cypher
var migrationsFS embed.FS

// ---------------------------------------------------------------------------
// Migration registry
// ---------------------------------------------------------------------------

// migrations lists migration filenames (relative to the embedded FS root)
// in the order they should be applied. Each entry must have a corresponding
// file in the migrations/ directory.
//
// ADD NEW MIGRATIONS HERE — append only; never reorder or remove entries.
var migrations = []string{
	"migrations/0003_tenant_id_constraints.cypher",
}

// ---------------------------------------------------------------------------
// SchemaMigrator
// ---------------------------------------------------------------------------

// SchemaMigrator applies versioned Cypher migrations to Neo4j.
type SchemaMigrator struct {
	client graph.GraphClient
	logger *slog.Logger
}

// NewSchemaMigrator constructs a SchemaMigrator backed by the given graph client.
func NewSchemaMigrator(client graph.GraphClient, logger *slog.Logger) *SchemaMigrator {
	initMigratorMetrics()
	return &SchemaMigrator{
		client: client,
		logger: logger,
	}
}

// Run applies all registered migrations in order, skipping those that have
// already been applied.
//
// Returns an error if any migration fails. A constraint-violation error causes
// the metric gibson_graphrag_tenant_constraint_violations_total to increment;
// the error is still returned so that the caller (daemon startup) can fail the
// readiness probe without failing liveness.
func (m *SchemaMigrator) Run(ctx context.Context) error {
	if err := m.ensureMigrationTable(ctx); err != nil {
		return fmt.Errorf("schema migrator: ensure migration tracking: %w", err)
	}

	applied, err := m.appliedMigrations(ctx)
	if err != nil {
		return fmt.Errorf("schema migrator: list applied migrations: %w", err)
	}

	var violationErr error
	for _, filename := range migrations {
		migID := migrationID(filename)
		if applied[migID] {
			m.logger.Debug("schema migration already applied, skipping", "migration", migID)
			continue
		}

		m.logger.Info("applying schema migration", "migration", migID)
		if err := m.applyMigration(ctx, migID, filename); err != nil {
			if isConstraintViolation(err) {
				tenantConstraintViolations.Inc()
				m.logger.Warn("schema migration constraint violation — legacy rows missing tenant_id",
					"migration", migID,
					"error", err)
				violationErr = fmt.Errorf("schema migrator: %s: constraint violation on existing data "+
					"(legacy rows missing tenant_id must be cleaned up): %w", migID, err)
				continue // try remaining migrations; don't short-circuit
			}
			if isEnterpriseFeatureError(err) {
				// Non-fatal: Community Edition does not support property existence
				// constraints (REQUIRE n.prop IS NOT NULL). Log a warning and skip
				// so the daemon starts normally on Community Edition clusters.
				// Tenant isolation is enforced at the application layer instead.
				m.logger.Warn("schema migration skipped — Enterprise-only feature not available on this Neo4j edition; "+
					"tenant_id NOT NULL constraints require Neo4j Enterprise Edition",
					"migration", migID,
					"error", err)
				continue
			}
			return fmt.Errorf("schema migrator: %s: %w", migID, err)
		}

		if err := m.recordApplied(ctx, migID); err != nil {
			// Non-fatal: migration ran successfully; recording is best-effort.
			m.logger.Warn("schema migrator: failed to record migration as applied",
				"migration", migID,
				"error", err)
		}

		m.logger.Info("schema migration applied successfully", "migration", migID)
	}

	return violationErr
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// ensureMigrationTable creates the :_GibsonSchemaMigration node label and the
// uniqueness constraint that backs the applied-migrations ledger. Idempotent.
func (m *SchemaMigrator) ensureMigrationTable(ctx context.Context) error {
	_, err := m.client.Query(ctx, `
		CREATE CONSTRAINT IF NOT EXISTS FOR (n:_GibsonSchemaMigration)
		REQUIRE n.migration_id IS UNIQUE
	`, nil)
	return err
}

// appliedMigrations returns the set of migration IDs already recorded in Neo4j.
func (m *SchemaMigrator) appliedMigrations(ctx context.Context) (map[string]bool, error) {
	result, err := m.client.Query(ctx, `
		MATCH (n:_GibsonSchemaMigration)
		RETURN n.migration_id AS migration_id
	`, nil)
	if err != nil {
		return nil, err
	}
	applied := make(map[string]bool, len(result.Records))
	for _, rec := range result.Records {
		if id, ok := rec["migration_id"].(string); ok && id != "" {
			applied[id] = true
		}
	}
	return applied, nil
}

// applyMigration reads the Cypher file and executes each statement sequentially.
// Statements are separated by blank lines; line comments (//) are stripped.
func (m *SchemaMigrator) applyMigration(ctx context.Context, migID, filename string) error {
	data, err := migrationsFS.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read migration file %s: %w", filename, err)
	}

	statements := parseCypherStatements(string(data))
	for i, stmt := range statements {
		if _, err := m.client.Query(ctx, stmt, nil); err != nil {
			return fmt.Errorf("statement %d: %w", i+1, err)
		}
	}
	return nil
}

// recordApplied inserts a :_GibsonSchemaMigration node to mark the migration done.
func (m *SchemaMigrator) recordApplied(ctx context.Context, migID string) error {
	_, err := m.client.Query(ctx, `
		MERGE (n:_GibsonSchemaMigration {migration_id: $id})
		ON CREATE SET n.applied_at = datetime()
	`, map[string]any{"id": migID})
	return err
}

// migrationID derives a stable identifier from a migration filename.
// "migrations/0003_tenant_id_constraints.cypher" → "0003_tenant_id_constraints"
func migrationID(filename string) string {
	base := filename
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	base = strings.TrimSuffix(base, ".cypher")
	return base
}

// parseCypherStatements splits a Cypher file into individual statements.
// Rules:
//   - Lines beginning with // (after trimming) are comments and are stripped.
//   - Statements are separated by one or more blank lines (after comment removal).
//   - A statement must be non-empty after trimming whitespace.
func parseCypherStatements(content string) []string {
	var stmtLines []string
	var result []string

	flush := func() {
		stmt := strings.TrimSpace(strings.Join(stmtLines, "\n"))
		if stmt != "" {
			result = append(result, stmt)
		}
		stmtLines = nil
	}

	for _, line := range strings.Split(content, "\n") {
		stripped := strings.TrimSpace(line)
		// Skip comment lines.
		if strings.HasPrefix(stripped, "//") {
			continue
		}
		// Blank line (after comment removal) acts as statement separator.
		if stripped == "" {
			if len(stmtLines) > 0 {
				flush()
			}
			continue
		}
		stmtLines = append(stmtLines, line)
	}
	flush() // capture last statement
	return result
}

// isConstraintViolation reports whether the error is a Neo4j constraint
// violation, indicating that existing nodes fail the newly applied constraint.
// We match the string "ConstraintValidationFailed" which is the Neo4j driver
// error classification for this case.
func isConstraintViolation(err error) bool {
	return IsConstraintViolationError(err)
}

// isEnterpriseFeatureError reports whether the error indicates that the
// requested operation is only available in Neo4j Enterprise Edition.
//
// Property existence constraints (REQUIRE n.prop IS NOT NULL) are Enterprise-only.
// Community Edition returns Neo.ClientError.Statement.FeatureNotAvailable or a
// similar error. We match several known message patterns so the daemon starts
// cleanly on Community Edition clusters without those constraints enforced.
func isEnterpriseFeatureError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "FeatureNotAvailable") ||
		strings.Contains(msg, "Feature not available") ||
		strings.Contains(msg, "Enterprise Edition") ||
		strings.Contains(msg, "enterprise") ||
		strings.Contains(msg, "Unsupported administration command") ||
		(strings.Contains(msg, "IS NOT NULL") && strings.Contains(msg, "not supported"))
}

// IsConstraintViolationError reports whether err originated from a Neo4j
// constraint violation during schema migration (i.e. legacy rows that lack
// tenant_id failing the NOT NULL constraint). Exported so the daemon startup
// code can distinguish constraint violations — which only fail readiness — from
// other migration errors, which fail startup entirely.
func IsConstraintViolationError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "ConstraintValidationFailed") ||
		strings.Contains(msg, "ConstraintViolation") ||
		(strings.Contains(msg, "already exists") && strings.Contains(msg, "tenant_id")) ||
		strings.Contains(msg, "constraint violation on existing data")
}
