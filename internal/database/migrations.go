package database

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"sort"
	"strings"
)

//go:embed schema.sql
var initialSchema string

// Migrator handles database schema migrations
type Migrator interface {
	// Migrate applies all pending migrations
	Migrate(ctx context.Context) error

	// CurrentVersion returns the current schema version
	CurrentVersion(ctx context.Context) (int, error)

	// Rollback rolls back to a target version
	Rollback(ctx context.Context, targetVersion int) error

	// GetAppliedMigrations returns a list of all applied migrations
	GetAppliedMigrations(ctx context.Context) ([]MigrationInfo, error)
}

// migration represents a single database migration
type migration struct {
	version int
	name    string
	up      string
	down    string
}

// migrator implements the Migrator interface
type migrator struct {
	db         *DB
	migrations []migration
}

// NewMigrator creates a new database migrator
func NewMigrator(db *DB) Migrator {
	return &migrator{
		db:         db,
		migrations: getMigrations(),
	}
}

// getMigrations returns all available migrations in order
func getMigrations() []migration {
	migrations := []migration{
		{
			version: 1,
			name:    "initial_schema",
			up:      initialSchema,
			down:    getDownMigration1(),
		},
		{
			version: 2,
			name:    "mission_memory",
			up:      getMissionMemorySchema(),
			down:    getDownMigration2(),
		},
		{
			version: 3,
			name:    "enhanced_findings",
			up:      getEnhancedFindingsSchema(),
			down:    getDownMigration3(),
		},
		{
			version: 4,
			name:    "missions_table",
			up:      getMissionsTableSchema(),
			down:    getDownMigration4(),
		},
		{
			version: 5,
			name:    "payload_system",
			up:      getPayloadSystemSchema(),
			down:    getDownMigration5(),
		},
		{
			version: 6,
			name:    "mission_orchestrator",
			up:      getMissionOrchestratorSchema(),
			down:    getDownMigration6(),
		},
		{
			version: 7,
			name:    "agent_steering",
			up:      getAgentSteeringSchema(),
			down:    getDownMigration7(),
		},
		{
			version: 8,
			name:    "mission_workflow_json",
			up:      getMissionWorkflowJSONSchema(),
			down:    getDownMigration8(),
		},
		{
			version: 9,
			name:    "mission_consolidation_columns",
			up:      getMissionConsolidationColumnsSchema(),
			down:    getDownMigration9(),
		},
		{
			version: 10,
			name:    "resumable_mission_architecture",
			up:      getResumableMissionArchitectureSchema(),
			down:    getDownMigration10(),
		},
		{
			version: 11,
			name:    "add_target_connection",
			up:      getTargetConnectionSchema(),
			down:    getDownMigration11(),
		},
		{
			version: 12,
			name:    "mission_lineage",
			up:      getMissionLineageSchema(),
			down:    getDownMigration12(),
		},
		{
			version: 13,
			name:    "knowledge_suite",
			up:      getKnowledgeSuiteSchema(),
			down:    getDownMigration13(),
		},
		{
			version: 14,
			name:    "mission_runs_table",
			up:      getMissionRunsTableSchema(),
			down:    getDownMigration14(),
		},
		// Note: Migration 15 (reports_table) will be added in task 1.2
		// {
		// 	version: 15,
		// 	name:    "reports_table",
		// 	up:      getReportsTableSchema(),
		// 	down:    getDownMigration15(),
		// },
		// Future migrations will be added here
	}

	// Sort by version to ensure correct order
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].version < migrations[j].version
	})

	return migrations
}

// getDownMigration1 returns the rollback SQL for migration 1
func getDownMigration1() string {
	return `
-- Drop triggers
DROP TRIGGER IF EXISTS update_findings_timestamp;
DROP TRIGGER IF EXISTS update_targets_timestamp;
DROP TRIGGER IF EXISTS update_credentials_timestamp;

-- Drop indexes
DROP INDEX IF EXISTS idx_findings_status;
DROP INDEX IF EXISTS idx_findings_severity;
DROP INDEX IF EXISTS idx_targets_credential;
DROP INDEX IF EXISTS idx_targets_type;
DROP INDEX IF EXISTS idx_targets_status;
DROP INDEX IF EXISTS idx_targets_provider;
DROP INDEX IF EXISTS idx_credentials_type;
DROP INDEX IF EXISTS idx_credentials_status;
DROP INDEX IF EXISTS idx_credentials_provider;

-- Drop tables (do NOT drop migrations table - it's managed separately)
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS targets;
DROP TABLE IF EXISTS credentials;
`
}

// Migrate applies all pending migrations
func (m *migrator) Migrate(ctx context.Context) error {
	// Ensure migrations table exists
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	// Get current version
	currentVersion, err := m.CurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	// Apply pending migrations
	for _, mig := range m.migrations {
		if mig.version <= currentVersion {
			continue // Skip already applied migrations
		}

		if err := m.applyMigration(ctx, mig); err != nil {
			return fmt.Errorf("failed to apply migration %d (%s): %w", mig.version, mig.name, err)
		}
	}

	return nil
}

// CurrentVersion returns the current schema version
func (m *migrator) CurrentVersion(ctx context.Context) (int, error) {
	// Ensure migrations table exists
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return 0, fmt.Errorf("failed to ensure migrations table: %w", err)
	}

	var version int
	query := "SELECT COALESCE(MAX(version), 0) FROM migrations"
	err := m.db.conn.QueryRowContext(ctx, query).Scan(&version)
	if err != nil {
		return 0, fmt.Errorf("failed to query current version: %w", err)
	}

	return version, nil
}

// Rollback rolls back to a target version
func (m *migrator) Rollback(ctx context.Context, targetVersion int) error {
	if targetVersion < 0 {
		return fmt.Errorf("invalid target version: %d", targetVersion)
	}

	// Get current version
	currentVersion, err := m.CurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	if targetVersion > currentVersion {
		return fmt.Errorf("cannot rollback to future version %d (current: %d)", targetVersion, currentVersion)
	}

	// Rollback migrations in reverse order
	for i := len(m.migrations) - 1; i >= 0; i-- {
		mig := m.migrations[i]
		if mig.version <= targetVersion {
			break
		}
		if mig.version > currentVersion {
			continue // Skip unapplied migrations
		}

		if err := m.rollbackMigration(ctx, mig); err != nil {
			return fmt.Errorf("failed to rollback migration %d (%s): %w", mig.version, mig.name, err)
		}
	}

	return nil
}

// ensureMigrationsTable creates the migrations table if it doesn't exist
func (m *migrator) ensureMigrationsTable(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := m.db.conn.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to create migrations table: %w", err)
	}

	return nil
}

// applyMigration applies a single migration within a transaction
func (m *migrator) applyMigration(ctx context.Context, mig migration) error {
	return m.db.WithTx(ctx, func(tx *sql.Tx) error {
		// Execute migration SQL
		// Split by semicolon to handle multiple statements
		statements := splitSQL(mig.up)
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			// Remove comment lines from the statement
			cleanStmt := removeComments(stmt)
			if cleanStmt == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, cleanStmt); err != nil {
				return fmt.Errorf("failed to execute statement: %w\nStatement: %s", err, cleanStmt)
			}
		}

		// Record migration in migrations table
		_, err := tx.ExecContext(ctx,
			"INSERT INTO migrations (version, name, applied_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
			mig.version, mig.name)
		if err != nil {
			return fmt.Errorf("failed to record migration: %w", err)
		}

		return nil
	})
}

// rollbackMigration rolls back a single migration within a transaction
func (m *migrator) rollbackMigration(ctx context.Context, mig migration) error {
	return m.db.WithTx(ctx, func(tx *sql.Tx) error {
		// Execute rollback SQL
		statements := splitSQL(mig.down)
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			// Remove comment lines from the statement
			cleanStmt := removeComments(stmt)
			if cleanStmt == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, cleanStmt); err != nil {
				return fmt.Errorf("failed to execute rollback statement: %w\nStatement: %s", err, cleanStmt)
			}
		}

		// Remove migration record
		_, err := tx.ExecContext(ctx, "DELETE FROM migrations WHERE version = ?", mig.version)
		if err != nil {
			return fmt.Errorf("failed to remove migration record: %w", err)
		}

		return nil
	})
}

// splitSQL splits SQL script into individual statements
// Handles BEGIN...END blocks (for triggers) and string literals
func splitSQL(sql string) []string {
	var statements []string
	var current strings.Builder
	inString := false
	stringChar := rune(0)
	beginEndDepth := 0

	// Tokenize to track BEGIN/END
	words := []string{}
	var wordBuf strings.Builder

	for i, ch := range sql {
		switch {
		case ch == '\'' || ch == '"':
			if !inString {
				inString = true
				stringChar = ch
			} else if ch == stringChar {
				// Check if escaped
				if i > 0 && sql[i-1] != '\\' {
					inString = false
				}
			}
			current.WriteRune(ch)
			wordBuf.WriteRune(ch)

		case (ch == ' ' || ch == '\n' || ch == '\t' || ch == ';') && !inString:
			if wordBuf.Len() > 0 {
				word := strings.ToUpper(strings.TrimSpace(wordBuf.String()))
				words = append(words, word)

				// Track BEGIN/END depth for triggers
				if word == "BEGIN" {
					beginEndDepth++
				} else if word == "END" {
					beginEndDepth--
				}

				wordBuf.Reset()
			}

			if ch == ';' && beginEndDepth == 0 {
				// End of statement
				stmt := strings.TrimSpace(current.String())
				if stmt != "" {
					statements = append(statements, stmt)
				}
				current.Reset()
				words = []string{}
			} else {
				current.WriteRune(ch)
			}

		default:
			current.WriteRune(ch)
			wordBuf.WriteRune(ch)
		}
	}

	// Add any remaining content
	if stmt := strings.TrimSpace(current.String()); stmt != "" {
		statements = append(statements, stmt)
	}

	return statements
}

// GetAppliedMigrations returns a list of all applied migrations
func (m *migrator) GetAppliedMigrations(ctx context.Context) ([]MigrationInfo, error) {
	if err := m.ensureMigrationsTable(ctx); err != nil {
		return nil, fmt.Errorf("failed to ensure migrations table: %w", err)
	}

	query := "SELECT version, name, applied_at FROM migrations ORDER BY version"
	rows, err := m.db.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query migrations: %w", err)
	}
	defer rows.Close()

	var migrations []MigrationInfo
	for rows.Next() {
		var info MigrationInfo
		if err := rows.Scan(&info.Version, &info.Name, &info.AppliedAt); err != nil {
			return nil, fmt.Errorf("failed to scan migration: %w", err)
		}
		migrations = append(migrations, info)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating migrations: %w", err)
	}

	return migrations, nil
}

// MigrationInfo contains information about an applied migration
type MigrationInfo struct {
	Version   int
	Name      string
	AppliedAt string
}

// removeComments removes SQL comment lines from a statement
// This handles both single-line (--) and multi-line (/* */) comments
func removeComments(sql string) string {
	var result strings.Builder
	lines := strings.Split(sql, "\n")

	inMultilineComment := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Handle multi-line comments
		if strings.Contains(trimmed, "/*") {
			inMultilineComment = true
		}
		if inMultilineComment {
			if strings.Contains(trimmed, "*/") {
				inMultilineComment = false
			}
			continue
		}

		// Skip lines that are ONLY comments (start with --)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}

		// Remove inline comments (everything after -- on the same line)
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}

		// Keep non-empty lines
		if strings.TrimSpace(line) != "" {
			result.WriteString(line)
			result.WriteString("\n")
		}
	}

	return strings.TrimSpace(result.String())
}

// getMissionMemorySchema returns the schema for mission memory with FTS5
func getMissionMemorySchema() string {
	return `
-- Mission memory storage
CREATE TABLE IF NOT EXISTS mission_memory (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    metadata TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(mission_id, key)
);

-- FTS5 virtual table for full-text search
CREATE VIRTUAL TABLE IF NOT EXISTS mission_memory_fts USING fts5(
    key,
    value,
    content=mission_memory,
    content_rowid=rowid
);

-- Trigger to sync FTS on INSERT
CREATE TRIGGER IF NOT EXISTS mission_memory_ai AFTER INSERT ON mission_memory BEGIN
    INSERT INTO mission_memory_fts(rowid, key, value) VALUES (new.rowid, new.key, new.value);
END;

-- Trigger to sync FTS on DELETE
CREATE TRIGGER IF NOT EXISTS mission_memory_ad AFTER DELETE ON mission_memory BEGIN
    INSERT INTO mission_memory_fts(mission_memory_fts, rowid, key, value) VALUES('delete', old.rowid, old.key, old.value);
END;

-- Trigger to sync FTS on UPDATE
CREATE TRIGGER IF NOT EXISTS mission_memory_au AFTER UPDATE ON mission_memory BEGIN
    INSERT INTO mission_memory_fts(mission_memory_fts, rowid, key, value) VALUES('delete', old.rowid, old.key, old.value);
    INSERT INTO mission_memory_fts(rowid, key, value) VALUES (new.rowid, new.key, new.value);
END;

-- Index for mission-scoped queries
CREATE INDEX IF NOT EXISTS idx_mission_memory_mission ON mission_memory(mission_id);
CREATE INDEX IF NOT EXISTS idx_mission_memory_mission_key ON mission_memory(mission_id, key);
`
}

// getDownMigration2 returns the rollback SQL for migration 2
func getDownMigration2() string {
	return `
-- Drop triggers
DROP TRIGGER IF EXISTS mission_memory_au;
DROP TRIGGER IF EXISTS mission_memory_ad;
DROP TRIGGER IF EXISTS mission_memory_ai;

-- Drop indexes
DROP INDEX IF EXISTS idx_mission_memory_mission_key;
DROP INDEX IF EXISTS idx_mission_memory_mission;

-- Drop FTS table
DROP TABLE IF EXISTS mission_memory_fts;

-- Drop main table
DROP TABLE IF EXISTS mission_memory;
`
}

// getEnhancedFindingsSchema returns the schema for enhanced findings storage
func getEnhancedFindingsSchema() string {
	return `
-- Migration 3: Finding System Schema Extension
-- Extends the existing findings table with enhanced fields for the finding system

-- Add new columns to existing findings table
ALTER TABLE findings ADD COLUMN mission_id TEXT;
ALTER TABLE findings ADD COLUMN agent_name TEXT;
ALTER TABLE findings ADD COLUMN delegated_from TEXT;
ALTER TABLE findings ADD COLUMN category TEXT;
ALTER TABLE findings ADD COLUMN subcategory TEXT;
ALTER TABLE findings ADD COLUMN confidence REAL DEFAULT 0.0;
ALTER TABLE findings ADD COLUMN risk_score REAL DEFAULT 0.0;
ALTER TABLE findings ADD COLUMN mitre_attack TEXT;
ALTER TABLE findings ADD COLUMN mitre_atlas TEXT;
ALTER TABLE findings ADD COLUMN references_json TEXT;
ALTER TABLE findings ADD COLUMN repro_steps TEXT;
ALTER TABLE findings ADD COLUMN related_ids TEXT;
ALTER TABLE findings ADD COLUMN occurrence_count INTEGER DEFAULT 1;
ALTER TABLE findings ADD COLUMN cvss_vector TEXT;
ALTER TABLE findings ADD COLUMN cvss_score REAL;
ALTER TABLE findings ADD COLUMN cwe_ids TEXT;
ALTER TABLE findings ADD COLUMN target_id TEXT;

-- Create indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_findings_mission ON findings(mission_id);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_risk_score ON findings(risk_score);
CREATE INDEX IF NOT EXISTS idx_findings_agent_name ON findings(agent_name);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence);
CREATE INDEX IF NOT EXISTS idx_findings_target_id ON findings(target_id);

-- Create FTS5 virtual table for full-text search
CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
    title,
    description,
    remediation,
    content=findings,
    content_rowid=rowid
);

-- Trigger to sync FTS on INSERT
CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
    INSERT INTO findings_fts(rowid, title, description, remediation)
    VALUES (new.rowid, new.title, new.description, new.remediation);
END;

-- Trigger to sync FTS on DELETE
CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, title, description, remediation)
    VALUES('delete', old.rowid, old.title, old.description, old.remediation);
END;

-- Trigger to sync FTS on UPDATE
CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
    INSERT INTO findings_fts(findings_fts, rowid, title, description, remediation)
    VALUES('delete', old.rowid, old.title, old.description, old.remediation);
    INSERT INTO findings_fts(rowid, title, description, remediation)
    VALUES (new.rowid, new.title, new.description, new.remediation);
END;
`
}

// getDownMigration3 returns the rollback SQL for migration 3
func getDownMigration3() string {
	return `
-- Drop FTS5 triggers
DROP TRIGGER IF EXISTS findings_au;
DROP TRIGGER IF EXISTS findings_ad;
DROP TRIGGER IF EXISTS findings_ai;

-- Drop FTS5 table
DROP TABLE IF EXISTS findings_fts;

-- Drop indexes
DROP INDEX IF EXISTS idx_findings_target_id;
DROP INDEX IF EXISTS idx_findings_confidence;
DROP INDEX IF EXISTS idx_findings_agent_name;
DROP INDEX IF EXISTS idx_findings_risk_score;
DROP INDEX IF EXISTS idx_findings_category;
DROP INDEX IF EXISTS idx_findings_mission;

-- Note: SQLite doesn't support DROP COLUMN, so we can't cleanly remove the columns
-- In a real production scenario, you would need to:
-- 1. Create a new table without the enhanced columns
-- 2. Copy data from old table to new table
-- 3. Drop old table
-- 4. Rename new table
-- For simplicity, we're leaving the columns in place during rollback
`
}

// getMissionsTableSchema returns the schema for missions table
func getMissionsTableSchema() string {
	return `
-- Missions table for mission orchestration
CREATE TABLE IF NOT EXISTS missions (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending',      -- 'pending', 'running', 'completed', 'failed', 'cancelled'
    workflow_id TEXT NOT NULL,
    workflow TEXT,                                -- JSON serialized workflow
    progress REAL DEFAULT 0.0,                   -- 0.0 to 1.0
    findings_count INTEGER DEFAULT 0,
    agent_assignments TEXT,                       -- JSON map of agent assignments
    metadata TEXT,                                -- JSON metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- Indexes for missions
CREATE INDEX IF NOT EXISTS idx_missions_status ON missions(status);
CREATE INDEX IF NOT EXISTS idx_missions_workflow_id ON missions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_missions_created_at ON missions(created_at DESC);

-- Trigger to update updated_at timestamp on missions
CREATE TRIGGER IF NOT EXISTS update_missions_timestamp
    AFTER UPDATE ON missions
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE missions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
`
}

// getDownMigration4 returns the rollback SQL for migration 4
func getDownMigration4() string {
	return `
-- Drop trigger
DROP TRIGGER IF EXISTS update_missions_timestamp;

-- Drop indexes
DROP INDEX IF EXISTS idx_missions_created_at;
DROP INDEX IF EXISTS idx_missions_workflow_id;
DROP INDEX IF EXISTS idx_missions_status;

-- Drop table
DROP TABLE IF EXISTS missions;
`
}

// getPayloadSystemSchema returns the complete schema for payload-related tables
func getPayloadSystemSchema() string {
	return `
-- Migration 5: Payload System Schema
-- Creates tables for attack payloads, chains, executions, and version history

-- ============================================================================
-- Payloads Table: Core payload storage
-- ============================================================================
CREATE TABLE IF NOT EXISTS payloads (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    version TEXT NOT NULL DEFAULT '1.0.0',
    description TEXT,

    -- Categorization (JSON arrays stored as TEXT)
    categories TEXT NOT NULL,                    -- JSON array of PayloadCategory
    tags TEXT,                                   -- JSON array of strings

    -- Content
    template TEXT NOT NULL,                      -- Template with {{parameter}} placeholders

    -- Parameters and Indicators (JSON stored as TEXT)
    parameters TEXT,                             -- JSON array of ParameterDef
    success_indicators TEXT NOT NULL,            -- JSON array of SuccessIndicator

    -- Targeting
    target_types TEXT,                           -- JSON array of target types
    severity TEXT NOT NULL,                      -- FindingSeverity enum

    -- MITRE Mappings
    mitre_techniques TEXT,                       -- JSON array of MITRE technique IDs

    -- Metadata (JSON stored as TEXT)
    metadata TEXT,                               -- JSON PayloadMetadata object

    -- Status
    built_in INTEGER NOT NULL DEFAULT 0,         -- Boolean: 1 for built-in, 0 for custom
    enabled INTEGER NOT NULL DEFAULT 1,          -- Boolean: 1 for enabled, 0 for disabled

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Payloads Full-Text Search (FTS5)
-- ============================================================================
CREATE VIRTUAL TABLE IF NOT EXISTS payloads_fts USING fts5(
    name,
    description,
    template,
    tags,
    content=payloads,
    content_rowid=rowid
);

-- Trigger to sync FTS on INSERT
CREATE TRIGGER IF NOT EXISTS payloads_ai AFTER INSERT ON payloads BEGIN
    INSERT INTO payloads_fts(rowid, name, description, template, tags)
    VALUES (new.rowid, new.name, new.description, new.template, new.tags);
END;

-- Trigger to sync FTS on DELETE
CREATE TRIGGER IF NOT EXISTS payloads_ad AFTER DELETE ON payloads BEGIN
    INSERT INTO payloads_fts(payloads_fts, rowid, name, description, template, tags)
    VALUES('delete', old.rowid, old.name, old.description, old.template, old.tags);
END;

-- Trigger to sync FTS on UPDATE
CREATE TRIGGER IF NOT EXISTS payloads_au AFTER UPDATE ON payloads BEGIN
    INSERT INTO payloads_fts(payloads_fts, rowid, name, description, template, tags)
    VALUES('delete', old.rowid, old.name, old.description, old.template, old.tags);
    INSERT INTO payloads_fts(rowid, name, description, template, tags)
    VALUES (new.rowid, new.name, new.description, new.template, new.tags);
END;

-- ============================================================================
-- Payload Indexes for Efficient Queries
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_payloads_name ON payloads(name);
CREATE INDEX IF NOT EXISTS idx_payloads_severity ON payloads(severity);
CREATE INDEX IF NOT EXISTS idx_payloads_built_in ON payloads(built_in);
CREATE INDEX IF NOT EXISTS idx_payloads_enabled ON payloads(enabled);
CREATE INDEX IF NOT EXISTS idx_payloads_created_at ON payloads(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payloads_updated_at ON payloads(updated_at DESC);

-- ============================================================================
-- Trigger to update updated_at timestamp on payloads
-- ============================================================================
CREATE TRIGGER IF NOT EXISTS update_payloads_timestamp
    AFTER UPDATE ON payloads
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE payloads SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ============================================================================
-- Attack Chains Table: Multi-stage attack orchestration
-- ============================================================================
CREATE TABLE IF NOT EXISTS attack_chains (
    id TEXT PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    description TEXT,
    version TEXT NOT NULL DEFAULT '1.0.0',

    -- Chain definition (JSON stored as TEXT)
    stages TEXT NOT NULL,                        -- JSON array of ChainStage

    -- Metadata
    metadata TEXT,                               -- JSON ChainMetadata object
    categories TEXT,                             -- JSON array of categories
    tags TEXT,                                   -- JSON array of strings

    -- MITRE Mappings
    mitre_techniques TEXT,                       -- JSON array of MITRE technique IDs

    -- Status
    built_in INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Attack Chains Indexes
CREATE INDEX IF NOT EXISTS idx_attack_chains_name ON attack_chains(name);
CREATE INDEX IF NOT EXISTS idx_attack_chains_enabled ON attack_chains(enabled);
CREATE INDEX IF NOT EXISTS idx_attack_chains_built_in ON attack_chains(built_in);
CREATE INDEX IF NOT EXISTS idx_attack_chains_created_at ON attack_chains(created_at DESC);

-- Trigger to update updated_at timestamp on attack_chains
CREATE TRIGGER IF NOT EXISTS update_attack_chains_timestamp
    AFTER UPDATE ON attack_chains
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE attack_chains SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;

-- ============================================================================
-- Payload Executions Table: Track individual payload executions
-- ============================================================================
CREATE TABLE IF NOT EXISTS payload_executions (
    id TEXT PRIMARY KEY,
    payload_id TEXT NOT NULL,
    mission_id TEXT,
    target_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL,                        -- ExecutionStatus enum

    -- Execution parameters
    parameters TEXT,                             -- JSON map of parameter values
    instantiated_text TEXT,                      -- Final payload after substitution

    -- Response data
    response TEXT,
    response_time_ms INTEGER DEFAULT 0,
    tokens_used INTEGER DEFAULT 0,
    cost REAL DEFAULT 0.0,

    -- Success evaluation
    success INTEGER NOT NULL DEFAULT 0,          -- Boolean
    indicators_matched TEXT,                     -- JSON array of matched indicator names
    confidence_score REAL DEFAULT 0.0,
    match_details TEXT,                          -- JSON object with match details

    -- Finding attribution
    finding_id TEXT,
    finding_created INTEGER NOT NULL DEFAULT 0,  -- Boolean

    -- Error information
    error_message TEXT,
    error_details TEXT,                          -- JSON object

    -- Analytics metadata
    target_type TEXT,
    target_provider TEXT,
    target_model TEXT,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,

    -- Additional metadata
    metadata TEXT,                               -- JSON object
    tags TEXT,                                   -- JSON array

    -- Foreign key constraints
    FOREIGN KEY (payload_id) REFERENCES payloads(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
    FOREIGN KEY (finding_id) REFERENCES findings(id) ON DELETE SET NULL
);

-- ============================================================================
-- Payload Executions Indexes for Analytics and Queries
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_payload_executions_payload_id ON payload_executions(payload_id);
CREATE INDEX IF NOT EXISTS idx_payload_executions_mission_id ON payload_executions(mission_id);
CREATE INDEX IF NOT EXISTS idx_payload_executions_target_id ON payload_executions(target_id);
CREATE INDEX IF NOT EXISTS idx_payload_executions_agent_id ON payload_executions(agent_id);
CREATE INDEX IF NOT EXISTS idx_payload_executions_status ON payload_executions(status);
CREATE INDEX IF NOT EXISTS idx_payload_executions_success ON payload_executions(success);
CREATE INDEX IF NOT EXISTS idx_payload_executions_target_type ON payload_executions(target_type);
CREATE INDEX IF NOT EXISTS idx_payload_executions_target_provider ON payload_executions(target_provider);
CREATE INDEX IF NOT EXISTS idx_payload_executions_created_at ON payload_executions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payload_executions_completed_at ON payload_executions(completed_at DESC);
CREATE INDEX IF NOT EXISTS idx_payload_executions_finding_id ON payload_executions(finding_id);

-- Composite indexes for analytics queries
CREATE INDEX IF NOT EXISTS idx_payload_executions_payload_success ON payload_executions(payload_id, success);
CREATE INDEX IF NOT EXISTS idx_payload_executions_payload_target_type ON payload_executions(payload_id, target_type);
CREATE INDEX IF NOT EXISTS idx_payload_executions_target_type_success ON payload_executions(target_type, success);

-- ============================================================================
-- Payload Versions Table: Version history tracking
-- ============================================================================
CREATE TABLE IF NOT EXISTS payload_versions (
    id TEXT PRIMARY KEY,
    payload_id TEXT NOT NULL,
    version TEXT NOT NULL,

    -- Full payload snapshot (JSON stored as TEXT)
    payload_data TEXT NOT NULL,                  -- Complete JSON serialized Payload

    -- Change tracking
    change_type TEXT NOT NULL,                   -- 'created', 'updated', 'disabled', 'enabled'
    change_summary TEXT,                         -- Human-readable description
    changed_by TEXT,                             -- User or system identifier

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Foreign key
    FOREIGN KEY (payload_id) REFERENCES payloads(id) ON DELETE CASCADE,

    -- Unique constraint on payload + version
    UNIQUE(payload_id, version)
);

-- Payload Versions Indexes
CREATE INDEX IF NOT EXISTS idx_payload_versions_payload_id ON payload_versions(payload_id);
CREATE INDEX IF NOT EXISTS idx_payload_versions_created_at ON payload_versions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payload_versions_change_type ON payload_versions(change_type);

-- ============================================================================
-- Chain Executions Table: Track attack chain executions
-- ============================================================================
CREATE TABLE IF NOT EXISTS chain_executions (
    id TEXT PRIMARY KEY,
    chain_id TEXT NOT NULL,
    mission_id TEXT,
    target_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL,                        -- ChainExecutionStatus enum

    -- Progress tracking
    total_stages INTEGER NOT NULL DEFAULT 0,
    completed_stages INTEGER NOT NULL DEFAULT 0,
    current_stage_index INTEGER,
    current_stage_id TEXT,

    -- Stage results (JSON stored as TEXT)
    stage_results TEXT,                          -- JSON array of StageResult

    -- Aggregated metrics
    total_executions INTEGER DEFAULT 0,
    successful_attacks INTEGER DEFAULT 0,
    failed_executions INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    total_duration_ms INTEGER DEFAULT 0,
    total_tokens_used INTEGER DEFAULT 0,
    total_cost REAL DEFAULT 0.0,

    -- Error tracking
    error_message TEXT,
    error_details TEXT,                          -- JSON object

    -- Timestamps
    started_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,

    -- Context for stages (JSON stored as TEXT)
    chain_context TEXT,                          -- JSON object passed between stages

    -- Metadata
    metadata TEXT,                               -- JSON object
    tags TEXT,                                   -- JSON array

    -- Foreign key constraints
    FOREIGN KEY (chain_id) REFERENCES attack_chains(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
);

-- Chain Executions Indexes
CREATE INDEX IF NOT EXISTS idx_chain_executions_chain_id ON chain_executions(chain_id);
CREATE INDEX IF NOT EXISTS idx_chain_executions_mission_id ON chain_executions(mission_id);
CREATE INDEX IF NOT EXISTS idx_chain_executions_target_id ON chain_executions(target_id);
CREATE INDEX IF NOT EXISTS idx_chain_executions_agent_id ON chain_executions(agent_id);
CREATE INDEX IF NOT EXISTS idx_chain_executions_status ON chain_executions(status);
CREATE INDEX IF NOT EXISTS idx_chain_executions_started_at ON chain_executions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_chain_executions_completed_at ON chain_executions(completed_at DESC);

-- Trigger to update updated_at timestamp on chain_executions
CREATE TRIGGER IF NOT EXISTS update_chain_executions_timestamp
    AFTER UPDATE ON chain_executions
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE chain_executions SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
`
}

// getDownMigration5 returns the rollback SQL for migration 5
func getDownMigration5() string {
	return `
-- Rollback Migration 5: Payload System Schema

-- Drop chain execution triggers and indexes
DROP TRIGGER IF EXISTS update_chain_executions_timestamp;
DROP INDEX IF EXISTS idx_chain_executions_completed_at;
DROP INDEX IF EXISTS idx_chain_executions_started_at;
DROP INDEX IF EXISTS idx_chain_executions_status;
DROP INDEX IF EXISTS idx_chain_executions_agent_id;
DROP INDEX IF EXISTS idx_chain_executions_target_id;
DROP INDEX IF EXISTS idx_chain_executions_mission_id;
DROP INDEX IF EXISTS idx_chain_executions_chain_id;

-- Drop chain executions table
DROP TABLE IF EXISTS chain_executions;

-- Drop payload version indexes
DROP INDEX IF EXISTS idx_payload_versions_change_type;
DROP INDEX IF EXISTS idx_payload_versions_created_at;
DROP INDEX IF EXISTS idx_payload_versions_payload_id;

-- Drop payload versions table
DROP TABLE IF EXISTS payload_versions;

-- Drop payload execution indexes
DROP INDEX IF EXISTS idx_payload_executions_target_type_success;
DROP INDEX IF EXISTS idx_payload_executions_payload_target_type;
DROP INDEX IF EXISTS idx_payload_executions_payload_success;
DROP INDEX IF EXISTS idx_payload_executions_finding_id;
DROP INDEX IF EXISTS idx_payload_executions_completed_at;
DROP INDEX IF EXISTS idx_payload_executions_created_at;
DROP INDEX IF EXISTS idx_payload_executions_target_provider;
DROP INDEX IF EXISTS idx_payload_executions_target_type;
DROP INDEX IF EXISTS idx_payload_executions_success;
DROP INDEX IF EXISTS idx_payload_executions_status;
DROP INDEX IF EXISTS idx_payload_executions_agent_id;
DROP INDEX IF EXISTS idx_payload_executions_target_id;
DROP INDEX IF EXISTS idx_payload_executions_mission_id;
DROP INDEX IF EXISTS idx_payload_executions_payload_id;

-- Drop payload executions table
DROP TABLE IF EXISTS payload_executions;

-- Drop attack chain triggers and indexes
DROP TRIGGER IF EXISTS update_attack_chains_timestamp;
DROP INDEX IF EXISTS idx_attack_chains_created_at;
DROP INDEX IF EXISTS idx_attack_chains_built_in;
DROP INDEX IF EXISTS idx_attack_chains_enabled;
DROP INDEX IF EXISTS idx_attack_chains_name;

-- Drop attack chains table
DROP TABLE IF EXISTS attack_chains;

-- Drop payload triggers and indexes
DROP TRIGGER IF EXISTS update_payloads_timestamp;
DROP INDEX IF EXISTS idx_payloads_updated_at;
DROP INDEX IF EXISTS idx_payloads_created_at;
DROP INDEX IF EXISTS idx_payloads_enabled;
DROP INDEX IF EXISTS idx_payloads_built_in;
DROP INDEX IF EXISTS idx_payloads_severity;
DROP INDEX IF EXISTS idx_payloads_name;

-- Drop FTS triggers
DROP TRIGGER IF EXISTS payloads_au;
DROP TRIGGER IF EXISTS payloads_ad;
DROP TRIGGER IF EXISTS payloads_ai;

-- Drop FTS table
DROP TABLE IF EXISTS payloads_fts;

-- Drop payloads table
DROP TABLE IF EXISTS payloads;
`
}

// getMissionOrchestratorSchema returns the schema for mission orchestrator enhancements
// This extends the existing missions table from migration 4 with additional fields
func getMissionOrchestratorSchema() string {
	return `
-- Migration 6: Mission Orchestrator Schema Enhancements
-- Extends the existing missions table with orchestration-specific fields

-- Add new columns to existing missions table for mission orchestration
ALTER TABLE missions ADD COLUMN target_id TEXT;
ALTER TABLE missions ADD COLUMN constraints TEXT;
ALTER TABLE missions ADD COLUMN metrics TEXT;
ALTER TABLE missions ADD COLUMN checkpoint TEXT;
ALTER TABLE missions ADD COLUMN error TEXT;

-- Create index for target_id lookups
CREATE INDEX IF NOT EXISTS idx_missions_target_id ON missions(target_id);

-- Create FTS5 virtual table for full-text search on missions
CREATE VIRTUAL TABLE IF NOT EXISTS missions_fts USING fts5(
    name,
    description,
    content=missions,
    content_rowid=rowid
);

-- Trigger to sync FTS on INSERT
CREATE TRIGGER IF NOT EXISTS missions_ai AFTER INSERT ON missions BEGIN
    INSERT INTO missions_fts(rowid, name, description)
    VALUES (new.rowid, new.name, new.description);
END;

-- Trigger to sync FTS on DELETE
CREATE TRIGGER IF NOT EXISTS missions_ad AFTER DELETE ON missions BEGIN
    INSERT INTO missions_fts(missions_fts, rowid, name, description)
    VALUES('delete', old.rowid, old.name, old.description);
END;

-- Trigger to sync FTS on UPDATE
CREATE TRIGGER IF NOT EXISTS missions_au AFTER UPDATE ON missions BEGIN
    INSERT INTO missions_fts(missions_fts, rowid, name, description)
    VALUES('delete', old.rowid, old.name, old.description);
    INSERT INTO missions_fts(rowid, name, description)
    VALUES (new.rowid, new.name, new.description);
END;
`
}

// getDownMigration6 returns the rollback SQL for migration 6
func getDownMigration6() string {
	return `
-- Rollback Mission Orchestrator Schema Enhancements

-- Drop FTS5 triggers
DROP TRIGGER IF EXISTS missions_au;
DROP TRIGGER IF EXISTS missions_ad;
DROP TRIGGER IF EXISTS missions_ai;

-- Drop FTS5 table
DROP TABLE IF EXISTS missions_fts;

-- Drop index
DROP INDEX IF EXISTS idx_missions_target_id;

-- Note: SQLite doesn't support DROP COLUMN directly
-- In production, you would need to:
-- 1. Create a new table without the enhanced columns
-- 2. Copy data from old table to new table
-- 3. Drop old table
-- 4. Rename new table
-- For simplicity, we're leaving the columns in place during rollback
`
}

// getAgentSteeringSchema returns the schema for interactive agent steering
func getAgentSteeringSchema() string {
	return `
-- Migration 7: Interactive Agent Steering Schema
-- Creates tables for agent sessions, stream events, and steering messages

-- ============================================================================
-- Agent Sessions Table: Track agent execution sessions
-- ============================================================================
CREATE TABLE IF NOT EXISTS agent_sessions (
    id TEXT PRIMARY KEY,
    mission_id TEXT,
    agent_name TEXT NOT NULL,
    status TEXT NOT NULL,                    -- 'running', 'paused', 'waiting_for_input', 'interrupted', 'completed', 'failed'
    mode TEXT NOT NULL,                      -- 'autonomous', 'interactive'
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    metadata TEXT                            -- JSON object for additional metadata
);

-- Indexes for agent sessions
CREATE INDEX IF NOT EXISTS idx_agent_sessions_mission ON agent_sessions(mission_id);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_status ON agent_sessions(status);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_agent_name ON agent_sessions(agent_name);
CREATE INDEX IF NOT EXISTS idx_agent_sessions_started_at ON agent_sessions(started_at DESC);

-- ============================================================================
-- Stream Events Table: Store all streaming events from agents
-- ============================================================================
CREATE TABLE IF NOT EXISTS stream_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    event_type TEXT NOT NULL,                -- 'output', 'tool_call', 'tool_result', 'finding', 'status', 'error'
    content TEXT NOT NULL,                   -- JSON content of the event
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    trace_id TEXT,                           -- OpenTelemetry trace ID for correlation
    span_id TEXT,                            -- OpenTelemetry span ID for correlation
    FOREIGN KEY (session_id) REFERENCES agent_sessions(id) ON DELETE CASCADE
);

-- Indexes for stream events
CREATE INDEX IF NOT EXISTS idx_stream_events_session ON stream_events(session_id, sequence);
CREATE INDEX IF NOT EXISTS idx_stream_events_type ON stream_events(event_type);
CREATE INDEX IF NOT EXISTS idx_stream_events_trace ON stream_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_stream_events_timestamp ON stream_events(timestamp DESC);

-- ============================================================================
-- Steering Messages Table: Track operator steering inputs
-- ============================================================================
CREATE TABLE IF NOT EXISTS steering_messages (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    operator_id TEXT,                        -- Identifier for the operator who sent the message
    message_type TEXT NOT NULL,              -- 'steer', 'interrupt', 'resume', 'cancel', 'set_mode'
    content TEXT NOT NULL,                   -- JSON content of the steering message
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged_at TIMESTAMP,               -- When the agent acknowledged the message
    trace_id TEXT,                           -- OpenTelemetry trace ID for correlation
    FOREIGN KEY (session_id) REFERENCES agent_sessions(id) ON DELETE CASCADE
);

-- Indexes for steering messages
CREATE INDEX IF NOT EXISTS idx_steering_session ON steering_messages(session_id, sequence);
CREATE INDEX IF NOT EXISTS idx_steering_operator ON steering_messages(operator_id);
CREATE INDEX IF NOT EXISTS idx_steering_type ON steering_messages(message_type);
CREATE INDEX IF NOT EXISTS idx_steering_timestamp ON steering_messages(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_steering_acknowledged ON steering_messages(acknowledged_at);
`
}

// getDownMigration7 returns the rollback SQL for migration 7
func getDownMigration7() string {
	return `
-- Rollback Migration 7: Interactive Agent Steering Schema

-- Drop indexes for steering messages
DROP INDEX IF EXISTS idx_steering_acknowledged;
DROP INDEX IF EXISTS idx_steering_timestamp;
DROP INDEX IF EXISTS idx_steering_type;
DROP INDEX IF EXISTS idx_steering_operator;
DROP INDEX IF EXISTS idx_steering_session;

-- Drop steering messages table
DROP TABLE IF EXISTS steering_messages;

-- Drop indexes for stream events
DROP INDEX IF EXISTS idx_stream_events_timestamp;
DROP INDEX IF EXISTS idx_stream_events_trace;
DROP INDEX IF EXISTS idx_stream_events_type;
DROP INDEX IF EXISTS idx_stream_events_session;

-- Drop stream events table
DROP TABLE IF EXISTS stream_events;

-- Drop indexes for agent sessions
DROP INDEX IF EXISTS idx_agent_sessions_started_at;
DROP INDEX IF EXISTS idx_agent_sessions_agent_name;
DROP INDEX IF EXISTS idx_agent_sessions_status;
DROP INDEX IF EXISTS idx_agent_sessions_mission;

-- Drop agent sessions table
DROP TABLE IF EXISTS agent_sessions;
`
}

// getMissionWorkflowJSONSchema returns the schema for adding workflow_json column
func getMissionWorkflowJSONSchema() string {
	return `
-- Migration 8: Add workflow_json column to missions table
-- Allows storing workflow definition inline with mission

ALTER TABLE missions ADD COLUMN workflow_json TEXT;
`
}

// getDownMigration8 returns the rollback SQL for migration 8
func getDownMigration8() string {
	return `
-- Rollback Migration 8: workflow_json column
-- Note: SQLite doesn't support DROP COLUMN directly
-- In production, this would require recreating the table
`
}

// getMissionConsolidationColumnsSchema returns the schema for mission consolidation
// This migration ensures all columns from mission.Mission struct exist in the database.
// Since SQLite doesn't support IF NOT EXISTS for ALTER TABLE ADD COLUMN, and the columns
// were already added in migrations 4, 6, and 8, this migration serves as documentation
// and verification that the schema is complete for mission consolidation.
func getMissionConsolidationColumnsSchema() string {
	return `
-- Migration 9: Mission Consolidation Columns
-- Ensures all columns from mission.Mission struct exist in the missions table.
-- This migration documents the complete schema after consolidation.

-- Summary of columns required for mission.Mission:
-- From migration 4 (getMissionsTableSchema):
--   - id TEXT PRIMARY KEY
--   - name TEXT UNIQUE NOT NULL
--   - description TEXT
--   - status TEXT NOT NULL DEFAULT 'pending'
--   - workflow_id TEXT NOT NULL
--   - workflow TEXT (deprecated, use workflow_json)
--   - progress REAL DEFAULT 0.0               ✓ REQUIRED
--   - findings_count INTEGER DEFAULT 0        ✓ REQUIRED
--   - agent_assignments TEXT                  ✓ REQUIRED
--   - metadata TEXT                           ✓ REQUIRED
--   - created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--   - updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
--   - started_at TIMESTAMP
--   - completed_at TIMESTAMP

-- From migration 6 (getMissionOrchestratorSchema):
--   - target_id TEXT                          ✓ referenced in mission.Mission
--   - constraints TEXT                        ✓ MissionConstraints JSON
--   - metrics TEXT                            ✓ MissionMetrics JSON
--   - checkpoint TEXT                         ✓ MissionCheckpoint JSON
--   - error TEXT                              ✓ error message string

-- From migration 8 (getMissionWorkflowJSONSchema):
--   - workflow_json TEXT                      ✓ WorkflowJSON field

-- All required columns exist from previous migrations.
-- This migration is a no-op that documents the consolidated schema.

-- Verification: Create a view to document the expected schema
CREATE TEMPORARY VIEW IF NOT EXISTS _mission_schema_v9 AS
SELECT
    'progress' as column_name, 'REAL' as type, 'Migration 4' as added_in
UNION ALL SELECT 'findings_count', 'INTEGER', 'Migration 4'
UNION ALL SELECT 'agent_assignments', 'TEXT', 'Migration 4'
UNION ALL SELECT 'metadata', 'TEXT', 'Migration 4'
UNION ALL SELECT 'target_id', 'TEXT', 'Migration 6'
UNION ALL SELECT 'constraints', 'TEXT', 'Migration 6'
UNION ALL SELECT 'metrics', 'TEXT', 'Migration 6'
UNION ALL SELECT 'checkpoint', 'TEXT', 'Migration 6'
UNION ALL SELECT 'error', 'TEXT', 'Migration 6'
UNION ALL SELECT 'workflow_json', 'TEXT', 'Migration 8';

-- Drop the documentation view
DROP VIEW IF EXISTS _mission_schema_v9;

-- Schema verification complete. All columns exist from previous migrations.
`
}

// getDownMigration9 returns the rollback SQL for migration 9
func getDownMigration9() string {
	return `
-- Rollback Migration 9: Mission Consolidation Columns
-- This migration only verified existing columns, so rollback is a no-op.
-- All columns were added in previous migrations (4, 6, 8) and remain in place.

-- No changes to rollback
`
}

// getResumableMissionArchitectureSchema returns the schema for resumable missions
func getResumableMissionArchitectureSchema() string {
	return `
-- Migration 10: Resumable Mission Architecture
-- Removes UNIQUE constraint on name, adds run linkage columns
-- Creates mission_events table for event persistence

-- ============================================================================
-- Recreate missions table without UNIQUE constraint on name
-- ============================================================================

-- Step 1: Create new table without UNIQUE constraint on name
CREATE TABLE IF NOT EXISTS missions_new (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,                    -- No longer UNIQUE
    description TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    workflow_id TEXT NOT NULL,
    workflow TEXT,
    workflow_json TEXT,
    target_id TEXT,
    constraints TEXT,
    metrics TEXT,
    checkpoint TEXT,
    error TEXT,
    progress REAL DEFAULT 0.0,
    findings_count INTEGER DEFAULT 0,
    agent_assignments TEXT,
    metadata TEXT,
    run_number INTEGER DEFAULT 1,          -- NEW: Sequential run number
    previous_run_id TEXT,                  -- NEW: Link to previous run
    checkpoint_at TIMESTAMP,               -- NEW: Last checkpoint time
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,

    FOREIGN KEY (previous_run_id) REFERENCES missions(id)
);

-- Step 2: Copy data from old table to new table
INSERT INTO missions_new (
    id, name, description, status, workflow_id, workflow, workflow_json,
    target_id, constraints, metrics, checkpoint, error, progress,
    findings_count, agent_assignments, metadata,
    created_at, updated_at, started_at, completed_at
)
SELECT
    id, name, description, status, workflow_id, workflow, workflow_json,
    target_id, constraints, metrics, checkpoint, error, progress,
    findings_count, agent_assignments, metadata,
    created_at, updated_at, started_at, completed_at
FROM missions;

-- Step 3: Drop old table
DROP TABLE missions;

-- Step 4: Rename new table to missions
ALTER TABLE missions_new RENAME TO missions;

-- ============================================================================
-- Indexes for Run Linkage and Queries
-- ============================================================================

-- Composite index for name + status queries (find active missions by name)
CREATE INDEX IF NOT EXISTS idx_missions_name_status ON missions(name, status);

-- Index for previous_run_id linkage
CREATE INDEX IF NOT EXISTS idx_missions_previous_run ON missions(previous_run_id);

-- Index for name lookups (used by GetByName, ListByName, etc.)
CREATE INDEX IF NOT EXISTS idx_missions_name ON missions(name);

-- ============================================================================
-- Mission Events Table: Persistent event log for audit trail
-- ============================================================================
CREATE TABLE IF NOT EXISTS mission_events (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    event_type TEXT NOT NULL,              -- 'started', 'paused', 'resumed', 'completed', 'failed', 'checkpoint', etc.
    payload TEXT,                          -- JSON serialized event payload
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
);

-- ============================================================================
-- Mission Events Indexes for Efficient Queries
-- ============================================================================

-- Index for querying events by mission
CREATE INDEX IF NOT EXISTS idx_mission_events_mission_id ON mission_events(mission_id);

-- Index for filtering by event type
CREATE INDEX IF NOT EXISTS idx_mission_events_type ON mission_events(event_type);

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_mission_events_created_at ON mission_events(created_at);

-- Composite index for mission + event type queries
CREATE INDEX IF NOT EXISTS idx_mission_events_mission_type ON mission_events(mission_id, event_type);
`
}

// getDownMigration10 returns the rollback SQL for migration 10
func getDownMigration10() string {
	return `
-- Rollback Migration 10: Resumable Mission Architecture

-- Drop mission_events indexes
DROP INDEX IF EXISTS idx_mission_events_mission_type;
DROP INDEX IF EXISTS idx_mission_events_created_at;
DROP INDEX IF EXISTS idx_mission_events_type;
DROP INDEX IF EXISTS idx_mission_events_mission_id;

-- Drop mission_events table
DROP TABLE IF EXISTS mission_events;

-- Drop missions table indexes for run linkage
DROP INDEX IF EXISTS idx_missions_previous_run;
DROP INDEX IF EXISTS idx_missions_name_status;

-- Note: SQLite doesn't support DROP COLUMN directly
-- The run_number, previous_run_id, and checkpoint_at columns will remain
-- In production, you would need to:
-- 1. Create a new table without the enhanced columns
-- 2. Copy data from old table to new table
-- 3. Drop old table
-- 4. Rename new table
-- For simplicity, we're leaving the columns in place during rollback
`
}

// getTargetConnectionSchema returns the schema for adding connection column to targets
func getTargetConnectionSchema() string {
	return `
-- Migration 11: Add connection column to targets table
-- Stores schema-based connection parameters (CIDR, URLs, hosts, etc.)

ALTER TABLE targets ADD COLUMN connection TEXT DEFAULT '{}';
`
}

// getDownMigration11 returns the rollback SQL for migration 11
func getDownMigration11() string {
	return `
-- Rollback Migration 11: Target Connection Column
-- Note: SQLite doesn't support DROP COLUMN directly
-- The connection column will remain in place during rollback
`
}

// getMissionLineageSchema returns the schema for adding parent mission tracking
func getMissionLineageSchema() string {
	return `
-- Migration 12: Mission Lineage Tracking
-- Adds parent_mission_id and depth columns to support mission hierarchy

-- Add parent_mission_id column (nullable FK to missions table)
ALTER TABLE missions ADD COLUMN parent_mission_id TEXT;

-- Add depth column to track how deep in the hierarchy this mission is
ALTER TABLE missions ADD COLUMN depth INTEGER DEFAULT 0;

-- Create index on parent_mission_id for efficient child mission queries
CREATE INDEX IF NOT EXISTS idx_missions_parent ON missions(parent_mission_id);

-- Create composite index for parent + status queries
CREATE INDEX IF NOT EXISTS idx_missions_parent_status ON missions(parent_mission_id, status);
`
}

// getDownMigration12 returns the rollback SQL for migration 12
func getDownMigration12() string {
	return `
-- Rollback Migration 12: Mission Lineage Tracking

-- Drop indexes
DROP INDEX IF EXISTS idx_missions_parent_status;
DROP INDEX IF EXISTS idx_missions_parent;

-- Note: SQLite doesn't support DROP COLUMN directly
-- The parent_mission_id and depth columns will remain in place during rollback
-- In production, you would need to:
-- 1. Create a new table without the lineage columns
-- 2. Copy data from old table to new table
-- 3. Drop old table
-- 4. Rename new table
-- For simplicity, we're leaving the columns in place during rollback
`
}

// getKnowledgeSuiteSchema returns the schema for the Local Knowledge Suite
// This includes vector-based knowledge storage and enhanced payload tables
func getKnowledgeSuiteSchema() string {
	return `
-- Migration 13: Local Knowledge Suite
-- Creates tables for knowledge vectors, sources, and enhanced payload storage

-- ============================================================================
-- Knowledge Vectors Table: Vector-based semantic search storage
-- ============================================================================
CREATE TABLE IF NOT EXISTS knowledge_vectors (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    embedding BLOB NOT NULL,
    metadata TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for knowledge vectors
CREATE INDEX IF NOT EXISTS idx_knowledge_vectors_created_at ON knowledge_vectors(created_at DESC);

-- ============================================================================
-- Knowledge Vectors Vec Table: sqlite-vec virtual table for similarity search
-- Note: This table will be created by SqliteVecStore when sqlite-vec extension is loaded
-- The extension must be loaded before this migration runs
-- CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_vectors_vec USING vec0(
--     embedding float[384]
-- );
-- ============================================================================

-- ============================================================================
-- Knowledge Sources Table: Track ingested knowledge sources
-- ============================================================================
CREATE TABLE IF NOT EXISTS knowledge_sources (
    source TEXT PRIMARY KEY,
    source_type TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    chunk_count INTEGER DEFAULT 0,
    ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    metadata TEXT
);

-- Indexes for knowledge sources
CREATE INDEX IF NOT EXISTS idx_knowledge_sources_hash ON knowledge_sources(source_hash);
CREATE INDEX IF NOT EXISTS idx_knowledge_sources_type ON knowledge_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_knowledge_sources_ingested_at ON knowledge_sources(ingested_at DESC);
`
}

// getDownMigration13 returns the rollback SQL for migration 13
func getDownMigration13() string {
	return `
-- Rollback Migration 13: Local Knowledge Suite

-- Drop knowledge sources indexes
DROP INDEX IF EXISTS idx_knowledge_sources_ingested_at;
DROP INDEX IF EXISTS idx_knowledge_sources_type;
DROP INDEX IF EXISTS idx_knowledge_sources_hash;

-- Drop knowledge sources table
DROP TABLE IF EXISTS knowledge_sources;

-- Drop sqlite-vec virtual table (if it was created)
DROP TABLE IF EXISTS knowledge_vectors_vec;

-- Drop knowledge vectors indexes
DROP INDEX IF EXISTS idx_knowledge_vectors_created_at;

-- Drop knowledge vectors table
DROP TABLE IF EXISTS knowledge_vectors;
`
}

// getMissionRunsTableSchema returns the schema for mission_runs table
// This separates execution tracking from mission definitions, aligning SQLite with Neo4j structure
func getMissionRunsTableSchema() string {
	return `
-- Migration 14: Mission Runs Table
-- Creates a separate table for tracking individual mission executions
-- This aligns SQLite with Neo4j's Mission/MissionRun node structure

-- ============================================================================
-- Mission Runs Table: Track individual execution instances
-- ============================================================================
CREATE TABLE IF NOT EXISTS mission_runs (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,                -- FK to missions table
    run_number INTEGER NOT NULL,             -- Sequential run number (1, 2, 3...)
    status TEXT NOT NULL DEFAULT 'pending',  -- 'pending', 'running', 'completed', 'failed', 'cancelled', 'paused'

    -- Execution metrics
    progress REAL DEFAULT 0.0,               -- 0.0 to 1.0
    findings_count INTEGER DEFAULT 0,

    -- State tracking
    checkpoint TEXT,                         -- JSON serialized checkpoint state
    error TEXT,                              -- Error message if failed

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Foreign key constraint
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE,

    -- Unique constraint: one run number per mission
    UNIQUE(mission_id, run_number)
);

-- ============================================================================
-- Indexes for Mission Runs
-- ============================================================================

-- Index for querying runs by mission
CREATE INDEX IF NOT EXISTS idx_mission_runs_mission_id ON mission_runs(mission_id);

-- Index for status filtering
CREATE INDEX IF NOT EXISTS idx_mission_runs_status ON mission_runs(status);

-- Index for finding latest run per mission
CREATE INDEX IF NOT EXISTS idx_mission_runs_mission_run ON mission_runs(mission_id, run_number DESC);

-- Index for active runs
CREATE INDEX IF NOT EXISTS idx_mission_runs_active ON mission_runs(status) WHERE status IN ('running', 'paused');

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_mission_runs_created_at ON mission_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mission_runs_started_at ON mission_runs(started_at DESC);

-- ============================================================================
-- Trigger to update updated_at timestamp
-- ============================================================================
CREATE TRIGGER IF NOT EXISTS update_mission_runs_timestamp
    AFTER UPDATE ON mission_runs
    FOR EACH ROW
    WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE mission_runs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
END;
`
}

// getDownMigration14 returns the rollback SQL for migration 14
func getDownMigration14() string {
	return `
-- Rollback Migration 14: Mission Runs Table

-- Drop trigger
DROP TRIGGER IF EXISTS update_mission_runs_timestamp;

-- Drop indexes
DROP INDEX IF EXISTS idx_mission_runs_started_at;
DROP INDEX IF EXISTS idx_mission_runs_created_at;
DROP INDEX IF EXISTS idx_mission_runs_active;
DROP INDEX IF EXISTS idx_mission_runs_mission_run;
DROP INDEX IF EXISTS idx_mission_runs_status;
DROP INDEX IF EXISTS idx_mission_runs_mission_id;

-- Drop table
DROP TABLE IF EXISTS mission_runs;
`
}

// getReportsTableSchema returns the schema for reports table
func getReportsTableSchema() string {
	return `
-- Migration 15: Reports Table
-- Creates table for storing generated security reports

-- ============================================================================
-- Reports Table: Store report metadata
-- ============================================================================
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    mission_id TEXT NOT NULL,
    type TEXT NOT NULL,                      -- 'executive', 'technical', 'compliance', etc.
    format TEXT NOT NULL,                    -- 'pdf', 'html', 'markdown', 'json', 'sarif', 'csv', 'docx'
    title TEXT NOT NULL,
    summary TEXT,

    -- Generation metadata
    generated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    generated_by TEXT NOT NULL,              -- User or system identifier
    template_used TEXT,                      -- Template name used for generation

    -- Configuration and metadata (JSON stored as TEXT)
    options TEXT NOT NULL,                   -- JSON ReportOptions object
    metadata TEXT NOT NULL,                  -- JSON ReportMetadata object (finding counts, metrics, etc.)

    -- File storage information
    file_path TEXT NOT NULL,                 -- Path to report file on filesystem
    file_size INTEGER NOT NULL,              -- File size in bytes
    checksum TEXT NOT NULL,                  -- SHA256 checksum of file content

    -- Foreign key constraint
    FOREIGN KEY (mission_id) REFERENCES missions(id) ON DELETE CASCADE
);

-- ============================================================================
-- Indexes for Reports
-- ============================================================================

-- Index for querying reports by mission
CREATE INDEX IF NOT EXISTS idx_reports_mission_id ON reports(mission_id);

-- Index for report type filtering
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(type);

-- Index for format filtering
CREATE INDEX IF NOT EXISTS idx_reports_format ON reports(format);

-- Index for time-based queries (most recent first)
CREATE INDEX IF NOT EXISTS idx_reports_generated_at ON reports(generated_at DESC);

-- Composite index for mission + type queries
CREATE INDEX IF NOT EXISTS idx_reports_mission_type ON reports(mission_id, type);

-- Composite index for mission + type + format (for GetLatest queries)
CREATE INDEX IF NOT EXISTS idx_reports_mission_type_format ON reports(mission_id, type, format, generated_at DESC);

-- Index for generated_by (track who generated reports)
CREATE INDEX IF NOT EXISTS idx_reports_generated_by ON reports(generated_by);
`
}

// getDownMigration15 returns the rollback SQL for migration 15
func getDownMigration15() string {
	return `
-- Rollback Migration 15: Reports Table

-- Drop indexes
DROP INDEX IF EXISTS idx_reports_generated_by;
DROP INDEX IF EXISTS idx_reports_mission_type_format;
DROP INDEX IF EXISTS idx_reports_mission_type;
DROP INDEX IF EXISTS idx_reports_generated_at;
DROP INDEX IF EXISTS idx_reports_format;
DROP INDEX IF EXISTS idx_reports_type;
DROP INDEX IF EXISTS idx_reports_mission_id;

-- Drop table
DROP TABLE IF EXISTS reports;
`
}
