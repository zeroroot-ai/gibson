package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Neo4jRunner applies Cypher migration files against a single per-tenant Neo4j
// database, tracking applied migrations via a singleton (:_SchemaVersion) node.
//
// Migration state is stored as:
//
//	(:_SchemaVersion {name: "<latest applied filename>", version: N, applied_at: <iso8601>})
//
// There is exactly one such node per database; it is MERGE'd on every update so
// the runner is safe to re-run.
type Neo4jRunner struct {
	// Driver is the shared Neo4j driver. The caller owns the driver lifecycle.
	Driver neo4j.DriverWithContext

	// DatabaseName is the per-tenant Neo4j database (e.g. "tenant_acme").
	DatabaseName string

	// MigrationsDir is the absolute path to the directory containing
	// *.up.cypher files (and optionally *.down.cypher files).
	MigrationsDir string
}

// Neo4jStatus holds the current migration state for a tenant Neo4j database.
type Neo4jStatus struct {
	// CurrentName is the filename of the last applied migration, as stored in
	// the :_SchemaVersion node. Empty when no migrations have been applied.
	CurrentName string

	// CurrentVersion is the numeric version prefix of CurrentName.
	CurrentVersion uint

	// Target is the highest version available in MigrationsDir.
	Target uint

	// Pending lists migration files that are available but not yet applied.
	Pending []MigrationInfo
}

// schemaVersionNode is the label for the singleton migration-tracking node.
const schemaVersionNode = "_SchemaVersion"

// Apply applies all pending *.up.cypher migrations against the tenant database
// in filename-sorted order. State is tracked in the :_SchemaVersion node.
//
// If MigrationsDir does not exist (Phase D pending), Apply is a no-op.
//
// Each migration file may contain multiple Cypher statements separated by
// semicolons; they are executed individually within a single write transaction.
func (r *Neo4jRunner) Apply(ctx context.Context) (currentName, targetName string, applied []string, err error) {
	files, err := r.listUp()
	if err != nil {
		return "", "", nil, err
	}
	if len(files) == 0 {
		return "", "", nil, nil
	}

	currentName, err = r.currentVersion(ctx)
	if err != nil {
		// Driver may be nil or DB unreachable; treat all files as pending.
		currentName = ""
	}

	// Determine which files are pending.
	pending := r.pendingFiles(files, currentName)
	if len(pending) == 0 {
		return currentName, currentName, nil, nil
	}

	if r.Driver == nil {
		return "", "", nil, fmt.Errorf("neo4j runner: driver is nil; cannot apply migrations")
	}

	session := r.Driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: r.DatabaseName,
		AccessMode:   neo4j.AccessModeWrite,
	})
	defer session.Close(ctx)

	for _, f := range pending {
		select {
		case <-ctx.Done():
			return currentName, currentName, applied, ctx.Err()
		default:
		}

		cypher, err := os.ReadFile(filepath.Join(r.MigrationsDir, f.Name))
		if err != nil {
			return currentName, currentName, applied, fmt.Errorf("neo4j runner: read %s: %w", f.Name, err)
		}

		stmts := splitCypherStatements(string(cypher))
		for _, stmt := range stmts {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
				_, err := tx.Run(ctx, stmt, nil)
				return nil, err
			}); err != nil {
				return currentName, currentName, applied, fmt.Errorf("neo4j runner: apply %s: %w", f.Name, err)
			}
		}

		// Update the :_SchemaVersion node after each file so a crash mid-run
		// leaves the state at the last successfully applied migration.
		if err := r.setVersion(ctx, session, f.Name, f.Version); err != nil {
			return currentName, currentName, applied, err
		}

		applied = append(applied, f.Name)
		currentName = f.Name
	}

	return files[0].Name, currentName, applied, nil
}

// Status returns the current migration state for the tenant database without
// applying anything.
func (r *Neo4jRunner) Status(ctx context.Context) (*Neo4jStatus, error) {
	files, err := r.listUp()
	if err != nil {
		return nil, err
	}

	var target uint
	if len(files) > 0 {
		target = files[len(files)-1].Version
	}

	currentName, err := r.currentVersion(ctx)
	if err != nil {
		// Driver nil, DB may not exist yet, or connection failure — treat as 0 applied.
		return &Neo4jStatus{Target: target, Pending: files}, nil
	}

	var currentVer uint
	if currentName != "" {
		currentVer, _ = parseVersion(currentName)
	}

	status := &Neo4jStatus{
		CurrentName:    currentName,
		CurrentVersion: currentVer,
		Target:         target,
	}
	status.Pending = r.pendingFiles(files, currentName)
	return status, nil
}

// Down rolls back migrations until the database is at toVersion. Matching
// *.down.cypher files are applied in reverse order.
func (r *Neo4jRunner) Down(ctx context.Context, toVersion uint) (rolledBack []string, err error) {
	files, err := r.listDown()
	if err != nil {
		return nil, err
	}

	if r.Driver == nil {
		return nil, fmt.Errorf("neo4j runner: driver is nil; cannot apply down migrations")
	}

	currentName, err := r.currentVersion(ctx)
	if err != nil {
		return nil, err
	}
	var currentVer uint
	if currentName != "" {
		currentVer, _ = parseVersion(currentName)
	}

	// Build the list of down files to apply (descending order, above toVersion).
	var toApply []MigrationInfo
	for i := len(files) - 1; i >= 0; i-- {
		f := files[i]
		if f.Version > toVersion && f.Version <= currentVer {
			toApply = append(toApply, f)
		}
	}

	if len(toApply) == 0 {
		return nil, nil
	}

	session := r.Driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: r.DatabaseName,
		AccessMode:   neo4j.AccessModeWrite,
	})
	defer session.Close(ctx)

	for _, f := range toApply {
		select {
		case <-ctx.Done():
			return rolledBack, ctx.Err()
		default:
		}

		cypher, err := os.ReadFile(filepath.Join(r.MigrationsDir, f.Name))
		if err != nil {
			return rolledBack, fmt.Errorf("neo4j runner: read %s: %w", f.Name, err)
		}

		stmts := splitCypherStatements(string(cypher))
		for _, stmt := range stmts {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" {
				continue
			}
			if _, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
				_, err := tx.Run(ctx, stmt, nil)
				return nil, err
			}); err != nil {
				return rolledBack, fmt.Errorf("neo4j runner: apply %s: %w", f.Name, err)
			}
		}
		rolledBack = append(rolledBack, f.Name)
	}

	// Update :_SchemaVersion to reflect the new state. If toVersion == 0
	// there is nothing applied; delete the node.
	if toVersion == 0 {
		_ = r.deleteVersion(ctx, session)
	} else {
		// Find the name of the migration at toVersion.
		newName := ""
		for _, f := range files {
			if f.Version == toVersion {
				newName = strings.Replace(f.Name, ".down.cypher", ".up.cypher", 1)
				break
			}
		}
		if newName != "" {
			_ = r.setVersion(ctx, session, newName, toVersion)
		}
	}

	return rolledBack, nil
}

// currentVersion reads the :_SchemaVersion singleton node and returns the
// name of the last applied migration. Returns "" when no migrations have been
// applied yet or when the driver is nil.
func (r *Neo4jRunner) currentVersion(ctx context.Context) (string, error) {
	if r.Driver == nil {
		return "", fmt.Errorf("neo4j runner: driver is nil")
	}
	session := r.Driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: r.DatabaseName,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx,
			fmt.Sprintf("MATCH (v:%s) RETURN v.name AS name LIMIT 1", schemaVersionNode),
			nil,
		)
		if err != nil {
			return nil, err
		}
		if res.Next(ctx) {
			name, _ := res.Record().Get("name")
			if n, ok := name.(string); ok {
				return n, nil
			}
		}
		return "", res.Err()
	})
	if err != nil {
		// Node doesn't exist yet — treat as empty.
		return "", nil
	}
	name, _ := result.(string)
	return name, nil
}

// setVersion updates the :_SchemaVersion singleton node.
func (r *Neo4jRunner) setVersion(ctx context.Context, session neo4j.SessionWithContext, name string, version uint) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx,
			fmt.Sprintf(`MERGE (v:%s)
SET v.name = $name,
    v.version = $version,
    v.applied_at = datetime()`, schemaVersionNode),
			map[string]any{"name": name, "version": int64(version)},
		)
		return nil, err
	})
	return err
}

// deleteVersion removes the :_SchemaVersion singleton node (used when rolling
// all the way back to version 0).
func (r *Neo4jRunner) deleteVersion(ctx context.Context, session neo4j.SessionWithContext) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx,
			fmt.Sprintf("MATCH (v:%s) DELETE v", schemaVersionNode),
			nil,
		)
		return nil, err
	})
	return err
}

// listUp returns available *.up.cypher migration files sorted by filename.
func (r *Neo4jRunner) listUp() ([]MigrationInfo, error) {
	return r.list(".up.cypher")
}

// listDown returns available *.down.cypher migration files sorted by filename.
func (r *Neo4jRunner) listDown() ([]MigrationInfo, error) {
	return r.list(".down.cypher")
}

func (r *Neo4jRunner) list(suffix string) ([]MigrationInfo, error) {
	if r.MigrationsDir == "" {
		return nil, nil
	}
	if _, err := os.Stat(r.MigrationsDir); os.IsNotExist(err) {
		return nil, nil
	}

	pattern := filepath.Join(r.MigrationsDir, "*"+suffix)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)

	result := make([]MigrationInfo, 0, len(matches))
	for _, path := range matches {
		base := filepath.Base(path)
		ver, err := parseVersion(base)
		if err != nil {
			continue
		}
		result = append(result, MigrationInfo{Version: ver, Name: base})
	}
	return result, nil
}

// pendingFiles returns the migration files from all that have not yet been
// applied (i.e. their version is greater than the current version).
func (r *Neo4jRunner) pendingFiles(all []MigrationInfo, currentName string) []MigrationInfo {
	var currentVer uint
	if currentName != "" {
		currentVer, _ = parseVersion(currentName)
	}
	var pending []MigrationInfo
	for _, f := range all {
		if f.Version > currentVer {
			pending = append(pending, f)
		}
	}
	return pending
}

// splitCypherStatements splits a Cypher source file on semicolons, stripping
// single-line comments (// ...) so they do not create spurious empty statements.
func splitCypherStatements(src string) []string {
	var stmts []string
	var cur strings.Builder
	for _, line := range strings.Split(src, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if idx := strings.Index(line, ";"); idx >= 0 {
			cur.WriteString(line[:idx+1])
			stmts = append(stmts, cur.String())
			cur.Reset()
			rest := line[idx+1:]
			if strings.TrimSpace(rest) != "" {
				cur.WriteString(rest)
				cur.WriteString("\n")
			}
		} else {
			cur.WriteString(line)
			cur.WriteString("\n")
		}
	}
	if s := strings.TrimSpace(cur.String()); s != "" {
		stmts = append(stmts, s)
	}
	return stmts
}
