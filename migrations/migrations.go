// Package migrations provides the embedded schema migration files for the
// Gibson daemon and the gibson-migrate CLI.
//
// Postgres migration files live under migrations/postgres/*.up.sql and
// migrations/postgres/*.down.sql. Neo4j migration files live under
// migrations/neo4j/*.up.cypher and migrations/neo4j/*.down.cypher.
//
// Migration files are authored by Phase D (tasks 4.8/4.9). Until Phase D
// lands, the Postgres set contains only the initial credentials table
// (001_credentials.up.sql authored by Phase C) and the Neo4j set is empty
// (placeholder .gitkeep). Callers that call LatestPostgresVersion or
// LatestNeo4jVersion receive 0 when no files matching the pattern exist.
//
// Spec: database-per-tenant-data-plane, Phase G.
package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// Postgres is the embedded FS for Postgres migration SQL files.
// Paths inside the FS start with "postgres/".
//
//go:embed postgres
var Postgres embed.FS

// Neo4j is the embedded FS for Neo4j migration Cypher files.
// Paths inside the FS start with "neo4j/".
//
//go:embed neo4j
var Neo4j embed.FS

// LatestPostgresVersion returns the highest version number present in the
// embedded Postgres migration set (*.up.sql files). Returns 0 when no
// migration files are available.
func LatestPostgresVersion() (uint, error) {
	return latestVersion(Postgres, "postgres", ".up.sql")
}

// LatestNeo4jVersion returns the highest version number present in the
// embedded Neo4j migration set (*.up.cypher files). Returns 0 when no
// migration files are available.
func LatestNeo4jVersion() (uint, error) {
	return latestVersion(Neo4j, "neo4j", ".up.cypher")
}

// latestVersion scans the embedded FS for files matching the suffix and
// returns the highest version parsed from the leading numeric prefix of
// each filename.
func latestVersion(efs embed.FS, dir, suffix string) (uint, error) {
	entries, err := fs.ReadDir(efs, dir)
	if err != nil {
		return 0, nil
	}

	var versions []uint
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		ver, err := ParseVersion(name)
		if err != nil {
			continue
		}
		versions = append(versions, ver)
	}

	if len(versions) == 0 {
		return 0, nil
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] > versions[j] })
	return versions[0], nil
}

// ParseVersion extracts the numeric version prefix from a migration filename.
// Expected format: "NNN_name.suffix" where NNN is a positive integer.
func ParseVersion(filename string) (uint, error) {
	base := filepath.Base(filename)
	idx := strings.IndexByte(base, '_')
	if idx <= 0 {
		return 0, fmt.Errorf("migrations: no leading version number in %q", base)
	}
	prefix := base[:idx]
	var ver uint
	if _, err := fmt.Sscanf(prefix, "%d", &ver); err != nil {
		return 0, fmt.Errorf("migrations: parse version from %q: %w", base, err)
	}
	return ver, nil
}

// ListPending returns the filenames in the embedded FS (for the given store)
// whose version is greater than currentVersion, sorted ascending.
func ListPending(efs embed.FS, dir, suffix string, currentVersion uint) ([]string, error) {
	entries, err := fs.ReadDir(efs, dir)
	if err != nil {
		return nil, nil
	}

	type vf struct {
		ver  uint
		name string
	}
	var candidates []vf
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, suffix) {
			continue
		}
		ver, err := ParseVersion(name)
		if err != nil {
			continue
		}
		if ver > currentVersion {
			candidates = append(candidates, vf{ver, name})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ver < candidates[j].ver })

	result := make([]string, 0, len(candidates))
	for _, c := range candidates {
		result = append(result, c.name)
	}
	return result, nil
}
