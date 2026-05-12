package checks

import (
	"go/ast"
	"strconv"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// ForbidRawStoreImportsAnalyzer flags any import of the raw store client
// libraries (pgx, go-redis, neo4j-go-driver, qdrant, miniredis) from a
// package whose import path is outside the allowlisted data-plane prefixes.
//
// The allowlisted packages are the ONLY locations permitted to hold raw
// store clients; every other package must access data through
// internal/datapool.Conn (which is already tenant-bound by construction).
//
// Test files are partially exempted: _test.go files may import miniredis
// (fixture servers for unit tests) but may NOT import other raw store
// clients from non-allowlisted packages.
//
// Spec: database-per-tenant-data-plane Requirement 16.1, Requirement 5.9.
var ForbidRawStoreImportsAnalyzer = &analysis.Analyzer{
	Name: "forbidrawstoreimports",
	Doc:  "fail on raw store client imports (pgx/go-redis/neo4j/qdrant/miniredis) outside internal/datapool/ and internal/admin/ (database-per-tenant-data-plane Req 16.1)",
	Run:  runForbidRawStoreImports,
}

// rawStoreImports lists import path prefixes whose presence outside the
// allowlisted packages is a policy violation.
var rawStoreImports = []string{
	"github.com/jackc/pgx/v5",
	"github.com/redis/go-redis/v9",
	"github.com/neo4j/neo4j-go-driver/v5",
	"github.com/qdrant/go-client",
	"github.com/alicebob/miniredis/v2",
}

// testOnlyImports lists raw store imports that are permitted in _test.go
// files (miniredis provides in-process Redis fixtures for unit tests).
var testOnlyImports = []string{
	"github.com/alicebob/miniredis/v2",
}

// allowedStorePackages lists package import-path substrings that are
// permitted to import raw store client libraries. Sub-packages are covered
// by substring matching.
//
// The primary allowlist (first group) is the permanent allowlist from the
// database-per-tenant-data-plane spec — these packages are the ONLY long-term
// consumers of raw store clients.
//
// The transitional allowlist (second group) covers packages that still hold
// legacy Redis/Neo4j imports during the Phase D cleanup migration. These are
// tracked for deletion; once deleted they become no-ops in the match loop.
// Any package NOT in either group that tries to add a raw store import will
// be caught by this analyzer, which is the primary goal.
var allowedStorePackages = []string{
	// Permanent allowlist — spec-approved locations for raw store client access.
	"/internal/datapool",
	"/internal/admin",
	"/internal/migrate",
	"/cmd/gibson-migrate",
	"/cmd/daemon",                  // cmd/daemon binary entry point (bootstrap wiring)
	"/internal/daemon",             // daemon bootstrap and subsystems (wires raw clients into Conn factory)
	"/tools/gibsoncheck",
	"/cmd/mission-storage-migrate", // one-off offline mission-storage migrator; peer of cmd/gibson-migrate (spec: mirror-delete-and-offline-migrator).

	// Transitional allowlist — Phase D migration in progress.
	// These packages are targeted for refactor/deletion; remove entries here
	// once the corresponding packages are cleaned up.
	"/internal/state",          // Phase D/4.7: TenantScopedStore pending deletion
	"/internal/database",       // Phase D/4.2: DAO refactor in progress
	"/internal/authz",          // Phase E/5.2: cross-tenant code relocation
	"/internal/audit",          // Phase E/5.2: audit stream on shared Redis
	"/internal/finding",        // Phase D/4.2: finding store _conn.go uses raw redis via Conn
	"/internal/graphrag",       // Phase D/4.4: Neo4j session via Conn
	"/internal/memory",         // Phase D/4.3: mission memory via Conn
	"/internal/component",      // Phase E/5.2: component quota counters (shared Redis)
	"/internal/budget",         // Phase D/4.x: budget enforcer pending Conn-bound refactor
	"/internal/checkpoint",     // Phase D/4.x: checkpoint store pending Conn-bound refactor
	"/internal/manifest",       // Phase D/4.x: manifest invalidator pending refactor
	"/internal/mission",        // Phase D/4.1,4.5: Conn-bound wrappers still import raw redis
	"/internal/missiondraft",   // Phase D/4.x: draft store pending Conn-bound refactor
	"/internal/onboarding",     // Phase D/4.x: onboarding store pending Conn-bound refactor
	"/internal/neo4j",          // Phase D/4.4: Neo4j client wrapper
	"/internal/ratelimit",      // Phase D/4.x: rate limiter on shared Redis
	"/internal/providerconfig", // Phase C/3.3: provider config store pending Conn-bound
	"/internal/apikeys",        // Phase D/4.x: API key store pending Conn-bound refactor
	"/internal/orchestrator",   // Phase D/4.4: Neo4j graph querier pending Conn-bound refactor
	"/internal/secrets",        // TenantConfigStore uses pgxpool directly against the operator-shared Postgres; pending relocation into internal/admin/ (same shape as the admin pool consumers) or wrapping by a new datapool.OperatorPool helper.
}

func runForbidRawStoreImports(pass *analysis.Pass) (any, error) {
	pkgPath := pass.Pkg.Path()

	// If this package is on the allowlist, skip all checks.
	for _, allowed := range allowedStorePackages {
		if strings.Contains(pkgPath, allowed) {
			return nil, nil
		}
	}

	for _, file := range pass.Files {
		fname := pass.Fset.Position(file.Pos()).Filename
		isTestFile := strings.HasSuffix(fname, "_test.go")

		for _, imp := range file.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				continue
			}

			for _, raw := range rawStoreImports {
				if !strings.HasPrefix(path, raw) {
					continue
				}

				// Test files may import miniredis; all other raw stores are
				// still forbidden even in test files (tests should use the
				// datapool mock, not raw clients).
				if isTestFile && isTestOnlyImport(path) {
					continue
				}

				pass.Reportf(imp.Pos(),
					"forbidden import %q in %q — raw store clients must be accessed via internal/datapool/Conn (see docs/data-plane.md); only internal/datapool/, internal/admin/, internal/migrate/, cmd/gibson-migrate/, and cmd/daemon/ may import raw store libraries directly",
					path, pkgPath)
			}
		}
	}

	return nil, nil
}

// isTestOnlyImport reports whether path is in the list of imports that
// are permitted in _test.go files (i.e. miniredis fixture server).
func isTestOnlyImport(path string) bool {
	for _, allowed := range testOnlyImports {
		if strings.HasPrefix(path, allowed) {
			return true
		}
	}
	return false
}

// astWalkForRawStore is retained so go vet does not complain about the
// go/ast import being unused if future sub-checks need AST walks.
var _ = ast.Walk
