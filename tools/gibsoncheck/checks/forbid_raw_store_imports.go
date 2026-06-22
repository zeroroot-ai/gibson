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
	Doc:  "fail on raw store client imports (pgx/go-redis/neo4j/qdrant/miniredis) outside internal/infra/datapool/ and internal/server/admin/ (database-per-tenant-data-plane Req 16.1)",
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
	"/internal/infra/datapool",
	"/internal/server/admin",
	"/internal/migrate",
	"/cmd/gibson-migrate",
	"/cmd/daemon",             // cmd/daemon binary entry point (bootstrap wiring)
	"/internal/server/daemon", // daemon bootstrap and subsystems (wires raw clients into Conn factory)
	"/tools/gibsoncheck",
	"/cmd/mission-storage-migrate", // one-off offline mission-storage migrator; peer of cmd/gibson-migrate (spec: mirror-delete-and-offline-migrator).

	// Folded platform-clients / shared infra (gibson#913, E4 monorepo fold,
	// ADR-0026/0056). These ARE the pool-construction / shared-store
	// primitives every internal service consumes — constructing raw store
	// clients is their entire purpose, so they are permanent peers of
	// internal/infra/datapool, not daemon business logic.
	"/internal/infra/pools",       // platform-clients pool constructors (NewPgxPool/NewRedis/NewNeo4j)
	"/internal/infra/tenantconfig", // operator-shared Postgres broker-config store; wrapped by the already-allowed internal/platform/secrets/configstore

	// Transitional allowlist — Phase D migration in progress.
	// These packages are targeted for refactor/deletion; remove entries here
	// once the corresponding packages are cleaned up.
	"/internal/engine/state",                 // Phase D/4.7: TenantScopedStore pending deletion
	"/internal/infra/database",               // Phase D/4.2: DAO refactor in progress
	"/internal/platform/authz",               // Phase E/5.2: cross-tenant code relocation
	"/internal/platform/audit",               // Phase E/5.2: audit stream on shared Redis
	"/internal/engine/finding",               // Phase D/4.2: finding store _conn.go uses raw redis via Conn
	"/internal/engine/graphrag",              // Phase D/4.4: Neo4j session via Conn
	"/internal/engine/memory",                // Phase D/4.3: mission memory via Conn
	"/internal/platform/component",           // Phase E/5.2: component quota counters (shared Redis)
	"/internal/platform/budget",              // Phase D/4.x: budget enforcer pending Conn-bound refactor
	"/internal/engine/checkpoint",            // Phase D/4.x: checkpoint store pending Conn-bound refactor
	"/internal/platform/manifest",            // Phase D/4.x: manifest invalidator pending refactor
	"/internal/engine/mission",               // Phase D/4.1,4.5: Conn-bound wrappers still import raw redis
	"/internal/engine/missiondraft",          // Phase D/4.x: draft store pending Conn-bound refactor
	"/internal/platform/onboarding",          // Phase D/4.x: onboarding store pending Conn-bound refactor
	"/internal/infra/neo4j",                  // Phase D/4.4: Neo4j client wrapper
	"/internal/platform/ratelimit",           // Phase D/4.x: rate limiter on shared Redis
	"/internal/platform/providerconfig",      // Phase C/3.3: provider config store pending Conn-bound
	"/internal/apikeys",                      // Phase D/4.x: API key store pending Conn-bound refactor
	"/internal/orchestrator",                 // Phase D/4.4: Neo4j graph querier pending Conn-bound refactor
	"/internal/platform/secrets/configstore", // sub-package that owns raw pgx access for the secrets broker stack against the operator-shared Postgres; the parent internal/platform/secrets/ stays free of raw store imports.
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
					"forbidden import %q in %q — raw store clients must be accessed via internal/infra/datapool/Conn (see docs/data-plane.md); only internal/infra/datapool/, internal/server/admin/, internal/migrate/, cmd/gibson-migrate/, and cmd/daemon/ may import raw store libraries directly",
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
