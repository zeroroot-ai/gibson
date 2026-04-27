// Command gibsoncheck is a custom Go analyzer that enforces
// architectural invariants of the Gibson daemon codebase. It is
// invoked from CI on every PR. Failures produce a non-zero exit code
// with descriptive messages naming the offending file and line.
//
// Checks bundled in this binary:
//
//   - forbiddenimports: gibson/ may not import OIDC/JWT validation
//     libraries beyond what is required for capability-grant minting,
//     and may not import zero-day-ai/openfga/* outside the authz
//     package. JWT validation is Envoy's job; FGA is ext-authz's.
//
//   - tenantfromcontext: gRPC handler functions must read tenant
//     from auth.TenantFromContext (or the legacy identity.TenantFromContext
//     during migration) and never from a request body field.
//
//   - notrustlocalhost: rejects any reference to the deleted
//     TrustLocalhost option.
//
//   - adminpoolacquire: only internal/admin/ and internal/datapool/admin/
//     may import the admin pool package. Any other package importing
//     internal/datapool/admin is a cross-tenant policy violation per
//     database-per-tenant-data-plane Requirement 11.5.
//
//   - forbidrawstoreimports: any package outside internal/datapool/,
//     internal/admin/, internal/migrate/, cmd/gibson-migrate/, and
//     cmd/daemon/ may not import raw store client libraries (pgx,
//     go-redis, neo4j-go-driver, qdrant, miniredis). All store access
//     must go through internal/datapool/Conn which is already
//     tenant-bound by construction. Test files may import miniredis.
//
//   - forbidrediskeyprefix: flags string literals that look like per-tenant
//     Redis key-prefix patterns (e.g. "tenant:", "gibson:tenant:") in
//     Redis call arguments outside the allowlisted subsystems. In the
//     database-per-tenant model, Conn.Redis is already scoped to the
//     tenant's logical DB and plain keys are sufficient.
//
// Spec: unified-identity-and-authorization Requirements 6.6, 8.7, 14.1.
// Spec: database-per-tenant-data-plane Requirements 11.5, 16.1.
package main

import (
	"fmt"
	"os"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/zero-day-ai/gibson/tools/gibsoncheck/checks"
)

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "gibsoncheck: %v\n", r)
			os.Exit(2)
		}
	}()
	multichecker.Main(
		[]*analysis.Analyzer{
			checks.ForbiddenImportsAnalyzer,
			checks.NoTrustLocalhostAnalyzer,
			checks.TenantFromContextAnalyzer,
			checks.AdminPoolAcquireAnalyzer,
			checks.ForbidRawStoreImportsAnalyzer,
			checks.ForbidRedisKeyPrefixAnalyzer,
		}...,
	)
}
