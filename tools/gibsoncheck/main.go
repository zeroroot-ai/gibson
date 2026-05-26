// Command gibsoncheck is a custom Go analyzer that enforces
// architectural invariants of the Gibson daemon codebase. It is
// invoked from CI on every PR. Failures produce a non-zero exit code
// with descriptive messages naming the offending file and line.
//
// Checks bundled in this binary:
//
//   - forbiddenimports: gibson/ may not import OIDC/JWT validation
//     libraries beyond what is required for capability-grant minting,
//     and may not import zeroroot-ai/openfga/* outside the authz
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
//   - secretsnolog: in core/sdk/secrets/, core/gibson/internal/secrets/,
//     and provider packages, flags any []byte value returned from a
//     Get/Resolve secrets source method being passed (directly or through
//     a single rename) to a logging-shaped sink (slog/log/fmt.Print*/zap).
//     Plaintext credential values must never appear in daemon logs.
//
//   - pluginlegacy: flags imports of the pre-release plugin paths deleted
//     by the plugin-runtime spec (Spec 2, Phase 1): sdk/pluginkit (always),
//     gibson/internal/plugin (always), and sdk/plugin with old symbol names
//     (Initialize/Query/Shutdown/Health/Methods/MethodDescriptor/etc.).
//     Scope: packages under github.com/zeroroot-ai/sdk/ and
//     github.com/zeroroot-ai/gibson/internal/. Note that sdk/plugin itself
//     is being reborn as the new production plugin SDK in Phases 2-8; only
//     the deleted symbol names from the pre-release shape are flagged.
//
// Spec: unified-identity-and-authorization Requirements 6.6, 8.7, 14.1.
// Spec: database-per-tenant-data-plane Requirements 11.5, 16.1.
// Spec: daemon-mission-finding-per-tenant-cutover Requirements 5.3, 5.4.
// Spec: secrets-broker NFR Security.
// Spec: plugin-runtime Requirement 11.6.
// Spec: non-plugin-secret-isolation Requirement 2.
package main

import (
	"fmt"
	"os"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/zeroroot-ai/gibson/tools/gibsoncheck/checks"
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
			checks.ForbidRedisClientConstructionAnalyzer,
			checks.SecretsNoLogAnalyzer,
			checks.PluginLegacyAnalyzer,
			checks.AgentSecretsImportAnalyzer,
			checks.NoK8sAPIInDaemonAnalyzer,
		}...,
	)
}
