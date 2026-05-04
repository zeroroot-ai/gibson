package tenant

import (
	"fmt"
	"strings"

	"github.com/zero-day-ai/sdk/auth"
)

// Names is the canonical source for every per-tenant resource name in the
// Gibson control plane. Construct with FromTenantID and call methods —
// never assemble per-tenant names from string concatenation at call sites.
//
// The zero value is invalid: zero-value Names returns empty strings from
// every method, which would silently break callers. Use FromTenantID to
// construct.
type Names struct {
	id auth.TenantID
}

// FromTenantID returns a Names value for the given (already-validated)
// TenantID. The auth package guarantees the TenantID is non-empty and
// matches the platform validation regex; FromTenantID does not re-validate.
func FromTenantID(id auth.TenantID) Names {
	return Names{id: id}
}

// TenantID returns the wrapped TenantID. Useful for callers that received
// a Names value and need the underlying type back (e.g., for context
// injection).
func (n Names) TenantID() auth.TenantID {
	return n.id
}

// Slug returns the tenant ID exactly as validated — lowercase ASCII,
// hyphens and underscores allowed, suitable for K8s resource names.
//
// Format: matches auth.TenantID.String().
func (n Names) Slug() string {
	return n.id.String()
}

// Underscore returns the tenant ID with hyphens replaced by underscores.
// Suitable for SQL identifiers (Postgres database names, role names) and
// Qdrant collection names where hyphens require quoting.
//
// Format: <lowercase ASCII letters, digits, underscores>.
func (n Names) Underscore() string {
	return strings.ReplaceAll(n.id.String(), "-", "_")
}

// Namespace returns the K8s namespace name for this tenant.
//
// Format: <slug>. Per spec tenant-provisioning-unification Requirement 1.5,
// the namespace name equals the tenant ID exactly — no "tenant-" prefix.
// Reserved-name protection (e.g., "default", "kube-system") is enforced
// by the operator's admission webhook against a chart-managed denylist,
// not by string transformation.
func (n Names) Namespace() string {
	return n.id.String()
}

// PostgresDB returns the per-tenant Postgres database name.
//
// Format: tenant_<underscore>.
func (n Names) PostgresDB() string {
	return "tenant_" + n.Underscore()
}

// PostgresAppRole returns the per-tenant Postgres login role name. This is
// the role the daemon connects as for runtime data-plane access — NOT the
// admin role used by the operator for DDL.
//
// Format: tenant_<underscore>_app. The "_app" suffix distinguishes the
// runtime role from any admin/owner roles that may be added in the future
// and is the canonical form the daemon's pgxpool reads from Vault.
func (n Names) PostgresAppRole() string {
	return n.PostgresDB() + "_app"
}

// Neo4jStatefulSet returns the K8s StatefulSet name for the per-tenant
// Neo4j instance. The matching Service has the same name.
//
// Format: tenant-<slug>-neo4j.
func (n Names) Neo4jStatefulSet() string {
	return "tenant-" + n.Slug() + "-neo4j"
}

// Neo4jService returns the K8s Service name for the per-tenant Neo4j
// instance. By convention this matches Neo4jStatefulSet.
func (n Names) Neo4jService() string {
	return n.Neo4jStatefulSet()
}

// Neo4jSecret returns the K8s Secret name holding the Neo4j NEO4J_AUTH
// value (consumed by the Neo4j pod's startup env). The daemon does NOT
// read this Secret — it reads the same credentials from Vault at
// dataplane.VaultPathInfraNeo4j.
//
// Format: tenant-<slug>-neo4j-auth.
func (n Names) Neo4jSecret() string {
	return n.Neo4jStatefulSet() + "-auth"
}

// Neo4jPVCRoot returns the PVC name root for the per-tenant Neo4j
// StatefulSet. The actual PVC for the first replica is "<root>-0".
//
// Format: data-tenant-<slug>-neo4j.
func (n Names) Neo4jPVCRoot() string {
	return "data-" + n.Neo4jStatefulSet()
}

// Neo4jBoltURI returns the Bolt URI the daemon dials to reach the
// per-tenant Neo4j instance. operatorNamespace is the namespace where the
// per-tenant StatefulSet is deployed (typically the gibson release
// namespace, NOT the tenant's own namespace).
//
// Format: bolt://<service>.<operator-ns>.svc.cluster.local:7687.
func (n Names) Neo4jBoltURI(operatorNamespace string) string {
	return fmt.Sprintf("bolt://%s.%s.svc.cluster.local:7687",
		n.Neo4jService(), operatorNamespace)
}

// RedisIndexField returns the field name used in the platform-wide Redis
// master-index hash to look up this tenant's logical-DB index. The hash
// key itself is dataplane.RedisIndexHashKey, which is shared across all
// tenants.
//
// Format: <slug>.
func (n Names) RedisIndexField() string {
	return n.Slug()
}

// QdrantCollection returns the per-tenant Qdrant collection name.
//
// Format: tenant_<underscore>.
func (n Names) QdrantCollection() string {
	return "tenant_" + n.Underscore()
}

// VaultPathPrefix returns the path prefix under which all per-tenant
// secrets live in the Community-edition path-prefix Vault model. The full
// path for a given infrastructure secret is
// secret/data/<VaultPathPrefix>/<dataplane.VaultPathInfra*>.
//
// Format: tenant/<slug>.
func (n Names) VaultPathPrefix() string {
	return "tenant/" + n.Slug()
}

// VaultPolicyName returns the Vault ACL policy name granting read/write
// access to this tenant's path prefix. Bound to the per-tenant JWT auth
// role.
//
// Format: tenant-<slug>-app.
func (n Names) VaultPolicyName() string {
	return "tenant-" + n.Slug() + "-app"
}

// VaultJWTRoleName returns the Vault JWT auth role name used by per-tenant
// plugin workloads (gibson-tool-runner pods) to authenticate to Vault.
//
// Format: gibson-plugin-<slug>.
func (n Names) VaultJWTRoleName() string {
	return "gibson-plugin-" + n.Slug()
}

// FGAObject returns the OpenFGA object identifier for this tenant. Used
// in tuple writes and authorization checks throughout the control plane.
//
// Format: tenant:<slug>.
func (n Names) FGAObject() string {
	return "tenant:" + n.Slug()
}

// ZitadelOrgSlug returns the Zitadel organization "primary domain" slug
// for this tenant. The display name (free-form, customer-chosen) is
// stored separately on Tenant.spec.displayName.
//
// Format: <slug>.
func (n Names) ZitadelOrgSlug() string {
	return n.Slug()
}

// LangfuseProject returns the Langfuse project name for this tenant.
//
// Format: <slug>.
func (n Names) LangfuseProject() string {
	return n.Slug()
}
