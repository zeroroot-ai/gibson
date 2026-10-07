// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenant

import (
	"strings"

	"github.com/zeroroot-ai/sdk/auth"
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

// PostgresDB returns the per-tenant Postgres database name.
//
// Format: tenant_<underscore>.
func (n Names) PostgresDB() string {
	return "tenant_" + n.Underscore()
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

// Neo4jNetworkPolicy returns the K8s NetworkPolicy name restricting bolt
// ingress to the per-tenant Neo4j pod. See ADR-0112 (single-writer graph
// ingress) and gibson#1255.
//
// Format: tenant-<slug>-neo4j-bolt.
func (n Names) Neo4jNetworkPolicy() string {
	return n.Neo4jStatefulSet() + "-bolt"
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
