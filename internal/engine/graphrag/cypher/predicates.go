// Package cypher provides Cypher query building helpers.
// Tenant isolation is provided by the per-tenant Neo4j database
// (database-per-tenant-data-plane); no tenant_id property predicates
// are needed or permitted in Cypher queries (C1/C2/C3/C18 closure).
package cypher

// TenantPredicate is intentionally a no-op stub kept for build compatibility
// while call sites are migrated. It returns an empty string and must not be
// used to add WHERE tenant_id clauses. Delete all call sites and this function
// once migration is complete.
//
// Deprecated: Use the per-tenant Neo4j database instead.
func TenantPredicate(_, _ string) string {
	return ""
}
