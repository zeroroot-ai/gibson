package dataplane

// Per-tenant Vault credential paths. Full path is
// secret/data/<VaultPathPrefix>/<one of the constants below>, where
// VaultPathPrefix is `tenant.Names.VaultPathPrefix()` ("tenant/<slug>").
//
// The operator writes these at provision time (one Vault write per
// data-plane store); the daemon reads them at runtime via the secrets
// broker. The broker resolves the per-tenant path prefix from the request
// context, so callers pass only the suffix:
//
//	dsn, _ := broker.Get(ctx, tenant, dataplane.VaultPathInfraPostgres)
//
// See spec tenant-provisioning-unification Requirements 4.1-4.7.
const (
	// VaultPathInfraPostgres is the per-tenant Postgres credentials path.
	// Payload (JSON): {host, port, database, role, password, dsn}.
	VaultPathInfraPostgres = "infra/postgres"

	// VaultPathInfraNeo4j is the per-tenant Neo4j credentials path.
	// Payload (JSON): {bolt_uri, username, password}.
	VaultPathInfraNeo4j = "infra/neo4j"

	// VaultPathInfraRedis is the per-tenant Redis logical-DB path.
	// Payload (JSON): {addr, db_index, password}.
	VaultPathInfraRedis = "infra/redis"

	// VaultPathInfraVector is the per-tenant Qdrant collection path.
	// Payload (JSON): {url, collection, api_key}.
	VaultPathInfraVector = "infra/vector"

	// VaultPathInfraLangfuse is the per-tenant Langfuse project credentials
	// path. Payload (JSON): {project_id, public_key, secret_key, host}.
	VaultPathInfraLangfuse = "infra/langfuse"

	// VaultPathInfraKEK is the per-tenant KEK path written by the
	// DeriveTenantKEK saga step. The KEK itself is short-lived material
	// the operator uses inside one reconcile to derive credentials for
	// the data-plane stores; production deployments may choose not to
	// persist it at all (Vault transit derive is on-demand). See spec
	// Requirement 5.6 for rotation semantics.
	VaultPathInfraKEK = "infra/kek"
)
