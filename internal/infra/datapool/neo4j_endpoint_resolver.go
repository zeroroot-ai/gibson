// Package datapool provides per-tenant data-plane connection management.
//
// This file defines the Neo4jEndpoint struct and the Neo4jEndpointResolver
// interface — the seam between the daemon's runtime session path and the
// underlying deployment shape (instance-per-tenant vs shared Enterprise
// cluster with multi-tenancy via named databases).
//
// Deployment shape summary:
//
//   - "instance" mode: one Neo4j StatefulSet per tenant, provisioned by the
//     tenant-operator. The resolver reads the per-tenant credentials (including
//     bolt URI) from the per-tenant Vault namespace as a unified JSON payload
//     at the infra/neo4j path.
//     The Database field of the returned Neo4jEndpoint is empty (""), which
//     causes the Neo4j driver to use the default database on that instance.
//
//   - "multi-db" mode: a shared Neo4j Enterprise cluster. The resolver returns
//     the shared cluster URI with Database set to "tenant_<sanitized>", causing
//     the driver to route each tenant's session to the tenant's named database.
//     No I/O is performed at resolve time — all config comes from daemon startup
//     values.
//
// Callers (neo4j_per_tenant.go) must not depend on which implementation is
// active. The EndpointResolver is the only decision boundary.
package datapool

import (
	"context"

	"github.com/zeroroot-ai/sdk/auth"
)

// Neo4jEndpoint contains the resolved connection parameters for a single
// tenant's Neo4j endpoint.
//
//   - BoltURI: the bolt:// (or bolt+routing://) URI to connect to.
//     In instance mode this is the per-tenant StatefulSet service address.
//     In multi-db mode this is the shared cluster URI.
//
//   - Username / Password: credentials for the Neo4j connection.
//     In instance mode these are loaded from a projected volume Secret.
//     In multi-db mode these are the shared cluster credentials from config.
//
//   - Database: the Neo4j database name to use when opening a session.
//     Empty string means the driver's default database ("neo4j" by default).
//     In instance mode this is always empty — each tenant owns the whole
//     Neo4j instance and uses the default database.
//     In multi-db mode this is "tenant_<sanitized>", routing the session to
//     the per-tenant named database inside the shared cluster.
type Neo4jEndpoint struct {
	BoltURI  string
	Username string
	Password string
	Database string
}

// Neo4jEndpointResolver resolves the Neo4j endpoint for a given tenant.
//
// Implementations:
//   - instanceResolver (neo4j_endpoint_resolver_instance.go): Postgres-backed
//     registry lookup + projected-volume credential read. For instance mode.
//   - multiDBResolver (neo4j_endpoint_resolver_multidb.go): returns a
//     pre-configured shared cluster URI with computed database name. For
//     multi-db mode. No I/O at resolve time.
//
// The resolver is constructed once at daemon bootstrap based on
// config.GraphRAG.Neo4j.TenantMode and held for the process lifetime.
// Implementations MUST be safe for concurrent use from multiple goroutines.
type Neo4jEndpointResolver interface {
	// Resolve returns the Neo4j endpoint for the given tenant.
	//
	// On success the caller may use the endpoint to open a Neo4j driver
	// and/or session. The caller owns the returned *Neo4jEndpoint — the
	// resolver may return a pointer to cached data and the caller MUST NOT
	// modify the struct.
	//
	// Error cases:
	//   - *NotProvisionedError if the tenant's Neo4j endpoint has not yet
	//     been registered (instance mode) or if credentials are unavailable.
	//   - Any other error indicates a transient infrastructure failure (e.g.
	//     registry Postgres unreachable). In that case callers should NOT
	//     wrap the error as NotProvisionedError — it will propagate as
	//     codes.Unavailable via MapPoolError.
	Resolve(ctx context.Context, tenant auth.TenantID) (*Neo4jEndpoint, error)
}
