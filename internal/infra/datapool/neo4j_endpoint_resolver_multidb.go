package datapool

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/sdk/auth"
)

// multiDBResolver implements Neo4jEndpointResolver for the "multi-db" tenant
// mode. In this mode all tenants share a single Neo4j Enterprise cluster and
// each tenant is isolated via a dedicated named database ("tenant_<sanitized>").
//
// This resolver performs NO I/O at resolve time — all configuration comes from
// daemon startup values (shared cluster URI, username, password from
// config.GraphRAG.Neo4j). It is O(1) per call.
//
// Under the current spec (per-tenant-data-plane-completion) this resolver is
// built and unit-tested but NOT active in the production code path. It becomes
// active when an operator sets config.GraphRAG.Neo4j.TenantMode = "multi-db"
// after migrating to a Neo4j Enterprise cluster. See MIGRATION-NEO4J.md for
// the 5-step migration runbook.
//
// The database name follows the same sanitization rules as the existing
// neo4j_per_tenant.go to ensure consistency during any migration period.
type multiDBResolver struct {
	sharedClusterURI string
	username         string
	password         string
}

// NewMultiDBResolver is the exported constructor for daemon bootstrap. It
// constructs a multiDBResolver from the shared cluster configuration.
// All three parameters are required when TenantMode is "multi-db".
//
// Implements Neo4jEndpointResolver.
func NewMultiDBResolver(sharedClusterURI, username, password string) Neo4jEndpointResolver {
	return newMultiDBResolver(sharedClusterURI, username, password)
}

// newMultiDBResolver constructs a multiDBResolver from the shared cluster
// configuration. All three parameters are required when TenantMode is "multi-db".
func newMultiDBResolver(sharedClusterURI, username, password string) *multiDBResolver {
	return &multiDBResolver{
		sharedClusterURI: sharedClusterURI,
		username:         username,
		password:         password,
	}
}

// Resolve returns the shared cluster URI with the per-tenant database name.
// No I/O is performed. The database name is "tenant_<sanitized>" using the
// same sanitization rules as the instance-mode driver construction.
// Implements Neo4jEndpointResolver.
func (m *multiDBResolver) Resolve(_ context.Context, tenant auth.TenantID) (*Neo4jEndpoint, error) {
	sanitized, err := sanitizeForNeo4j(tenant.String())
	if err != nil {
		return nil, fmt.Errorf("multiDBResolver: invalid tenant ID for Neo4j database name: %w", err)
	}

	return &Neo4jEndpoint{
		BoltURI:  m.sharedClusterURI,
		Username: m.username,
		Password: m.password,
		Database: fmt.Sprintf("tenant_%s", sanitized),
	}, nil
}
