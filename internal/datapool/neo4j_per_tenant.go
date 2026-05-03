package datapool

import (
	"context"
	"fmt"
	"strings"
	"sync"

	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zero-day-ai/sdk/auth"
)

// neo4jPerTenant manages per-tenant Neo4j sessions. It holds a cache of
// DriverWithContext instances keyed by tenant ID (one driver per endpoint)
// and creates per-tenant sessions on demand via a Neo4jEndpointResolver.
//
// Session routing per mode:
//   - instance mode (instanceResolver): one driver per tenant pointing at the
//     per-tenant StatefulSet; sessions use the default database ("neo4j").
//   - multi-db mode (multiDBResolver): one driver per tenant pointing at the
//     shared Enterprise cluster; sessions use the tenant_<sanitized> database.
//
// Sessions are caller-owned; Conn.Release closes them. Drivers are cached
// for the process lifetime (eviction is future work if fleet size demands it).
//
// Spec: per-tenant-data-plane-completion Task 15 / Req 5.1, 5.2.
type neo4jPerTenant struct {
	resolver Neo4jEndpointResolver

	mu      sync.RWMutex
	drivers map[auth.TenantID]neo4j.DriverWithContext
}

// newNeo4jPerTenant constructs a neo4jPerTenant backed by the given resolver.
// The resolver is called on the first ForTenant call per tenant to obtain
// the endpoint; subsequent calls use the cached driver.
func newNeo4jPerTenant(resolver Neo4jEndpointResolver) *neo4jPerTenant {
	return &neo4jPerTenant{
		resolver: resolver,
		drivers:  make(map[auth.TenantID]neo4j.DriverWithContext),
	}
}

// ForTenant creates a new Neo4j session for the given tenant.
//
// On first call for a tenant the resolver is consulted to obtain the bolt URI
// and credentials; a DriverWithContext is created and cached. Subsequent calls
// reuse the cached driver.
//
// The returned session is caller-owned and must be closed. The recommended
// pattern is to close it in the release func registered on Conn (see
// pool_impl.go:For).
//
// Returns *NotProvisionedError if the resolver indicates the tenant's Neo4j
// endpoint is not yet provisioned.
func (n *neo4jPerTenant) ForTenant(ctx context.Context, tenant auth.TenantID) (neo4j.SessionWithContext, error) {
	driver, err := n.driverForTenant(ctx, tenant)
	if err != nil {
		return nil, err
	}

	// Resolve again (cached) to get the database name.
	ep, err := n.resolver.Resolve(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("datapool: neo4j: ForTenant: resolving endpoint for session: %w", err)
	}

	session := driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: ep.Database, // "" = default DB in instance mode; "tenant_x" in multi-db
		AccessMode:   neo4j.AccessModeWrite,
	})

	return session, nil
}

// driverForTenant returns (creating if necessary) the cached DriverWithContext
// for the given tenant. Protected by sync.RWMutex.
func (n *neo4jPerTenant) driverForTenant(ctx context.Context, tenant auth.TenantID) (neo4j.DriverWithContext, error) {
	// Fast path: read lock.
	n.mu.RLock()
	driver, ok := n.drivers[tenant]
	n.mu.RUnlock()
	if ok {
		return driver, nil
	}

	// Slow path: resolve endpoint and create driver under write lock.
	// Double-check after acquiring write lock to avoid duplicate creation
	// under concurrent calls for the same tenant.
	n.mu.Lock()
	defer n.mu.Unlock()

	if driver, ok = n.drivers[tenant]; ok {
		return driver, nil
	}

	ep, err := n.resolver.Resolve(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("datapool: neo4j: resolving endpoint for tenant %s: %w", tenant, err)
	}

	driver, err = neo4j.NewDriverWithContext(ep.BoltURI, neo4j.BasicAuth(ep.Username, ep.Password, ""))
	if err != nil {
		return nil, fmt.Errorf("datapool: neo4j: creating driver for tenant %s: %w", tenant, err)
	}

	n.drivers[tenant] = driver
	return driver, nil
}

// Close shuts down all cached Neo4j drivers. Should be called during daemon
// shutdown after all in-flight sessions have been closed by their owners.
func (n *neo4jPerTenant) Close(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	var firstErr error
	for tenant, driver := range n.drivers {
		if err := driver.Close(ctx); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("datapool: neo4j: closing driver for tenant %s: %w", tenant, err)
		}
	}
	n.drivers = make(map[auth.TenantID]neo4j.DriverWithContext)
	return firstErr
}

// sanitizeForNeo4j converts a tenant ID to a safe Neo4j database name
// component. Neo4j database names must be [a-z0-9.] with a letter start and
// at most 63 characters. We apply the same substitution as Postgres (hyphens
// → underscores).
func sanitizeForNeo4j(tenantID string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("datapool: neo4j: empty tenant ID")
	}
	// Replace hyphens with underscores (Neo4j database names don't allow hyphens).
	replaced := strings.ReplaceAll(tenantID, "-", "_")
	// Validate: only [a-z0-9_] after replacement.
	for _, c := range replaced {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return "", fmt.Errorf("datapool: neo4j: tenant ID %q contains character %q unsafe for Neo4j database names", tenantID, c)
		}
	}
	if len(replaced) > 63 {
		return "", fmt.Errorf("datapool: neo4j: sanitized name %q exceeds 63-character Neo4j database name limit", replaced)
	}
	return replaced, nil
}

// isNeo4jDBNotExist returns true if the error indicates a Neo4j database
// does not exist. Neo4j surfaces this as an error message containing
// "database does not exist" or Neo4j error code Neo.ClientError.Database.DatabaseNotFound.
func isNeo4jDBNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database does not exist") ||
		strings.Contains(msg, "DatabaseNotFound") ||
		strings.Contains(msg, "Neo.ClientError.Database.DatabaseNotFound")
}
