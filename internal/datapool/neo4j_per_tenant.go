package datapool

import (
	"context"
	"fmt"
	"strings"

	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/zero-day-ai/sdk/auth"
)

// neo4jPerTenant manages per-tenant Neo4j sessions. It holds a single shared
// DriverWithContext (one per Neo4j cluster) and creates per-tenant sessions
// on demand. Sessions are caller-owned; Conn.Release closes them.
type neo4jPerTenant struct {
	driver neo4j.DriverWithContext
}

func newNeo4jPerTenant(uri, user, password string) (*neo4jPerTenant, error) {
	if uri == "" {
		return nil, fmt.Errorf("datapool: neo4j: URI is required")
	}
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, password, ""))
	if err != nil {
		return nil, fmt.Errorf("datapool: neo4j: failed to create driver: %w", err)
	}
	return &neo4jPerTenant{driver: driver}, nil
}

// ForTenant creates a new Neo4j session bound to the tenant's dedicated
// database (tenant_<sanitized>). The session is caller-owned and must be
// closed via Conn.Release.
//
// Returns *NotProvisionedError if the database does not exist (detected on
// first use, not at session creation time, due to Neo4j's lazy-connect model).
func (n *neo4jPerTenant) ForTenant(_ context.Context, tenant auth.TenantID) (neo4j.SessionWithContext, error) {
	sanitized, err := sanitizeForNeo4j(tenant.String())
	if err != nil {
		return nil, err
	}

	dbName := "tenant_" + sanitized

	session := n.driver.NewSession(context.Background(), neo4j.SessionConfig{
		DatabaseName: dbName,
		AccessMode:   neo4j.AccessModeWrite,
	})

	return session, nil
}

// Close shuts down the shared Neo4j driver.
func (n *neo4jPerTenant) Close(ctx context.Context) error {
	if n.driver == nil {
		return nil
	}
	return n.driver.Close(ctx)
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
