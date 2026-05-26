package datapool

import (
	"context"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/datapool/vectordb"
	"github.com/zeroroot-ai/sdk/auth"
)

// vectorPerTenant wraps the vectordb.Driver to provide per-tenant collection
// access. The collection name is tenant_<sanitized_tenantID>.
type vectorPerTenant struct {
	driver vectordb.Driver
}

func newVectorPerTenant(driver vectordb.Driver) *vectorPerTenant {
	return &vectorPerTenant{driver: driver}
}

// ForTenant returns a vectordb.Client bound to the tenant's dedicated
// collection (tenant_<sanitized>).
//
// Returns *NotProvisionedError if the collection does not exist.
func (v *vectorPerTenant) ForTenant(ctx context.Context, tenant auth.TenantID) (vectordb.Client, error) {
	sanitized, err := sanitizeForVector(tenant.String())
	if err != nil {
		return nil, err
	}
	collection := "tenant_" + sanitized

	client, err := v.driver.For(ctx, collection)
	if err != nil {
		if isVectorCollectionNotExist(err, collection) {
			return nil, &NotProvisionedError{
				Tenant: tenant.String(),
				Reason: fmt.Sprintf("vector collection %q does not exist", collection),
			}
		}
		return nil, fmt.Errorf("datapool: vector: failed to get client for tenant %s (collection %s): %w", tenant, collection, err)
	}
	return client, nil
}

// Close shuts down the underlying vector Driver.
func (v *vectorPerTenant) Close() error {
	return v.driver.Close()
}

// sanitizeForVector converts a tenant ID string to a safe vector collection
// name component. Collection names follow the same rules as Neo4j database
// names: lowercase letters, digits, and underscores.
func sanitizeForVector(tenantID string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("datapool: vector: empty tenant ID")
	}
	replaced := strings.ReplaceAll(tenantID, "-", "_")
	for _, c := range replaced {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
			return "", fmt.Errorf("datapool: vector: tenant ID %q contains character %q unsafe for vector collection names", tenantID, c)
		}
	}
	return replaced, nil
}

// isVectorCollectionNotExist returns true if the error indicates the vector
// collection does not exist. The exact check depends on the underlying vector
// store; the Redis VSS adapter populates errors with the collection name
// in a detectable way.
func isVectorCollectionNotExist(err error, collection string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, fmt.Sprintf("collection %q", collection))
}
