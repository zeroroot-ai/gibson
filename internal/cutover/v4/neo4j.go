package cutoverv4

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
)

const (
	// nodeBatchSize is the maximum number of nodes deleted per Cypher batch.
	// Keeping this below Neo4j's default transaction heap guard (1 GB) while
	// remaining performant for typical pre-prod tenant sizes.
	nodeBatchSize = 10_000
)

// WipeTenantGraph deletes all Neo4j nodes (and their relationships) whose
// tenant_id property matches tenantID.
//
// For tenants with more than batchNodeThreshold nodes the deletion is performed
// in batches of nodeBatchSize to avoid exhausting Neo4j heap inside a single
// transaction.  The function returns the total count of nodes deleted.
//
// Constraints:
//   - Uses parameterised Cypher; never string-concatenates tenantID into queries.
//   - Does NOT drop or recreate any indices.
//   - Does NOT touch nodes belonging to other tenants.
//
// The caller is responsible for providing an already-connected GraphClient;
// this function creates no new connections.
func WipeTenantGraph(ctx context.Context, client graph.GraphClient, tenantID string) (int, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("WipeTenantGraph: tenantID must not be empty")
	}

	// Determine node count to choose between single-shot and batched deletion.
	total, err := countTenantNodes(ctx, client, tenantID)
	if err != nil {
		return 0, fmt.Errorf("WipeTenantGraph: count nodes: %w", err)
	}

	if total == 0 {
		return 0, nil
	}

	if total <= batchNodeThreshold {
		deleted, err := deleteAllTenantNodes(ctx, client, tenantID)
		if err != nil {
			return 0, fmt.Errorf("WipeTenantGraph: delete all: %w", err)
		}
		return deleted, nil
	}

	// Batched deletion for large tenants.
	return deleteTenantNodesBatched(ctx, client, tenantID)
}

// countTenantNodes returns the number of nodes with the given tenant_id.
func countTenantNodes(ctx context.Context, client graph.GraphClient, tenantID string) (int, error) {
	const cypher = `MATCH (n) WHERE n.tenant_id = $t RETURN count(n) AS cnt`

	result, err := client.Query(ctx, cypher, map[string]any{"t": tenantID})
	if err != nil {
		return 0, err
	}

	if len(result.Records) == 0 {
		return 0, nil
	}

	cnt, ok := result.Records[0]["cnt"]
	if !ok {
		return 0, fmt.Errorf("count query returned no 'cnt' column")
	}

	switch v := cnt.(type) {
	case int64:
		return int(v), nil
	case int:
		return v, nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("unexpected type for cnt: %T", cnt)
	}
}

// deleteAllTenantNodes executes a single DETACH DELETE for small tenants.
// Returns the number of nodes deleted according to the query summary.
func deleteAllTenantNodes(ctx context.Context, client graph.GraphClient, tenantID string) (int, error) {
	const cypher = `
		MATCH (n) WHERE n.tenant_id = $t
		DETACH DELETE n
	`

	result, err := client.Query(ctx, cypher, map[string]any{"t": tenantID})
	if err != nil {
		return 0, err
	}

	return result.Summary.NodesDeleted, nil
}

// deleteTenantNodesBatched deletes nodes in chunks of nodeBatchSize to avoid
// exhausting Neo4j transaction heap for large tenants. It loops until no nodes
// remain for the tenant. Returns the cumulative node count.
func deleteTenantNodesBatched(ctx context.Context, client graph.GraphClient, tenantID string) (int, error) {
	const cypher = `
		MATCH (n) WHERE n.tenant_id = $t
		WITH n LIMIT $limit
		DETACH DELETE n
		RETURN count(n) AS deleted
	`

	params := map[string]any{
		"t":     tenantID,
		"limit": int64(nodeBatchSize),
	}

	total := 0
	for {
		result, err := client.Query(ctx, cypher, params)
		if err != nil {
			return total, fmt.Errorf("batch delete: %w", err)
		}

		// Extract batch count from RETURN clause if present.
		batchDeleted := result.Summary.NodesDeleted
		if len(result.Records) > 0 {
			if v, ok := result.Records[0]["deleted"]; ok {
				switch n := v.(type) {
				case int64:
					batchDeleted = int(n)
				case int:
					batchDeleted = n
				case float64:
					batchDeleted = int(n)
				}
			}
		}

		total += batchDeleted

		// If we deleted fewer nodes than the batch size, we're done.
		if batchDeleted < nodeBatchSize {
			break
		}

		// Check context cancellation between batches.
		if err := ctx.Err(); err != nil {
			return total, fmt.Errorf("context cancelled after deleting %d nodes: %w", total, err)
		}
	}

	return total, nil
}
