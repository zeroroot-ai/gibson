package graph

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// mergeNode is a NEW write-capable method in the adapter package. No file of
// that package may open a write transaction,
// so this must be flagged: the adapter package has no allowance (gibson#673).
func mergeNode(ctx context.Context, session neo4j.SessionWithContext, id string) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) { // want `session\.ExecuteWrite opens a managed write transaction`
		return tx.Run(ctx, "MERGE (n {id: $id}) RETURN n", map[string]any{"id": id})
	})
	return err
}
