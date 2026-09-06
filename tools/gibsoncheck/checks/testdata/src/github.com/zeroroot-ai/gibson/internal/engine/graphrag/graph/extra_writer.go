package graph

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// mergeNode is a NEW write-capable method added outside the two allowed adapter
// files. Being in the adapter package is not the same as being an adapter file,
// so this must be flagged — this is exactly the gap the narrowed exemption
// closes (gibson#1300).
func mergeNode(ctx context.Context, session neo4j.SessionWithContext, id string) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) { // want `session\.ExecuteWrite opens a managed write transaction`
		return tx.Run(ctx, "MERGE (n {id: $id}) RETURN n", map[string]any{"id": id})
	})
	return err
}
