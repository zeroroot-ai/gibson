// Package daemon is the analysistest fixture for the graphwrite analyzer's
// allowance. This file stands in for the real graph projector: it is in the
// daemon package AND its base name starts with graph_projector, so it may open
// a write transaction. Its sibling grpc.go is in the SAME package and may not —
// the pair is what proves the allowance is file-grained rather than a blanket
// pass for everything in the daemon package.
package daemon

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// upsertHost is the projector doing its job: constant Cypher, $params, inside a
// write transaction it is the only code allowed to open.
func upsertHost(ctx context.Context, session neo4j.SessionWithContext, id string) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, "MERGE (h:Host {brain_id: $id}) RETURN h", map[string]any{"id": id})
	})
	return err
}
