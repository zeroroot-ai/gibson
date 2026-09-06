package daemon

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// createMission is the RPC layer reaching for the driver from inside the same
// package as the projector. Being a neighbour of the sole writer is not the
// same as being it, so this is still a violation.
func createMission(ctx context.Context, session neo4j.SessionWithContext, id string) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) { // want `session\.ExecuteWrite opens a managed write transaction`
		return tx.Run(ctx, "MERGE (m:Mission {id: $id}) RETURN m", map[string]any{"id": id})
	})
	return err
}
