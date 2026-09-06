// Package graphwriteviolation is a synthetic re-introduction of the write path
// ADR-0012 removed: an RPC-layer file in the daemon package tree that opens its
// own Neo4j write transaction. This is the mutation case — if the graphwrite
// analyzer stops flagging this file, the guard has stopped working.
package graphwriteviolation

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// createMission mirrors the inline `MERGE (m:Mission …)` the CreateMission RPC
// handler used to run before it was folded into the projector.
func createMission(ctx context.Context, session neo4j.SessionWithContext, id string) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) { // want `session\.ExecuteWrite opens a managed write transaction`
		return tx.Run(ctx, "MERGE (m:Mission {id: $id}) RETURN m", map[string]any{"id": id})
	})
	return err
}

// beginWrite takes the other route to a write: an explicit transaction.
func beginWrite(ctx context.Context, session neo4j.SessionWithContext) error {
	tx, err := session.BeginTransaction(ctx) // want `session\.BeginTransaction opens an explicit transaction`
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// readIsFine shows that reads are not restricted — the graph is a read model.
func readIsFine(ctx context.Context, session neo4j.SessionWithContext) error {
	_, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, "MATCH (m:Mission) RETURN m", nil)
	})
	return err
}
