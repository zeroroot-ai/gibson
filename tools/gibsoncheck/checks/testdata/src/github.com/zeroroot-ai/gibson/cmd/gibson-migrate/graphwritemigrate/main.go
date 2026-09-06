// Package graphwritemigrate is the analysistest fixture for the gibson-migrate
// exemption: schema DDL runs as its own Job outside the data plane, so it may
// open a write transaction. No `want` comments — this file must produce zero
// diagnostics.
package graphwritemigrate

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func applyConstraint(ctx context.Context, session neo4j.SessionWithContext) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, "CREATE CONSTRAINT IF NOT EXISTS FOR (h:Host) REQUIRE h.brain_id IS UNIQUE", nil)
	})
	return err
}
