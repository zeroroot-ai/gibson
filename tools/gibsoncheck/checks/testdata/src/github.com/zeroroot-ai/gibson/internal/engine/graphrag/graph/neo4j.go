// Package graph is the analysistest fixture for the graphwrite analyzer's rule
// on the driver-adapter package (gibson#673). The package has no allowance: its
// Query is a read entry point, and a write transaction in it must be flagged,
// even in a file named neo4j.go. Its sibling extra_writer.go proves the same
// for a new write method in any other file.
package graph

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// query stands in for the old adapter Query, which picked a write transaction
// from the statement text. A write through this read entry point is flagged.
func query(ctx context.Context, session neo4j.SessionWithContext, cypher string) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) { // want `session\.ExecuteWrite opens a managed write transaction`
		return tx.Run(ctx, cypher, nil)
	})
	return err
}

// readQuery is the read entry point as it is now. A read is never flagged.
func readQuery(ctx context.Context, session neo4j.SessionWithContext, cypher string) error {
	_, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, cypher, nil)
	})
	return err
}
