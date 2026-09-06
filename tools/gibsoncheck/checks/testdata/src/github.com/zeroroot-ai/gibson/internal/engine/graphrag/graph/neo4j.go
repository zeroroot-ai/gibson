// Package graph is the analysistest fixture for the graphwrite analyzer's
// driver-adapter allowance (gibson#1300). This file's base name is neo4j.go, one
// of the two adapter files permitted to hold the driver, so its write
// transaction is allowed. Its sibling extra_writer.go is in the SAME package but
// is not an allowed adapter file — the pair proves the allowance is file-grained,
// not a blanket pass for the whole graphrag/graph package.
package graph

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// query stands in for the real adapter's Query: it selects a write transaction
// from the statement text, which schema DDL and the loader still rely on.
func query(ctx context.Context, session neo4j.SessionWithContext, cypher string) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, cypher, nil)
	})
	return err
}
