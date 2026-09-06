package graphwriteviolation

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// TestFixtureWritesAreSkipped stands in for a test that seeds a fixture
// graph directly against the driver. Test files are exempt (they are not
// the production data plane), so this call must produce NO diagnostic even
// though it is the exact shape the analyzer otherwise flags — no `want`
// comment here means analysistest fails if the analyzer stops skipping
// _test.go files.
func testFixtureWrite(ctx context.Context, session neo4j.SessionWithContext) error {
	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		return tx.Run(ctx, "MERGE (m:Mission {id: $id}) RETURN m", nil)
	})
	return err
}
