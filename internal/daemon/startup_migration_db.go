package daemon

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq" // Postgres driver
	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// connectTimeout is the maximum time the startup migration check will wait
// when probing individual tenant Postgres databases. Keeps daemon startup
// snappy even when some tenant DBs are temporarily unreachable.
// Note: Neo4j timeout is controlled by the pool's AcquireTimeout; this
// constant applies only to the direct Postgres SQL path.
const connectTimeout = 3 * time.Second

// queryPostgresVersion connects to the given DSN and reads the highest version
// from the schema_migrations table. Returns 0 when the table does not exist
// or no rows are present.
func queryPostgresVersion(ctx context.Context, dsn string) (uint, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return 0, fmt.Errorf("startup migration check: open postgres: %w", err)
	}
	defer db.Close()

	// Short ping timeout — we don't want to hang daemon startup.
	pingCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		// DB unreachable — treat as 0 applied (not an error that blocks startup).
		return 0, nil
	}

	var version uint
	row := db.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
	if err := row.Scan(&version); err != nil {
		// Table doesn't exist yet — no migrations applied.
		return 0, nil
	}
	return version, nil
}

// queryNeo4jVersionViaSession reads the version property from the singleton
// :_SchemaVersion node using a pre-opened per-tenant session. The session
// lifecycle is owned by the caller (via conn.Release); this function does not
// close the session.
//
// Returns 0 when the node does not exist (no migrations applied yet). The
// caller (pgAndNeo4jVersionReader.Neo4jVersion) controls the context timeout
// via the pool's AcquireTimeout; no additional timeout is added here.
func queryNeo4jVersionViaSession(ctx context.Context, session neo4j.SessionWithContext) (uint, error) {
	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "MATCH (v:_SchemaVersion) RETURN v.version AS version LIMIT 1", nil)
		if err != nil {
			return nil, err
		}
		if res.Next(ctx) {
			ver, _ := res.Record().Get("version")
			return ver, nil
		}
		return nil, res.Err()
	})
	if err != nil || result == nil {
		// Node doesn't exist — no migrations applied.
		return 0, nil
	}

	switch v := result.(type) {
	case int64:
		if v >= 0 {
			return uint(v), nil
		}
	case float64:
		if v >= 0 {
			return uint(v), nil
		}
	}
	return 0, nil
}
