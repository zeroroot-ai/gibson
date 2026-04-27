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
// when probing individual tenant databases. Keeps daemon startup snappy even
// when some tenant DBs are temporarily unreachable.
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

// queryNeo4jVersion connects to Neo4j and reads the version property from the
// singleton :_SchemaVersion node in the given database. Returns 0 when the
// node does not exist.
func queryNeo4jVersion(ctx context.Context, uri, user, password, dbName string) (uint, error) {
	if uri == "" {
		return 0, nil
	}
	auth := neo4j.BasicAuth(user, password, "")
	driver, err := neo4j.NewDriverWithContext(uri, auth)
	if err != nil {
		return 0, fmt.Errorf("startup migration check: neo4j driver: %w", err)
	}
	defer driver.Close(ctx)

	// Use a short timeout for the connectivity check.
	verifyCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	if err := driver.VerifyConnectivity(verifyCtx); err != nil {
		// Neo4j unreachable — not fatal; treat as 0 applied.
		return 0, nil
	}

	session := driver.NewSession(ctx, neo4j.SessionConfig{
		DatabaseName: dbName,
		AccessMode:   neo4j.AccessModeRead,
	})
	defer session.Close(ctx)

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
