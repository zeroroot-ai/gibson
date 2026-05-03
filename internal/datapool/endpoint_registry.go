package datapool

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// endpointRegistry performs Postgres-backed lookups against the
// tenant_neo4j_endpoints table. This table is written by the tenant-operator
// when a per-tenant Neo4j StatefulSet reaches the Ready state, and is read by
// the daemon's instanceResolver at runtime.
//
// Schema (created by tenant-operator migration):
//
//	CREATE TABLE IF NOT EXISTS tenant_neo4j_endpoints (
//	    tenant_id    TEXT PRIMARY KEY,
//	    bolt_uri     TEXT NOT NULL,
//	    secret_name  TEXT NOT NULL,
//	    tier         TEXT NOT NULL,
//	    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
//	    ready_at     TIMESTAMPTZ,
//	    version      INT NOT NULL DEFAULT 1
//	);
//
// The daemon SELECTs by primary key (O(1)). The resolver caches results for
// 5 min so steady-state per-RPC latency is not dominated by this query.
//
// See design.md Component 4 and decision D2 for why a Postgres table was
// chosen over a Kubernetes ConfigMap.
type endpointRegistry struct {
	pool *pgxpool.Pool
}

// newEndpointRegistry constructs an endpointRegistry backed by the given admin
// Postgres pool. The pool must have read access to tenant_neo4j_endpoints.
func newEndpointRegistry(pool *pgxpool.Pool) *endpointRegistry {
	return &endpointRegistry{pool: pool}
}

// Lookup retrieves the bolt URI and secret name for a tenant's Neo4j endpoint.
//
// Returns (boltURI, secretName, nil) on success.
// Returns ("", "", sql.ErrNoRows) when no row exists for the tenant — the
// caller should interpret this as "not yet provisioned".
// Returns any other error on Postgres connectivity or query failure.
func (r *endpointRegistry) Lookup(ctx context.Context, tenantID string) (boltURI, secretName string, err error) {
	const q = `SELECT bolt_uri, secret_name FROM tenant_neo4j_endpoints WHERE tenant_id = $1`

	row := r.pool.QueryRow(ctx, q, tenantID)
	err = row.Scan(&boltURI, &secretName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", sql.ErrNoRows
		}
		// pgx uses pgx.ErrNoRows, not database/sql — handle both.
		if isNoRows(err) {
			return "", "", sql.ErrNoRows
		}
		return "", "", fmt.Errorf("endpoint_registry: query failed for tenant %q: %w", tenantID, err)
	}
	return boltURI, secretName, nil
}

// isNoRows checks whether a pgx error indicates no rows found. pgx/v5 uses
// pgx.ErrNoRows which has the same message as database/sql but is a distinct
// type; check both to be robust.
func isNoRows(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return msg == "no rows in result set"
}
