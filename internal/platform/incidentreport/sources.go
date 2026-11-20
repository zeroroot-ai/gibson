// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"errors"
	"fmt"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// PoolGraph reads the graph of the tenant of the context through the data-plane
// pool. The pool gives each tenant its own database, so a query holds no
// tenant predicate and cannot reach the graph of another tenant.
type PoolGraph struct {
	// Pool returns the data-plane pool. It returns nil while the pool starts.
	Pool func() datapool.Pool
}

// Read implements GraphReader.
func (g PoolGraph) Read(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return nil, ErrNoTenant
	}
	pool := g.Pool()
	if pool == nil {
		return nil, errors.New("incidentreport: the data-plane pool is not ready")
	}
	conn, err := pool.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: acquire the data plane: %w", datapool.MapPoolError(err))
	}
	defer conn.Release()
	if conn.Neo4j == nil {
		// An unprovisioned graph is an error. An empty answer would read as
		// "no incident".
		return nil, errors.New("incidentreport: the tenant has no graph database")
	}
	res, err := conn.Neo4j.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		cur, runErr := tx.Run(ctx, cypher, params)
		if runErr != nil {
			return nil, fmt.Errorf("run: %w", runErr)
		}
		records, colErr := cur.Collect(ctx)
		if colErr != nil {
			return nil, fmt.Errorf("collect: %w", colErr)
		}
		rows := make([]map[string]any, 0, len(records))
		for _, rec := range records {
			if rec != nil {
				rows = append(rows, rec.AsMap())
			}
		}
		return rows, nil
	})
	if err != nil {
		return nil, fmt.Errorf("incidentreport: read the graph: %w", err)
	}
	rows, _ := res.([]map[string]any)
	return rows, nil
}

// BrainHistory reads the full history of the Timeline of the tenant of the
// context from the brain registry.
type BrainHistory struct {
	Registry *brain.Registry
}

// History implements HistoryReader.
func (b BrainHistory) History(ctx context.Context) ([]brain.Event, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return nil, ErrNoTenant
	}
	eng := b.Registry.For(tenant.String())
	if err := eng.Err(); err != nil {
		return nil, fmt.Errorf("incidentreport: the brain of the tenant is not available: %w", err)
	}
	evs, err := eng.History(ctx)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: %w", err)
	}
	return evs, nil
}
