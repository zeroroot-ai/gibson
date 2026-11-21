// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

import (
	"context"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/sdk/auth"
)

// TenantGraph reads one tenant graph. component.PoolGraphRAGQuerier
// implements it, through the data-plane pool.
type TenantGraph interface {
	ReadGraph(ctx context.Context, tenant, cypher string, params map[string]any) ([]map[string]any, error)
}

// QuerierGraph reads the graph of the tenant of the context. The pool gives
// each tenant its own database, so a query holds no tenant predicate and
// cannot reach the graph of another tenant.
type QuerierGraph struct {
	// Graph returns the graph reader. It returns nil while the daemon starts.
	Graph func() TenantGraph
}

// Read implements GraphReader.
func (g QuerierGraph) Read(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return nil, ErrNoTenant
	}
	r := g.Graph()
	if r == nil {
		return nil, errors.New("incidentreport: the graph querier is not ready")
	}
	rows, err := r.ReadGraph(ctx, tenant.String(), cypher, params)
	if err != nil {
		return nil, fmt.Errorf("incidentreport: read the graph: %w", err)
	}
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
