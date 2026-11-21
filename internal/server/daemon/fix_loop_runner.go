// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/fixloop"
	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

// findingPlacer is the read of the place of a finding. PoolGraphRAGQuerier
// serves it.
type findingPlacer interface {
	FindingPlaces(ctx context.Context, tenant, findingID string) ([]component.Place, error)
}

// applicationPlacer answers the Application of a finding. It resolves the
// querier on each call, because the daemon builds the querier after Start.
type applicationPlacer struct {
	querier func() any
}

// Application implements fixloop.Placer. A finding with no Application, such as
// a finding on a Host, has no place for the one-at-a-time rule and for the
// health signal.
func (p applicationPlacer) Application(ctx context.Context, tenant, findingID string) (string, error) {
	fp, ok := p.querier().(findingPlacer)
	if !ok {
		return "", errors.New("the graph querier is not wired")
	}
	places, err := fp.FindingPlaces(ctx, tenant, findingID)
	if err != nil {
		return "", fmt.Errorf("finding places: %w", err)
	}
	for _, pl := range places {
		if pl.Label == component.PlaceApplication {
			return pl.Key, nil
		}
	}
	return "", nil
}

// governedConnector is the fixloop.TenantCaller of the daemon. It resolves the
// callback manager on each call, because the daemon builds it after the fix
// loop. With no callback manager, the call fails and the Watcher tries it
// again on the next pass. No call of the fix loop goes around the governed
// path (ADR-0065).
type governedConnector struct {
	callback func() *harness.CallbackManager
}

var _ fixloop.TenantCaller = governedConnector{}

// CallConnectorForTenant implements fixloop.TenantCaller.
func (g governedConnector) CallConnectorForTenant(
	ctx context.Context, tenant, missionID, connector, tool string, args map[string]any,
) (any, error) {
	cb := g.callback()
	if cb == nil {
		return nil, errors.New("the callback manager is not wired, so no governed connector call can run")
	}
	out, err := cb.CallConnectorForTenant(ctx, tenant, missionID, connector, tool, args)
	if err != nil {
		return nil, fmt.Errorf("governed connector call: %w", err)
	}
	return out, nil
}

// FixLoopRunner reads the facts of the fix loop for each tenant World and
// submits the events (gibson#1458, #1463, #1465). The Watcher reads the facts
// itself. No agent states them (see package fixloop).
type FixLoopRunner struct {
	reg      *brain.Registry
	watcher  *fixloop.Watcher
	interval time.Duration
	logger   *slog.Logger
}

// NewFixLoopRunner builds the runner. A non-positive interval means 30 seconds.
func NewFixLoopRunner(reg *brain.Registry, w *fixloop.Watcher, interval time.Duration, logger *slog.Logger) *FixLoopRunner {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &FixLoopRunner{reg: reg, watcher: w, interval: interval, logger: logger}
}

// step runs one pass over each tenant World.
func (r *FixLoopRunner) step(ctx context.Context) {
	for _, tenant := range r.reg.Tenants() {
		eng := r.reg.For(tenant)
		var slots []brain.MergeSlot
		eng.ReadWorld(func(w *brain.World) { slots = w.MergeSlots() })
		for _, ev := range r.watcher.Step(ctx, tenant, eng.Findings(), slots) {
			eng.Submit(ev)
		}
	}
}

// Run steps on a ticker until ctx ends.
func (r *FixLoopRunner) Run(ctx context.Context) {
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.step(ctx)
		}
	}
}
