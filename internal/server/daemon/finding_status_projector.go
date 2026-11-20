// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// findingStatusSetter writes the status of one finding to the findings table.
// pgstore.Store satisfies it.
type findingStatusSetter interface {
	SetStatus(ctx context.Context, tenantID string, id types.ID, status finding.FindingStatus) (bool, error)
}

// findingStatusKey names one finding of one tenant.
type findingStatusKey struct{ tenant, id string }

// FindingStatusProjector copies the status of each finding in the tenant World
// to the findings table (gibson#1518). The World is the source of the status
// and the table is a read model, like the graph. Each pass writes only the
// findings whose status differs from the last write, so a failed write is
// retried on the next pass and nothing is lost.
type FindingStatusProjector struct {
	reg      *brain.Registry
	setter   findingStatusSetter
	interval time.Duration
	logger   *slog.Logger

	mu      sync.Mutex
	written map[findingStatusKey]string
}

// NewFindingStatusProjector builds the projector. A non-positive interval
// means 5 seconds.
func NewFindingStatusProjector(
	reg *brain.Registry, setter findingStatusSetter, interval time.Duration, logger *slog.Logger,
) *FindingStatusProjector {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &FindingStatusProjector{
		reg: reg, setter: setter, interval: interval, logger: logger,
		written: map[findingStatusKey]string{},
	}
}

// project runs one pass over every tenant World.
func (p *FindingStatusProjector) project(ctx context.Context) {
	if p.reg == nil || p.setter == nil {
		return
	}
	for _, tenant := range p.reg.Tenants() {
		for _, f := range p.reg.For(tenant).Findings() {
			key := findingStatusKey{tenant: tenant, id: f.ID}
			p.mu.Lock()
			last := p.written[key]
			p.mu.Unlock()
			if last == f.Status {
				continue
			}
			id := types.ID(f.ID)
			if id.Validate() != nil {
				// A World finding with no UUID, such as an anomaly finding, has
				// no row in the table. There is nothing to write.
				continue
			}
			if _, err := p.setter.SetStatus(ctx, tenant, id, finding.FindingStatus(f.Status)); err != nil {
				p.logger.Warn("finding status projection: write failed",
					"tenant", tenant, "finding_id", f.ID, "error", err)
				continue
			}
			p.mu.Lock()
			p.written[key] = f.Status
			p.mu.Unlock()
		}
	}
}

// Run projects on a ticker until ctx ends.
func (p *FindingStatusProjector) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.project(ctx)
		}
	}
}
