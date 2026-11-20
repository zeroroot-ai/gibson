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

// findingRecordSetter writes fields of one finding to the findings table.
// pgstore.Store satisfies it.
type findingRecordSetter interface {
	SetStatus(ctx context.Context, tenantID string, id types.ID, status finding.FindingStatus) (bool, error)
	SetPriority(
		ctx context.Context, tenantID string, id types.ID, priority finding.Priority, rule string,
	) (bool, error)
}

// findingRecordKey names one finding of one tenant.
type findingRecordKey struct{ tenant, id string }

// findingRecord is what the projector last wrote for one finding.
type findingRecord struct {
	status   string
	priority string
	rule     string
}

// FindingRecordProjector copies the status and the priority of each finding in
// the tenant World to the findings table (gibson#1518, gibson#1522). The World
// is the source and the table is a read model, like the graph. Each pass
// writes only the fields that differ from the last write, so a failed write is
// retried on the next pass and nothing is lost.
type FindingRecordProjector struct {
	reg      *brain.Registry
	setter   findingRecordSetter
	interval time.Duration
	logger   *slog.Logger

	mu      sync.Mutex
	written map[findingRecordKey]findingRecord
}

// NewFindingRecordProjector builds the projector. A non-positive interval
// means 5 seconds.
func NewFindingRecordProjector(
	reg *brain.Registry, setter findingRecordSetter, interval time.Duration, logger *slog.Logger,
) *FindingRecordProjector {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &FindingRecordProjector{
		reg: reg, setter: setter, interval: interval, logger: logger,
		written: map[findingRecordKey]findingRecord{},
	}
}

// project runs one pass over every tenant World.
func (p *FindingRecordProjector) project(ctx context.Context) {
	if p.reg == nil || p.setter == nil {
		return
	}
	for _, tenant := range p.reg.Tenants() {
		for _, f := range p.reg.For(tenant).Findings() {
			p.projectOne(ctx, tenant, f)
		}
	}
}

func (p *FindingRecordProjector) projectOne(ctx context.Context, tenant string, f brain.FindingSnapshot) {
	id := types.ID(f.ID)
	if id.Validate() != nil {
		// A World finding with no UUID, such as an anomaly finding, has no row in
		// the table. There is nothing to write.
		return
	}
	key := findingRecordKey{tenant: tenant, id: f.ID}
	p.mu.Lock()
	rec := p.written[key]
	p.mu.Unlock()

	if rec.status != f.Status {
		if _, err := p.setter.SetStatus(ctx, tenant, id, finding.FindingStatus(f.Status)); err != nil {
			p.logger.Warn("finding projection: status write failed",
				"tenant", tenant, "finding_id", f.ID, "error", err)
		} else {
			rec.status = f.Status
		}
	}
	// No priority yet means nothing to write. An empty priority is not a value.
	if f.Priority != "" && (rec.priority != f.Priority || rec.rule != f.PriorityRule) {
		if _, err := p.setter.SetPriority(ctx, tenant, id, finding.Priority(f.Priority), f.PriorityRule); err != nil {
			p.logger.Warn("finding projection: priority write failed",
				"tenant", tenant, "finding_id", f.ID, "error", err)
		} else {
			rec.priority, rec.rule = f.Priority, f.PriorityRule
		}
	}
	p.mu.Lock()
	p.written[key] = rec
	p.mu.Unlock()
}

// Run projects on a ticker until ctx ends.
func (p *FindingRecordProjector) Run(ctx context.Context) {
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
