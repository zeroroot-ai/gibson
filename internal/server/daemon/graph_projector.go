// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — graph_projector.go
//
// The graph projector makes the per-tenant Neo4j knowledge graph a read-model of
// the ECS brain's World (ADR-0007): the World (a fold of the Timeline) is the
// single source of truth, and this is the ONLY writer of the projected graph.
// It runs asynchronously on a ticker — never inside the brain's tick — so Neo4j
// I/O never blocks the single-writer reducer. Writes are idempotent (keyed by the
// host's stable, replay-deterministic id), so repeated passes converge.
package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// MissionProjection is the Mission-node shape the RPC layer hands the projector
// when a mission is created. It exists because a Mission node is materialized at
// CreateMission time rather than folded out of the World on the projection tick,
// and the projector is nonetheless the only code allowed to write it (ADR-0012).
type MissionProjection struct {
	// ID is the mission id, the node's identity together with the tenant.
	ID string
	// Name is the mission's display name.
	Name string
	// TargetID is the mission's target, stored as the node's `target` property.
	TargetID string
	// Status is the mission's lifecycle status at creation time.
	Status string
	// CreatedBy is the creating principal. Today the RPC layer passes the mission
	// name as a proxy; it becomes real once user attribution is wired.
	CreatedBy string
}

// GraphWriter upserts World entities into a tenant's knowledge graph. Abstracted
// so the projection loop is unit-testable without Neo4j.
type GraphWriter interface {
	UpsertHost(ctx context.Context, tenant string, h brain.HostSnapshot) error
	// UpsertMission materializes a :Mission node. Called from the CreateMission
	// RPC rather than from the projection tick — the RPC layer used to run this
	// MERGE inline, which made it a second writer; folding it here keeps the
	// projector the sole owner of entity materialization (ADR-0012 step 2).
	UpsertMission(ctx context.Context, tenant string, m MissionProjection) error
	UpsertFinding(ctx context.Context, tenant string, f brain.FindingSnapshot) error
	UpsertDomain(ctx context.Context, tenant string, d brain.DomainSnapshot) error
	UpsertSubdomain(ctx context.Context, tenant string, s brain.SubdomainSnapshot) error
	UpsertCredential(ctx context.Context, tenant string, c brain.CredentialSnapshot) error
	UpsertAccount(ctx context.Context, tenant string, a brain.AccountSnapshot) error
	UpsertAgentRun(ctx context.Context, tenant string, r brain.AgentRunSnapshot) error
	UpsertLlmCall(ctx context.Context, tenant string, c brain.LlmCallSnapshot) error
	// UpsertObservation materializes an :Observation — the node an
	// out-of-taxonomy shape lands on (ADR-0012). Keyed by the Timeline event
	// id, so projection is replayable and two sightings of the same fact stay
	// distinct nodes.
	UpsertObservation(ctx context.Context, tenant string, o brain.ObservationSnapshot) error
	// UpsertEntity materializes a typed application-lifecycle node
	// (gibson#1656): the label is a Taxonomy member passed as a parameter,
	// identity is (label, key), and every edge is a Taxonomy relationship
	// type to another (label, key) node, merged so re-projection never
	// duplicates.
	UpsertEntity(ctx context.Context, tenant string, e brain.EntitySnapshot) error
}

// GraphProjector periodically projects every tenant's World into the graph.
type GraphProjector struct {
	reg      *brain.Registry
	writer   GraphWriter
	interval time.Duration
	logger   *slog.Logger
}

// NewGraphProjector constructs a projector. interval defaults to 5s if non-positive.
func NewGraphProjector(reg *brain.Registry, writer GraphWriter, interval time.Duration, logger *slog.Logger) *GraphProjector {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &GraphProjector{reg: reg, writer: writer, interval: interval, logger: logger}
}

// project runs one projection pass over every tenant's World. Per-host failures
// are logged and skipped — projection is best-effort and self-heals next pass.
func (p *GraphProjector) project(ctx context.Context) {
	if p.reg == nil || p.writer == nil {
		return
	}
	for _, tenant := range p.reg.Tenants() {
		eng := p.reg.For(tenant)
		for _, h := range eng.Hosts() {
			if err := p.writer.UpsertHost(ctx, tenant, h); err != nil {
				p.logger.Warn("graph projection: host upsert failed",
					"tenant", tenant, "host_id", h.ID, "address", h.Address, "error", err)
			}
		}
		for _, f := range eng.Findings() {
			if err := p.writer.UpsertFinding(ctx, tenant, f); err != nil {
				p.logger.Warn("graph projection: finding upsert failed",
					"tenant", tenant, "finding_id", f.ID, "error", err)
			}
		}
		for _, d := range eng.Domains() {
			if err := p.writer.UpsertDomain(ctx, tenant, d); err != nil {
				p.logger.Warn("graph projection: domain upsert failed",
					"tenant", tenant, "domain_id", d.ID, "error", err)
			}
		}
		for _, s := range eng.Subdomains() {
			if err := p.writer.UpsertSubdomain(ctx, tenant, s); err != nil {
				p.logger.Warn("graph projection: subdomain upsert failed",
					"tenant", tenant, "subdomain_id", s.ID, "error", err)
			}
		}
		for _, c := range eng.Credentials() {
			if err := p.writer.UpsertCredential(ctx, tenant, c); err != nil {
				p.logger.Warn("graph projection: credential upsert failed",
					"tenant", tenant, "credential_id", c.ID, "error", err)
			}
		}
		for _, a := range eng.Accounts() {
			if err := p.writer.UpsertAccount(ctx, tenant, a); err != nil {
				p.logger.Warn("graph projection: account upsert failed",
					"tenant", tenant, "account_id", a.ID, "error", err)
			}
		}
		for _, r := range eng.AgentRuns() {
			if err := p.writer.UpsertAgentRun(ctx, tenant, r); err != nil {
				p.logger.Warn("graph projection: agent-run upsert failed",
					"tenant", tenant, "run_id", r.RunID, "error", err)
			}
		}
		for _, o := range eng.Observations() {
			if err := p.writer.UpsertObservation(ctx, tenant, o); err != nil {
				p.logger.Warn("graph projection: observation upsert failed",
					"tenant", tenant, "event_id", o.EventID, "shape", o.Shape, "error", err)
			}
		}
		for _, c := range eng.LlmCalls() {
			if err := p.writer.UpsertLlmCall(ctx, tenant, c); err != nil {
				p.logger.Warn("graph projection: llm-call upsert failed",
					"tenant", tenant, "call_id", c.CallID, "error", err)
			}
		}
		for _, e := range eng.Entities() {
			if err := p.writer.UpsertEntity(ctx, tenant, e); err != nil {
				p.logger.Warn("graph projection: entity upsert failed",
					"tenant", tenant, "label", e.Label, "key", e.Key, "error", err)
			}
		}
	}
}

// Run projects on a ticker until ctx is cancelled. Intended to run in its own
// goroutine for the daemon's lifetime.
func (p *GraphProjector) Run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	p.logger.Info("graph projector started", "interval", p.interval)
	for {
		select {
		case <-ctx.Done():
			p.logger.Info("graph projector stopped")
			return
		case <-t.C:
			p.project(ctx)
		}
	}
}
