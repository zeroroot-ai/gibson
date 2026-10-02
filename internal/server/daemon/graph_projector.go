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

// MissionProjection is the complete Mission-node shape. Every caller describes
// the whole node, because a Mission node is written three times — when a mission
// is created, when a run bootstraps its graph, and on every projection tick for
// as long as the mission is in the World — and the projector is the only code
// allowed to write it (ADR-0012).
//
// An empty string field means "the caller does not know this yet", not "set it
// to empty", and a blank must never erase a known value: the create-time write
// runs in a goroutine, so it can land either side of the run-time write, and the
// tick knows a mission's status but not its objective or definition. The Cypher
// keeps the stored value in that case.
type MissionProjection struct {
	// ID is the mission id, the node's identity together with the tenant.
	ID string
	// Name is the mission's display name.
	Name string
	// Description is the mission's full description.
	Description string
	// TargetID is the mission's primary target, stored as the node's `target`
	// property. A fan-out run's per-target work hangs off its MissionNodes
	// (gibson#549), not off this.
	TargetID string
	// Status is the mission's lifecycle status.
	Status string
	// CreatedBy is the creating principal. Today the RPC layer passes the mission
	// name as a proxy; it becomes real once user attribution is wired.
	CreatedBy string
	// Objective is the mission's goal in one sentence, so a graph reader can see
	// what a mission was for without fetching its definition.
	Objective string
	// YAMLSource is the mission definition the run was projected from.
	YAMLSource string
	// StartedAt is when the run began. nil at create time.
	StartedAt *time.Time
}

// TargetProjection is the :Target-node shape — the registered entity a mission
// assesses, as distinct from a :Host, which is discovered (gibson#550).
//
// A Target is not a World entity. It is read from the target store when a run
// resolves its target set, so the projection tick does not produce one and the
// per-run graph bootstrap does. Empty fields keep their stored value, like
// every other write through this writer.
type TargetProjection struct {
	// ID is the target UUID. It is the node's identity, and it is already the
	// value of Finding.scope and of a fan-out instance's target_id, which is
	// what makes a Target node a join rather than a new fact.
	ID string
	// Name is the target's display name.
	Name string
	// Type is the target's schema-based type.
	Type string
	// URL is the target endpoint, by the same precedence a run uses:
	// URL, then Connection["url"], then the name.
	URL string
	// Status is the target's registration status.
	Status string
	// MissionID, when set, draws Mission -[:TARGETS]-> Target. The Mission node
	// is MATCHed, never merged: it has one writer and this is not it
	// (gibson#551).
	MissionID string
}

// GraphWriter upserts World entities into a tenant's knowledge graph. Abstracted
// so the projection loop is unit-testable without Neo4j.
type GraphWriter interface {
	UpsertHost(ctx context.Context, tenant string, h brain.HostSnapshot) error
	// UpsertMission materializes a :Mission node. It is the ONLY writer of one:
	// the CreateMission RPC and the per-run graph bootstrap both used to MERGE
	// their own, which is what ADR-0012 step 2 forbids. Both now call this, and
	// so does the projection tick, which is what keeps a mission's status
	// current for its whole life.
	UpsertMission(ctx context.Context, tenant string, m MissionProjection) error
	// UpsertTarget materializes a :Target — the registered entity a mission
	// assesses. Called from the per-run graph bootstrap, because a Target is
	// read from the target store rather than folded out of the World.
	UpsertTarget(ctx context.Context, tenant string, t TargetProjection) error
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
		// Missions are projected on the tick like every other entity, so the
		// graph tracks a mission's status for its whole life. Before this, the
		// two eager writers both ran when a mission STARTED, so :Mission.status
		// was "running" forever and GetGraphSummary reported every mission as
		// running. The tick does not know the objective, the
		// definition or the start time; the upsert keeps the stored value for a
		// field whose parameter is empty, which is what makes that safe.
		for _, m := range eng.Missions() {
			if err := p.writer.UpsertMission(ctx, tenant, missionProjectionOf(m)); err != nil {
				p.logger.Warn("graph projection: mission upsert failed",
					"tenant", tenant, "mission_id", m.ID, "error", err)
			}
		}
	}
}

// missionProjectionOf is the World's view of a mission as the graph's Mission
// node. It carries only what a MissionSnapshot knows: the fields it leaves
// empty (objective, the definition source, the start time) are the ones only
// the create RPC and the run bootstrap know, and the upsert keeps whatever they
// already stored.
func missionProjectionOf(m brain.MissionSnapshot) MissionProjection {
	return MissionProjection{
		ID:          m.ID,
		Name:        m.Name,
		Description: m.Description,
		TargetID:    m.TargetID,
		Status:      string(m.Status),
		CreatedBy:   m.CreatedBy.Ref(),
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
