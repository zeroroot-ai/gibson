// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package ingest folds a tool's DiscoveryResult (proto field 100) into the
// per-tenant ECS brain World.
//
// It does not touch Neo4j. The World is the source of truth and the graph
// projector is the graph's only writer (ADR-0007, ADR-0012); an ingest path that
// wrote nodes itself would be a second writer, which is the thing the
// `graphwrite` analyzer exists to prevent. So the shape here is: proto in,
// Timeline events out, projector materializes.
//
// This replaces `graphrag/loader`, which built Cypher with fmt.Sprintf from
// agent-supplied labels, relationship types and property names. The loader was
// never constructed in production but was imported by seven production files,
// so it would have armed itself the day anyone wired it (gibson#1266).
package ingest

import (
	"context"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

// DiscoveryProcessor folds a discovery result into a tenant's World.
//
// Best-effort by contract: an unusable payload is reported in the result, not
// returned as an error, because the caller is a tool-dispatch path that has
// already answered its own caller by the time this runs.
type DiscoveryProcessor interface {
	// Process translates the discovery into brain events and submits them.
	// It returns statistics; it returns an error only when the processor itself
	// is unusable.
	Process(ctx context.Context, execCtx ExecContext, discovery *graphragpb.DiscoveryResult) (*ProcessResult, error)
}

// WorldSink submits one brain Timeline event to a tenant's World engine.
//
// tenant is the resolved owning tenant, or "" when the dispatch path did not
// carry one — the sink decides what to do with that, exactly as the Observe
// RPC's sink does, so tenancy policy stays in the daemon where the registry
// tenant is known.
type WorldSink func(tenant string, ev brain.Event)

// ProcessResult reports what one Process call did.
type ProcessResult struct {
	// EventsSubmitted is the number of Timeline events handed to the World.
	// It is not a node count: whether an event creates or enriches an entity is
	// the reducer's decision, and whether that reaches Neo4j is the projector's.
	EventsSubmitted int

	// Skipped is the number of discovered entities with no World vocabulary —
	// evidence, custom nodes, explicit relationships, and children whose parent
	// id names nothing in the payload. Non-zero is worth logging: it is data the
	// agent sent that nothing will store until the Observations fallback exists
	// (ADR-0012, gibson#1258).
	Skipped int

	// Errors holds non-fatal problems encountered while processing.
	Errors []error

	// Duration is the wall time spent in Process.
	Duration time.Duration
}

// HasErrors reports whether any error was recorded.
func (r *ProcessResult) HasErrors() bool { return len(r.Errors) > 0 }

// AddError records a non-fatal error and returns the result for chaining.
func (r *ProcessResult) AddError(err error) *ProcessResult {
	r.Errors = append(r.Errors, err)
	return r
}

// discoveryProcessor is the World-backed implementation.
type discoveryProcessor struct {
	sink   WorldSink
	logger *slog.Logger
}

// NewDiscoveryProcessor returns a processor that submits discovered entities to
// sink. A nil sink yields a processor that reports every call as an error rather
// than silently dropping discoveries — "wired to nothing" is the failure mode
// this whole change exists to remove, so it must not look like success.
func NewDiscoveryProcessor(sink WorldSink, logger *slog.Logger) DiscoveryProcessor {
	if logger == nil {
		logger = slog.Default()
	}
	return &discoveryProcessor{sink: sink, logger: logger}
}

// Process implements DiscoveryProcessor.
func (p *discoveryProcessor) Process(
	ctx context.Context,
	execCtx ExecContext,
	discovery *graphragpb.DiscoveryResult,
) (*ProcessResult, error) {
	start := time.Now()
	result := &ProcessResult{}
	if discovery == nil {
		return result, nil
	}

	nodeCount := countProtoNodes(discovery)
	if nodeCount == 0 {
		p.logger.DebugContext(ctx, "discovery result is empty; nothing to ingest")
		return result, nil
	}

	events, skipped := discoveryEvents(execCtx, discovery)
	result.Skipped = skipped

	if p.sink == nil {
		return result, errNoWorldSink
	}

	tenant := ""
	if !execCtx.TenantID.IsZero() {
		tenant = execCtx.TenantID.String()
	}

	for _, ev := range events {
		p.sink(tenant, ev)
	}
	result.EventsSubmitted = len(events)
	result.Duration = time.Since(start)

	p.logger.InfoContext(ctx, "discovery result folded into the World",
		"node_count", nodeCount,
		"events_submitted", result.EventsSubmitted,
		"skipped", result.Skipped,
		"tenant", tenant,
		"mission_id", execCtx.MissionID,
		"mission_run_id", execCtx.MissionRunID,
		"agent_name", execCtx.AgentName,
		"agent_run_id", execCtx.AgentRunID,
		"tool_execution_id", execCtx.ToolExecutionID,
		"duration_ms", result.Duration.Milliseconds(),
	)
	return result, nil
}

// countProtoNodes returns the number of discovered entities in the result.
func countProtoNodes(discovery *graphragpb.DiscoveryResult) int {
	if discovery == nil {
		return 0
	}
	return len(discovery.Hosts) +
		len(discovery.Ports) +
		len(discovery.Services) +
		len(discovery.Endpoints) +
		len(discovery.Domains) +
		len(discovery.Subdomains) +
		len(discovery.Technologies) +
		len(discovery.Certificates) +
		len(discovery.Findings) +
		len(discovery.Evidence) +
		len(discovery.CustomNodes)
}
