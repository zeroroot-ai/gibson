// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import "github.com/zeroroot-ai/sdk/auth"

// ExecContext is the provenance envelope that travels with a DiscoveryResult
// from the dispatch path that produced it to the World that folds it.
//
// It used to live in `internal/engine/graphrag/loader`, which string-built
// Cypher from tool output. The loader is gone (ADR-0012 step 8, gibson#1266);
// this type outlived it because seven production files pass it around and none
// of them ever wanted a Cypher builder — they wanted somewhere to put the
// mission/agent identifiers.
type ExecContext struct {
	// MissionRunID is the id of the current mission run. On the component path
	// it is the work-item id, which is why it is not usable as a World Scope:
	// scoping hosts by work item would fragment one host into one entity per
	// task that saw it.
	MissionRunID string

	// MissionID is the mission that owns this run. It is the World Scope for
	// every entity folded out of the discovery (ADR-0002: identity is
	// scope-relative). Empty means tenant-ambient — see the note on
	// DiscoveryProcessor about gibson#1256.
	MissionID string

	// AgentName is the agent that produced the discovery, carried for logging.
	AgentName string

	// AgentRunID is the agent run that produced the discovery.
	AgentRunID string

	// ToolExecutionID is the tool execution that produced the discovery
	// (optional).
	ToolExecutionID string

	// TenantID is the owning tenant. It selects the per-tenant World the events
	// are submitted to. Zero means "tenant not resolved here" and the ingest
	// sink falls back to the daemon's registry tenant, matching how the Observe
	// RPC's sink resolves tenancy on the same callback path.
	TenantID auth.TenantID
}
