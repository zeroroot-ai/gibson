// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"time"
)

// FindingRaised is the fact that an agent submitted a finding. The ID is the ID
// of the finding row in the Postgres database of the tenant. The daemon wires a
// FindingSink to fold this into the tenant World, so the graph projector writes
// a finding node with the same ID. The graph keeps the node for relations only.
// The fields and the evidence of the finding are in Postgres. Kept as a plain
// struct and callback so the harness stays decoupled from the brain package.
type FindingRaised struct {
	Tenant       string
	ID           string
	Title        string
	Description  string
	Severity     string
	ScopeID      string
	MissionID    string
	MissionRunID string
	AgentName    string
	// CheckRef is the mission that raised the finding. A rerun of that mission
	// is the check that verifies the fix (ADR-0178). The daemon sets the kind.
	CheckRef string
	// At is the time of the read. The harness sets it.
	At time.Time
}

// FindingSink folds a FindingRaised into the World. Optional. When nil, the
// harness raises no finding node.
type FindingSink func(ctx context.Context, f FindingRaised)
