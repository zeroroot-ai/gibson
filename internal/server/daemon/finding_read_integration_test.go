// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build integration

package daemon

import (
	"context"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestProjectedFindingReadsBackByIdAndByTitle (gibson#210) runs the production
// projector Cypher against a real Neo4j and reads the node back through the
// production dashboard query, the way ComponentService.GetFindings and
// GraphService.GetFindings do. The unit test next door proves the two sides
// name the same properties. This one proves the server returns the finding
// for a search by its title, with the id the daemon handed the submitter.
func TestProjectedFindingReadsBackByIdAndByTitle(t *testing.T) {
	ctx := context.Background()
	drv := startProvisionedNeo4j(t, ctx)

	snapshot := brain.FindingSnapshot{
		ID:          "299176b7-0306-4ecb-9948-95d4bd0e0beb",
		Title:       "Exposed admin panel",
		Description: "no auth on /admin",
		Severity:    "info",
	}
	runWrite(t, ctx, drv, upsertFindingCypher, findingUpsertParams(snapshot))

	sess := drv.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer func() { _ = sess.Close(ctx) }()
	q := graph.NewDashboardQueries(graph.NewSessionGraphClient(sess))

	tenant, err := auth.NewTenantID("tenant-finding-read")
	if err != nil {
		t.Fatal(err)
	}
	records, total, err := q.Findings(ctx, tenant, graph.FindingsFilters{Search: snapshot.Title})
	if err != nil {
		t.Fatalf("Findings(search=title): %v", err)
	}
	if total != 1 || len(records) != 1 {
		t.Fatalf("Findings(search=title) returned %d records (total %d), want 1", len(records), total)
	}
	if records[0].ID != snapshot.ID {
		t.Errorf("record ID = %q, want %q", records[0].ID, snapshot.ID)
	}
	if records[0].Name != snapshot.Title {
		t.Errorf("record Name = %q, want %q", records[0].Name, snapshot.Title)
	}

	// A search that matches nothing stays empty, so the title predicate is a
	// filter and not a pass-through.
	none, _, err := q.Findings(ctx, tenant, graph.FindingsFilters{Search: "no such finding"})
	if err != nil {
		t.Fatalf("Findings(search=miss): %v", err)
	}
	if len(none) != 0 {
		t.Errorf("Findings(search=miss) returned %d records, want 0", len(none))
	}
}
