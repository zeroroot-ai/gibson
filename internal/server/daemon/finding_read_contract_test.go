// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// finding_read_contract_test.go holds the projector/reader pair test for the
// :Finding property contract (gibson#210).
//
// The graph projector is the sole writer of :Finding nodes (ADR-0007) and the
// dashboard reader (graph.DashboardQueries.Findings) is what every finding read
// runs: ComponentService.GetFindings, GraphService.GetFindings and the export.
// The two met only in a live Neo4j, and they disagreed: the projector merged on
// brain_id and wrote title, the reader mapped id and name. A finding an enrolled
// agent submitted came back with a Neo4j internal id and no name, so a read by
// the id the daemon returned found nothing.
//
// This test derives the properties the projector writes from the production
// Cypher and the production parameter builder, hands them to the production
// reader mapping, and asserts the record carries the World's id and title.

import (
	"regexp"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j/dbtype"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
)

var (
	// findingMergeKey matches the MERGE that gives a :Finding its identity.
	findingMergeKey = regexp.MustCompile(`MERGE \(f:Finding \{(\w+): \$(\w+)\}\)`)
	// findingSetProp matches every `f.<prop> = $<param>` assignment.
	findingSetProp = regexp.MustCompile(`f\.(\w+) = \$(\w+)`)
	// vulnerabilityMergeKey matches the MERGE that gives a :Vulnerability its identity.
	vulnerabilityMergeKey = regexp.MustCompile(`MERGE \(v:Vulnerability \{(\w+): \$(\w+)\}\)`)
)

// projectedFindingNode builds the node upsertFindingCypher leaves in the graph
// for f, from the Cypher text and the parameter set the projector issues.
func projectedFindingNode(t *testing.T, f brain.FindingSnapshot) dbtype.Node {
	t.Helper()

	params := findingUpsertParams(f)
	props := map[string]any{}

	key := findingMergeKey.FindStringSubmatch(upsertFindingCypher)
	if key == nil {
		t.Fatalf("upsertFindingCypher has no MERGE (f:Finding {<prop>: $<param>}):\n%s", upsertFindingCypher)
	}
	props[key[1]] = params[key[2]]

	for _, m := range findingSetProp.FindAllStringSubmatch(upsertFindingCypher, -1) {
		v, ok := params[m[2]]
		if !ok {
			t.Fatalf("upsertFindingCypher sets f.%s from $%s, which findingUpsertParams does not supply", m[1], m[2])
		}
		props[m[1]] = v
	}

	// The Neo4j internal id is deliberately unrelated to the World id, so a
	// reader that falls back to it is caught.
	return dbtype.Node{Id: 424242, Labels: []string{"Finding"}, Props: props}
}

// TestFindingReaderReadsWhatTheProjectorWrites: a FindingRaised the projector
// materialised reads back through the dashboard mapping with the daemon's
// finding id and the finding's title.
func TestFindingReaderReadsWhatTheProjectorWrites(t *testing.T) {
	t.Parallel()

	snapshot := brain.FindingSnapshot{
		ID:          "299176b7-0306-4ecb-9948-95d4bd0e0beb",
		Title:       "Exposed admin panel",
		Description: "no auth on /admin",
		Severity:    "info",
	}

	rec := graph.FindingRecordFromNode(projectedFindingNode(t, snapshot))

	if rec.ID != snapshot.ID {
		t.Errorf("record ID = %q, want the id the daemon returned %q", rec.ID, snapshot.ID)
	}
	if rec.Name != snapshot.Title {
		t.Errorf("record Name = %q, want the title %q", rec.Name, snapshot.Title)
	}
	if rec.Severity != snapshot.Severity {
		t.Errorf("record Severity = %q, want %q", rec.Severity, snapshot.Severity)
	}
	if rec.Description != snapshot.Description {
		t.Errorf("record Description = %q, want %q", rec.Description, snapshot.Description)
	}
}

// TestFindingPropertyContractIsShared: the reader's named properties are the
// ones the projector merges on and writes, so a rename on either side fails
// here rather than in a tenant's graph.
func TestFindingPropertyContractIsShared(t *testing.T) {
	t.Parallel()

	key := findingMergeKey.FindStringSubmatch(upsertFindingCypher)
	if key == nil {
		t.Fatalf("upsertFindingCypher has no MERGE (f:Finding {<prop>: $<param>}):\n%s", upsertFindingCypher)
	}
	if key[1] != graph.FindingIDProperty {
		t.Errorf("projector merges a :Finding on %q, reader maps %q", key[1], graph.FindingIDProperty)
	}

	written := map[string]bool{}
	for _, m := range findingSetProp.FindAllStringSubmatch(upsertFindingCypher, -1) {
		written[m[1]] = true
	}
	if !written[graph.FindingTitleProperty] {
		t.Errorf("projector never writes f.%s, which the reader maps as the name:\n%s",
			graph.FindingTitleProperty, upsertFindingCypher)
	}

	vkey := vulnerabilityMergeKey.FindStringSubmatch(upsertFindingCypher)
	if vkey == nil {
		t.Fatalf("upsertFindingCypher has no MERGE (v:Vulnerability {<prop>: $<param>}):\n%s", upsertFindingCypher)
	}
	if vkey[1] != graph.VulnerabilityKeyProperty {
		t.Errorf("projector merges a :Vulnerability on %q, reader maps %q", vkey[1], graph.VulnerabilityKeyProperty)
	}
}
