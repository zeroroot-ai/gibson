// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// The application-lifecycle projection (gibson#1656) follows the Host
// projection's rule: the label and every relationship type reach Neo4j as
// arguments, never as query text. These are the checks that need no database;
// that Neo4j then treats them as names is asserted in the integration file.

// upsertEntityCypherIsAConstant fails to COMPILE if the entity query stops
// being a compile-time constant, the same guard the Host query carries.
const upsertEntityCypherIsAConstant = upsertEntityCypher

// TestEntityLabelsAndEdgeTypesTravelAsParameters pins the mechanism.
func TestEntityLabelsAndEdgeTypesTravelAsParameters(t *testing.T) {
	t.Parallel()

	for _, want := range []string{"apoc.merge.node([$label]", "apoc.merge.relationship(n, e.type"} {
		if !strings.Contains(upsertEntityCypherIsAConstant, want) {
			t.Errorf("upsertEntityCypher does not call %s:\n%s", want, upsertEntityCypher)
		}
	}
	// No lifecycle label or edge type may appear as query text.
	for _, label := range []string{
		":Application", ":Repository", ":Image", ":Package", ":Deployment",
		":Vulnerability", ":MergeRequest", ":Pipeline", ":Control",
		":CONTAINS", ":BUILT_FROM", ":FIXED_BY",
	} {
		if strings.Contains(upsertEntityCypher, label) {
			t.Errorf("upsertEntityCypher writes %q as query text; it must be an argument:\n%s",
				label, upsertEntityCypher)
		}
	}
}

// TestEntityUpsertParams_CarriesLabelKeyAndEdges: the happy path, including
// that an edge is carried as (type, label, key) data.
func TestEntityUpsertParams_CarriesLabelKeyAndEdges(t *testing.T) {
	t.Parallel()

	params, err := entityUpsertParams(brain.EntitySnapshot{
		Label: "Image", Key: "sha256:abc", ScopeID: "scope-1",
		Props: map[string]string{"tag": "v1"},
		Edges: []brain.EntityEdge{
			{Type: "CONTAINS", TargetLabel: "Package", TargetKey: "pkg:npm/lodash@4.17.20"},
			{Type: "BUILT_FROM", TargetLabel: "Repository", TargetKey: "gitlab.com/examplebank/customer-portal"},
		},
	})
	if err != nil {
		t.Fatalf("entityUpsertParams: %v", err)
	}
	// Identity travels as a parameter MAP keyed by the label's own identity
	// property, so an entity write converges with that label's first-class
	// projection instead of creating a second node (gibson#1669). Image is a
	// lifecycle-owned label, so its property is `key`.
	if params["label"] != "Image" || params["scope"] != "scope-1" {
		t.Errorf("identity params wrong: %+v", params)
	}
	if ident, _ := params["ident"].(map[string]any); ident["key"] != "sha256:abc" {
		t.Errorf("ident = %+v, want {key: sha256:abc}", params["ident"])
	}
	if params["taxonomy_version"] != taxonomy.Version {
		t.Errorf("taxonomy_version = %v, want %d", params["taxonomy_version"], taxonomy.Version)
	}
	props, _ := params["props"].(map[string]any)
	if props["tag"] != "v1" {
		t.Errorf("props = %+v, want tag=v1", props)
	}
	edges, _ := params["edges"].([]map[string]any)
	if len(edges) != 2 {
		t.Fatalf("edges = %+v, want 2", edges)
	}
	if edges[0]["type"] != "CONTAINS" || edges[0]["label"] != "Package" {
		t.Errorf("first edge = %+v", edges[0])
	}
}

// TestEntityUpsertParams_RefusesWhatTheTaxonomyDoesNotAdmit: the projector is
// the last line before Neo4j and refuses on its own authority, even though the
// ingest already gated the same shape.
func TestEntityUpsertParams_RefusesWhatTheTaxonomyDoesNotAdmit(t *testing.T) {
	t.Parallel()

	if _, err := entityUpsertParams(brain.EntitySnapshot{Label: "Wharrgarbl", Key: "k"}); err == nil {
		t.Error("an out-of-taxonomy label must be refused, not projected")
	}
	if _, err := entityUpsertParams(brain.EntitySnapshot{Label: "Image", Key: ""}); err == nil {
		t.Error("an entity with no key has no identity to merge on and must be refused")
	}
}

// TestEntityUpsertParams_DropsUnadmittedEdges: a bad edge is dropped and the
// node still lands, so one malformed relationship never loses the entity.
func TestEntityUpsertParams_DropsUnadmittedEdges(t *testing.T) {
	t.Parallel()

	params, err := entityUpsertParams(brain.EntitySnapshot{
		Label: "Finding", Key: "f1",
		Edges: []brain.EntityEdge{
			{Type: "TOUCHES", TargetLabel: "Control", TargetKey: "PCI-6.3.1"},
			{Type: "NUDGES", TargetLabel: "Control", TargetKey: "PCI-6.3.1"},
			{Type: "TOUCHES", TargetLabel: "Wharrgarbl", TargetKey: "x"},
			{Type: "TOUCHES", TargetLabel: "Control", TargetKey: ""},
		},
	})
	if err != nil {
		t.Fatalf("entityUpsertParams: %v", err)
	}
	edges, _ := params["edges"].([]map[string]any)
	if len(edges) != 1 || edges[0]["type"] != "TOUCHES" {
		t.Fatalf("only the admitted edge may survive, got %+v", edges)
	}
}

// TestEntityUpsertParams_CannotRewriteIdentityThroughProps: the properties the
// query owns are dropped from the payload, so an emitter cannot move a node's
// identity or its bookkeeping.
func TestEntityUpsertParams_CannotRewriteIdentityThroughProps(t *testing.T) {
	t.Parallel()

	params, err := entityUpsertParams(brain.EntitySnapshot{
		Label: "Application", Key: "customer-portal",
		Props: map[string]string{
			"key": "somewhere-else", "scope": "other-tenant",
			"taxonomy_version": "99", "updated_at": "0",
			"not a plain identifier": "dropped",
			"name":                   "Customer Portal",
		},
	})
	if err != nil {
		t.Fatalf("entityUpsertParams: %v", err)
	}
	props, _ := params["props"].(map[string]any)
	if len(props) != 1 || props["name"] != "Customer Portal" {
		t.Fatalf("reserved and unsafe property names must be dropped, got %+v", props)
	}
	if ident, _ := params["ident"].(map[string]any); ident["key"] != "customer-portal" {
		t.Errorf("identity came from the payload: %v", params["ident"])
	}
}

// TestFindingUpsertParams_StatusAndVulnerability: status is never empty on a
// projected node, and the vulnerability id drives the INSTANCE_OF merge.
func TestFindingUpsertParams_StatusAndVulnerability(t *testing.T) {
	t.Parallel()

	p := findingUpsertParams(brain.FindingSnapshot{
		ID: "f1", Status: brain.FindingStatusVerified, VulnerabilityID: "CVE-2025-1234",
	})
	if p["status"] != brain.FindingStatusVerified || p["vulnerability_id"] != "CVE-2025-1234" {
		t.Errorf("params = %+v", p)
	}

	// A Finding with no status projects as open rather than as an empty string.
	for _, bad := range []string{"", "wharrgarbl"} {
		p := findingUpsertParams(brain.FindingSnapshot{ID: "f1", Status: bad})
		if p["status"] != brain.FindingStatusOpen {
			t.Errorf("status %q projected as %v, want open", bad, p["status"])
		}
	}
}

// TestFindingCypherMergesTheVulnerabilityByKey: the Vulnerability is merged by
// its id, which is what makes one CVE across four Applications one node; and
// the merge is skipped when there is no id.
func TestFindingCypherMergesTheVulnerabilityByKey(t *testing.T) {
	t.Parallel()

	for _, want := range []string{
		"MERGE (v:Vulnerability {key: $vulnerability_id})",
		"MERGE (f)-[:INSTANCE_OF]->(v)",
		"CASE WHEN $vulnerability_id = '' THEN [] ELSE [1] END",
	} {
		if !strings.Contains(upsertFindingCypher, want) {
			t.Errorf("upsertFindingCypher is missing %q:\n%s", want, upsertFindingCypher)
		}
	}
	if !strings.Contains(upsertFindingCypher, "f.status = $status") {
		t.Errorf("upsertFindingCypher must SET status on every pass so a change lands in place:\n%s",
			upsertFindingCypher)
	}
}

// TestProjectedVocabularyCoversTheLifecycle: every lifecycle label and edge the
// writer can emit is declared, so the drift guard at wiring time is meaningful
// rather than vacuous.
func TestProjectedVocabularyCoversTheLifecycle(t *testing.T) {
	t.Parallel()

	have := map[string]bool{}
	for _, l := range projectedNodeLabels {
		have[l] = true
	}
	for _, r := range projectedRelationshipTypes {
		have[r] = true
	}
	for _, want := range []string{
		"Application", "Repository", "Image", "Package", "Deployment",
		"Vulnerability", "MergeRequest", "Pipeline", "Control",
		"HAS_REPOSITORY", "BUILT_FROM", "CONTAINS", "HAS_DEPLOYMENT", "RUNS",
		"EXPOSES", "INSTANCE_OF", "FIXED_BY", "VERIFIED_BY", "MERGED_INTO", "TOUCHES",
	} {
		if !have[want] {
			t.Errorf("%q is in the Taxonomy but the projector does not declare it", want)
		}
	}
	if drift := checkProjectedVocabulary(); len(drift) > 0 {
		t.Errorf("projected vocabulary drifted from the Taxonomy: %v", drift)
	}
}

// TestFindingUpsertParams_CarriesTheTerminalStatusAsAParameter: the Cypher
// decides whether to stamp verified_at by comparing $status to $verified_status,
// so the definition of "verified" stays in brain.FindingStatusVerified and the
// query stays a constant (gibson#1671).
func TestFindingUpsertParams_CarriesTheTerminalStatusAsAParameter(t *testing.T) {
	t.Parallel()

	p := findingUpsertParams(brain.FindingSnapshot{ID: "f1"})
	if p["verified_status"] != brain.FindingStatusVerified {
		t.Errorf("verified_status = %v, want %q", p["verified_status"], brain.FindingStatusVerified)
	}

	// It is the same value whatever the Finding's own status is: the parameter
	// names the terminal status, it does not report this Finding's.
	for _, s := range []string{brain.FindingStatusOpen, brain.FindingStatusFixed, brain.FindingStatusVerified} {
		p := findingUpsertParams(brain.FindingSnapshot{ID: "f1", Status: s})
		if p["verified_status"] != brain.FindingStatusVerified {
			t.Errorf("status %q gave verified_status %v", s, p["verified_status"])
		}
	}
}
