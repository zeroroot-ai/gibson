// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ingest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
)

func entityEvents(t *testing.T, d *graphragpb.DiscoveryResult) (entities []brain.EntityObserved, skipped int) {
	t.Helper()
	events, skipped := discoveryEvents(ExecContext{MissionID: "m"}, d)
	for _, ev := range events {
		if e, ok := ev.(brain.EntityObserved); ok {
			entities = append(entities, e)
		}
	}
	return entities, skipped
}

// TestCustomNodeInTheTaxonomyBecomesATypedEntity: a custom node whose type is
// an admitted label is folded as that label, keyed by its identifying
// properties (gibson#1656).
func TestCustomNodeInTheTaxonomyBecomesATypedEntity(t *testing.T) {
	got, skipped := entityEvents(t, &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{{
			NodeType:     "Package",
			IdProperties: map[string]string{"purl": "pkg:npm/lodash@4.17.20"},
			Properties:   map[string]string{"ecosystem": "npm"},
		}},
	})
	require.Len(t, got, 1)
	assert.Zero(t, skipped)
	assert.Equal(t, "Package", got[0].Label)
	assert.Equal(t, "pkg:npm/lodash@4.17.20", got[0].Key,
		"one identifying property is the key verbatim, so a key is matchable across payloads")
	assert.Equal(t, map[string]string{"ecosystem": "npm"}, got[0].Props)
	assert.Equal(t, "m", got[0].MissionID)
}

// TestCustomNodeOutOfTheTaxonomyIsSkippedNotInvented: the Taxonomy is the gate.
// An unknown type is counted, never turned into a label of its own.
func TestCustomNodeOutOfTheTaxonomyIsSkippedNotInvented(t *testing.T) {
	got, skipped := entityEvents(t, &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{
			{NodeType: "Wharrgarbl", IdProperties: map[string]string{"id": "x"}},
			// Admitted label, but no identifying property: nothing to merge on.
			{NodeType: "Application", IdProperties: nil},
			{NodeType: "", IdProperties: map[string]string{"id": "y"}},
		},
	})
	assert.Empty(t, got)
	assert.Equal(t, 3, skipped, "everything unmappable is counted, never silently dropped")
}

// TestCustomNodeParentLinkNeedsEveryPartAdmitted: the parent edge travels only
// when the parent label, the relationship type and the parent key are all good.
func TestCustomNodeParentLinkNeedsEveryPartAdmitted(t *testing.T) {
	good, skipped := entityEvents(t, &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{{
			NodeType:         "Package",
			IdProperties:     map[string]string{"purl": "pkg:npm/lodash@4.17.20"},
			ParentType:       strp("Image"),
			ParentId:         map[string]string{"digest": "sha256:abc"},
			RelationshipType: strp("CONTAINS"),
		}},
	})
	require.Len(t, good, 1)
	assert.Zero(t, skipped)
	require.Len(t, good[0].Edges, 1)
	assert.Equal(t, brain.EntityEdge{
		Type: "CONTAINS", TargetLabel: "Image", TargetKey: "sha256:abc",
	}, good[0].Edges[0])

	// A parent edge naming an unknown relationship: the node still lands, the
	// edge does not, and the drop is counted.
	bad, badSkipped := entityEvents(t, &graphragpb.DiscoveryResult{
		CustomNodes: []*graphragpb.CustomNode{{
			NodeType:         "Package",
			IdProperties:     map[string]string{"purl": "pkg:npm/lodash@4.17.20"},
			ParentType:       strp("Image"),
			ParentId:         map[string]string{"digest": "sha256:abc"},
			RelationshipType: strp("SWALLOWED_BY"),
		}},
	})
	require.Len(t, bad, 1)
	assert.Empty(t, bad[0].Edges, "an out-of-taxonomy edge type is dropped, the node is not")
	assert.Equal(t, 1, badSkipped)
}

// TestExplicitRelationshipNeedsBothEndsAdmitted: an explicit edge travels only
// when its type and BOTH node labels are admitted. One bad end is enough to
// skip it, because a half-typed edge would name a node the Taxonomy cannot hold.
func TestExplicitRelationshipNeedsBothEndsAdmitted(t *testing.T) {
	got, skipped := entityEvents(t, &graphragpb.DiscoveryResult{
		ExplicitRelationships: []*graphragpb.ExplicitRelationship{
			{
				FromType: "Finding", FromId: map[string]string{"id": "f1"},
				ToType: "Control", ToId: map[string]string{"id": "PCI-6.3.1"},
				RelationshipType: "TOUCHES",
			},
			// Unknown relationship type.
			{
				FromType: "Finding", FromId: map[string]string{"id": "f1"},
				ToType: "Control", ToId: map[string]string{"id": "PCI-6.3.1"},
				RelationshipType: "NUDGES",
			},
			// Unknown target label.
			{
				FromType: "Finding", FromId: map[string]string{"id": "f1"},
				ToType: "Wharrgarbl", ToId: map[string]string{"id": "x"},
				RelationshipType: "TOUCHES",
			},
		},
	})
	require.Len(t, got, 1)
	assert.Equal(t, 2, skipped)
	assert.Equal(t, "Finding", got[0].Label)
	assert.Equal(t, "f1", got[0].Key)
	require.Len(t, got[0].Edges, 1)
	assert.Equal(t, brain.EntityEdge{
		Type: "TOUCHES", TargetLabel: "Control", TargetKey: "PCI-6.3.1",
	}, got[0].Edges[0])
}

// TestEntityKeyIsIndependentOfMapOrder: several identifying properties join in
// sorted form, so the same entity keys the same way on every delivery.
func TestEntityKeyIsIndependentOfMapOrder(t *testing.T) {
	a := EntityKey(map[string]string{"name": "lodash", "version": "4.17.20"})
	b := EntityKey(map[string]string{"version": "4.17.20", "name": "lodash"})
	assert.Equal(t, a, b)
	assert.Equal(t, "name=lodash|version=4.17.20", a)

	assert.Empty(t, EntityKey(nil), "no identifying property, no stable key")
	assert.Equal(t, "CVE-2025-1234", EntityKey(map[string]string{"id": " CVE-2025-1234 "}),
		"a single property is the key verbatim, trimmed")
}

// TestFindingCarriesItsVulnerabilityIdentity: the first CVE id is the shared
// identity the projector links INSTANCE_OF, so one CVE across two Applications
// is one Vulnerability node.
func TestFindingCarriesItsVulnerabilityIdentity(t *testing.T) {
	events, _ := discoveryEvents(ExecContext{MissionID: "m"}, &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{{
			Id: strp("f1"), Title: "vulnerable lodash", Severity: "high",
			CveIds: strp("CVE-2025-1234, CVE-2025-9999"),
		}},
	})
	require.Len(t, events, 1)
	f := events[0].(brain.FindingRaised)
	assert.Equal(t, "CVE-2025-1234", f.VulnerabilityID, "the first id is the identity")
	assert.Equal(t, brain.FindingStatusOpen, f.Status)
}

// TestFindingWithoutACveHasNoSharedIdentity: a source finding with no public id
// still raises, it just has nothing to share.
func TestFindingWithoutACveHasNoSharedIdentity(t *testing.T) {
	events, _ := discoveryEvents(ExecContext{MissionID: "m"}, &graphragpb.DiscoveryResult{
		Findings: []*graphragpb.Finding{{Id: strp("f1"), Title: "hardcoded secret", Severity: "high"}},
	})
	require.Len(t, events, 1)
	assert.Empty(t, events[0].(brain.FindingRaised).VulnerabilityID)
}
