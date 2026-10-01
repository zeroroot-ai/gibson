// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package taxonomy

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testBase(t *testing.T) *Registry {
	t.Helper()
	r, err := New(1, []string{ObservationLabel, "Host"}, []string{"HAS_PORT"})
	require.NoError(t, err)
	return r
}

// -----------------------------------------------------------------------
// Acceptance: a proposed label is held as data until promoted (criterion 1).
// -----------------------------------------------------------------------

func TestPromotionGate_ObserveHoldsAsDataNeverPromotes(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	count := gate.Observe(ProposedNodeLabel, "Container")
	assert.Equal(t, 1, count)

	// Merely observing never promotes, no matter the label.
	decision := gate.Base().ClassifyNode("Container")
	assert.False(t, decision.InTaxonomy)
	assert.Equal(t, ObservationLabel, decision.Label)
}

func TestPromotionGate_ObserveAcceptsAnyStringIncludingUnsafeOnes(t *testing.T) {
	// Recording a sighting is data, never Cypher structure, so Observe must
	// never itself reject anything — only Promote enforces safety.
	base := testBase(t)
	gate := NewPromotionGate(base)

	count := gate.Observe(ProposedNodeLabel, "Evil`; DETACH DELETE n; //")
	assert.Equal(t, 1, count)
}

func TestPromotionGate_ObserveIsRecurrenceCounted(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	assert.Equal(t, 1, gate.Observe(ProposedNodeLabel, "Container"))
	assert.Equal(t, 2, gate.Observe(ProposedNodeLabel, "Container"))
	assert.Equal(t, 3, gate.Observe(ProposedNodeLabel, "Container"))
	// A different kind or label has an independent count.
	assert.Equal(t, 1, gate.Observe(ProposedRelationshipType, "Container"))
	assert.Equal(t, 1, gate.Observe(ProposedNodeLabel, "Other"))
}

// -----------------------------------------------------------------------
// Acceptance: promotion requires ValidIdentifier pass + settlement
// (recurrence + HITL) (criterion 2).
// -----------------------------------------------------------------------

func TestPromotionGate_PromoteFailsBelowRecurrenceThreshold(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	for range MinRecurrenceForSettlement - 1 {
		gate.Observe(ProposedNodeLabel, "Container")
	}
	require.NoError(t, gate.Confirm(ProposedNodeLabel, "Container", "reviewer-1"))

	reg, err := gate.Promote(ProposedNodeLabel, "Container")
	require.Error(t, err)
	assert.Nil(t, reg)
}

func TestPromotionGate_PromoteFailsWithoutConfirmation(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	for range MinRecurrenceForSettlement {
		gate.Observe(ProposedNodeLabel, "Container")
	}

	reg, err := gate.Promote(ProposedNodeLabel, "Container")
	require.Error(t, err)
	assert.Nil(t, reg)
}

func TestPromotionGate_PromoteSucceedsWhenSettled(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	for range MinRecurrenceForSettlement {
		gate.Observe(ProposedNodeLabel, "Container")
	}
	require.NoError(t, gate.Confirm(ProposedNodeLabel, "Container", "reviewer-1"))

	reg, err := gate.Promote(ProposedNodeLabel, "Container")
	require.NoError(t, err)
	require.NotNil(t, reg)
	assert.Equal(t, base.Version()+1, reg.Version())

	decision := reg.ClassifyNode("Container")
	assert.True(t, decision.InTaxonomy)
	assert.Equal(t, "Container", decision.Label)

	// The gate's own Base() reflects the promotion for any further Promote.
	assert.Equal(t, reg.Version(), gate.Base().Version())
}

func TestPromotionGate_PromoteRelationshipType(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	for range MinRecurrenceForSettlement {
		gate.Observe(ProposedRelationshipType, "MANAGES")
	}
	require.NoError(t, gate.Confirm(ProposedRelationshipType, "MANAGES", "reviewer-1"))

	reg, err := gate.Promote(ProposedRelationshipType, "MANAGES")
	require.NoError(t, err)
	decision := reg.ClassifyRelationship("MANAGES")
	assert.True(t, decision.InTaxonomy)
}

// -----------------------------------------------------------------------
// Acceptance: a planted unsafe/backtick label is refused and never reaches
// Cypher — the required failing fixture (criterion 3). This test documents
// and proves the safety gate: it fails RED if either Confirm or Promote is
// ever changed to let an invalid identifier through settlement.
// -----------------------------------------------------------------------

func TestPromotionGate_PlantedUnsafeLabelIsNeverPromoted(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	const unsafeLabel = "Evil`; DETACH DELETE n; //"

	// The planted label recurs past the settlement threshold freely —
	// Observe never rejects anything, because recording a sighting is data,
	// never Cypher structure (ADR-0024 §2).
	for range MinRecurrenceForSettlement {
		gate.Observe(ProposedNodeLabel, unsafeLabel)
	}

	// A careless or compromised reviewer tries to confirm it. Refused before
	// the confirmation is even recorded: a human cannot approve past the
	// automated ValidIdentifier check.
	err := gate.Confirm(ProposedNodeLabel, unsafeLabel, "careless-reviewer")
	require.Error(t, err)
	var invalidErr *InvalidProposalError
	require.ErrorAs(t, err, &invalidErr)

	// Even a direct Promote call — as if settlement had somehow been
	// satisfied — is refused independently.
	reg, err := gate.Promote(ProposedNodeLabel, unsafeLabel)
	require.Error(t, err)
	require.ErrorAs(t, err, &invalidErr)
	assert.Nil(t, reg)

	// The unsafe label never reaches the Taxonomy: it still falls back to
	// Observation, exactly as an untouched Registry would classify it.
	decision := gate.Base().ClassifyNode(unsafeLabel)
	assert.False(t, decision.InTaxonomy)
	assert.Equal(t, ObservationLabel, decision.Label)
	assert.Equal(t, base.Version(), gate.Base().Version())
}

func TestPromotionGate_PlantedUnsafeRelationshipTypeIsNeverPromoted(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	const unsafeRel = "OWNS`}]->(n) DETACH DELETE n //"

	for range MinRecurrenceForSettlement {
		gate.Observe(ProposedRelationshipType, unsafeRel)
	}
	err := gate.Confirm(ProposedRelationshipType, unsafeRel, "careless-reviewer")
	require.Error(t, err)

	reg, err := gate.Promote(ProposedRelationshipType, unsafeRel)
	require.Error(t, err)
	assert.Nil(t, reg)
}

// -----------------------------------------------------------------------
// Acceptance: promotion is recorded and replayable (criterion 4).
// -----------------------------------------------------------------------

func TestPromotionGate_PromotionsAreRecorded(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	for range MinRecurrenceForSettlement {
		gate.Observe(ProposedNodeLabel, "Container")
	}
	require.NoError(t, gate.Confirm(ProposedNodeLabel, "Container", "reviewer-1"))
	reg, err := gate.Promote(ProposedNodeLabel, "Container")
	require.NoError(t, err)

	records := gate.Promotions()
	require.Len(t, records, 1)
	assert.Equal(t, ProposedNodeLabel, records[0].Kind)
	assert.Equal(t, "Container", records[0].Label)
	assert.Equal(t, reg.Version(), records[0].Version)
}

func TestPromotionGate_ReplayIsDeterministic(t *testing.T) {
	base := testBase(t)

	apply := func(g *PromotionGate) {
		for range MinRecurrenceForSettlement {
			g.Observe(ProposedNodeLabel, "Container")
		}
		_ = g.Confirm(ProposedNodeLabel, "Container", "reviewer-1")
		_, _ = g.Promote(ProposedNodeLabel, "Container")

		for range MinRecurrenceForSettlement {
			g.Observe(ProposedRelationshipType, "MANAGES")
		}
		_ = g.Confirm(ProposedRelationshipType, "MANAGES", "reviewer-2")
		_, _ = g.Promote(ProposedRelationshipType, "MANAGES")
	}

	g1 := NewPromotionGate(base)
	apply(g1)

	g2 := NewPromotionGate(base)
	apply(g2)

	assert.Equal(t, g1.Base().NodeLabels(), g2.Base().NodeLabels())
	assert.Equal(t, g1.Base().RelationshipTypes(), g2.Base().RelationshipTypes())
	assert.Equal(t, g1.Base().Version(), g2.Base().Version())
	assert.Equal(t, g1.Promotions(), g2.Promotions())
}

func TestPromotionGate_PromotingAnAlreadyPromotedLabelFails(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	for range MinRecurrenceForSettlement {
		gate.Observe(ProposedNodeLabel, "Host")
	}
	require.NoError(t, gate.Confirm(ProposedNodeLabel, "Host", "reviewer-1"))

	reg, err := gate.Promote(ProposedNodeLabel, "Host")
	require.Error(t, err)
	assert.Nil(t, reg)
}

// -----------------------------------------------------------------------
// ProposalKind.String, InvalidProposalError.Error/Unwrap, and
// NotSettledError.Error were 0%-covered: every earlier test triggers these
// errors but only checks require.Error(err)/errors.As, never calls
// Error()/Unwrap() directly. Exercise the rendering and unwrapping
// explicitly.
// -----------------------------------------------------------------------

func TestProposalKind_String(t *testing.T) {
	assert.Equal(t, "node_label", ProposedNodeLabel.String())
	assert.Equal(t, "relationship_type", ProposedRelationshipType.String())
	assert.Equal(t, "unknown", ProposalKind(99).String())
}

func TestInvalidProposalError_ErrorAndUnwrap(t *testing.T) {
	wrapped := errors.New("boom")
	err := &InvalidProposalError{Kind: ProposedRelationshipType, Label: "Bad`Label", Err: wrapped}

	msg := err.Error()
	assert.Contains(t, msg, "relationship_type")
	assert.Contains(t, msg, "Bad`Label")
	assert.Contains(t, msg, "boom")
	assert.Same(t, wrapped, err.Unwrap())
	assert.Same(t, wrapped, errors.Unwrap(err))
}

func TestNotSettledError_Error(t *testing.T) {
	err := &NotSettledError{Kind: ProposedNodeLabel, Label: "Container", Recurrence: 1, Confirmed: false}

	msg := err.Error()
	assert.Contains(t, msg, "node_label")
	assert.Contains(t, msg, "Container")
	assert.Contains(t, msg, "recurrence=1")
	assert.Contains(t, msg, "confirmed=false")
}

// -----------------------------------------------------------------------
// promotedRegistry's default case (an unrecognised ProposalKind) was
// 0%-covered: every earlier test uses one of the two defined constants.
// Drive it through the real public path (Observe/Confirm/Promote) rather
// than calling the unexported helper directly, so this also documents what
// Promote actually does if a future ProposalKind value is added without a
// matching case in promotedRegistry's switch.
// -----------------------------------------------------------------------

func TestPromotionGate_PromoteRejectsUnrecognisedProposalKind(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)
	unknownKind := ProposalKind(99)

	for range MinRecurrenceForSettlement {
		gate.Observe(unknownKind, "Something")
	}
	require.NoError(t, gate.Confirm(unknownKind, "Something", "reviewer-1"))

	reg, err := gate.Promote(unknownKind, "Something")
	require.Error(t, err)
	assert.Nil(t, reg)
	assert.Contains(t, err.Error(), "unknown proposal kind")
}

// -----------------------------------------------------------------------
// Key form at promotion (gibson#484): every runtime-promoted label must carry
// a written key form, assigned and recorded by the gate. A node label gets a
// collision-proof identity property (brain_id, unique by construction); a
// relationship type is an edge and carries no node identity (accounted for as
// not-applicable). Nothing is ever promoted with an unwritten key, which is
// what lets two producers of one label merge on the same node instead of
// splitting it (gibson#1669) and keeps the per-label uniqueness constraint
// (charts/hosted#486) satisfied.
// -----------------------------------------------------------------------

func TestPromotionGate_EveryPromotedLabelCarriesAnAccountedForKeyForm(t *testing.T) {
	base := testBase(t)
	gate := NewPromotionGate(base)

	for range MinRecurrenceForSettlement {
		gate.Observe(ProposedNodeLabel, "Container")
	}
	require.NoError(t, gate.Confirm(ProposedNodeLabel, "Container", "reviewer-1"))
	_, err := gate.Promote(ProposedNodeLabel, "Container")
	require.NoError(t, err)

	for range MinRecurrenceForSettlement {
		gate.Observe(ProposedRelationshipType, "MANAGES")
	}
	require.NoError(t, gate.Confirm(ProposedRelationshipType, "MANAGES", "reviewer-2"))
	_, err = gate.Promote(ProposedRelationshipType, "MANAGES")
	require.NoError(t, err)

	records := gate.Promotions()
	require.Len(t, records, 2)
	for _, rec := range records {
		switch rec.Kind {
		case ProposedNodeLabel:
			// A node label carries a written key form: non-empty, a valid
			// identifier, unique by construction, never the collision-prone
			// generic "key" default the projector falls back to.
			require.Equal(t, DiscoveredNodeIdentityProperty, rec.IdentityProperty, "node label %q", rec.Label)
			require.NotEmpty(t, rec.IdentityProperty)
			require.NotEqual(t, "key", rec.IdentityProperty)
			require.NoError(t, ValidIdentifier(rec.IdentityProperty))
		case ProposedRelationshipType:
			require.Empty(t, rec.IdentityProperty, "relationship type %q carries no node identity", rec.Label)
		default:
			t.Fatalf("unexpected proposal kind %v", rec.Kind)
		}
	}
}

// PromotedIdentityProperty accounts for every kind in the closed ProposalKind
// vocabulary: a node label gets the unique-by-construction key form, a
// relationship type gets the not-applicable (empty) form. This is the fixture
// gibson#484 requires: a label that reached promotion with no written key form
// would fail here, because PromotedIdentityProperty would hand back an unsafe
// empty string for a node label.
func TestPromotedIdentityProperty_AccountsForEveryKind(t *testing.T) {
	// Node labels: a real, collision-proof key form.
	nodeKey := PromotedIdentityProperty(ProposedNodeLabel)
	require.NotEmpty(t, nodeKey, "a promoted node label must carry a written key form")
	require.NotEqual(t, "key", nodeKey, "the generic key default is collision-prone and forbidden (gibson#484)")
	require.NoError(t, ValidIdentifier(nodeKey), "the key form must itself be a safe identifier")
	require.Equal(t, DiscoveredNodeIdentityProperty, nodeKey)

	// Relationship types are edges: no node identity, accounted for as empty.
	require.Empty(t, PromotedIdentityProperty(ProposedRelationshipType))
}
