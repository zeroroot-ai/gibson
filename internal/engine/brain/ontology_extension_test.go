// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// TestOntologyExtensionProposed_CodecRoundTrip proves OntologyExtensionProposed
// survives the durable Timeline's JSON envelope round trip (EncodeEvent/
// DecodeEvent) — required for durable persistence (ADR-0011) and for the
// codec's kind registry to stay complete, mirroring
// TestDomainPackEvents_CodecRoundTrip.
func TestOntologyExtensionProposed_CodecRoundTrip(t *testing.T) {
	ev := OntologyExtensionProposed{
		ProposalKind: taxonomy.ProposedRelationshipType,
		Label:        "RUNS_ON",
		Proposer:     "agent-1",
		Claim:        "sighted an edge worth naming",
	}
	b, err := EncodeEvent(ev)
	require.NoError(t, err)
	decoded, err := DecodeEvent(b)
	require.NoError(t, err)
	assert.True(t, reflect.DeepEqual(decoded, Event(ev)), "round trip: got %#v (%T), want %#v", decoded, decoded, ev)
}

// TestOntologyExtensionProposed_ReplayReproducesTheWorld is the core
// gibson#391 determinism unit: World == fold(Timeline) for proposal
// recurrence, mirroring TestDomainPack_EnableDisable_ReplayReproducesTheWorld.
func TestOntologyExtensionProposed_ReplayReproducesTheWorld(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("tenant-1")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-1", Claim: "sighted a container node"})
	apply(OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-2", Claim: "sighted it again"})
	apply(OntologyExtensionProposed{ProposalKind: taxonomy.ProposedRelationshipType, Label: "RUNS_ON", Proposer: "agent-1", Claim: "sighted an edge"})

	want := w.OntologyProposalSnapshot()
	require.Len(t, want, 2)

	replayed := Replay("tenant-1", tl)
	assert.Equal(t, want, replayed.OntologyProposalSnapshot())
}

// TestOntologyExtensionProposed_RecurrenceIsCounted proves PromotionGate.
// Observe's recurrence counting is wired end to end: the SAME (kind, label)
// sighted three times reports recurrence 3, and DIFFERENT labels never share
// a counter.
func TestOntologyExtensionProposed_RecurrenceIsCounted(t *testing.T) {
	w := NewWorld("tenant-1")

	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-1", Claim: "one"})
	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-2", Claim: "two"})
	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-3", Claim: "three"})
	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Sidecar", Proposer: "agent-1", Claim: "unrelated"})

	snapshot := w.OntologyProposalSnapshot()
	require.Len(t, snapshot, 2)

	byLabel := make(map[string]OntologyProposalSnapshot, len(snapshot))
	for _, s := range snapshot {
		byLabel[s.Label] = s
	}

	require.Contains(t, byLabel, "Container")
	assert.Equal(t, 3, byLabel["Container"].Recurrence)
	assert.Equal(t, "agent-3", byLabel["Container"].LastProposer)
	assert.Equal(t, "three", byLabel["Container"].LastClaim)

	require.Contains(t, byLabel, "Sidecar")
	assert.Equal(t, 1, byLabel["Sidecar"].Recurrence)
}

// TestOntologyExtensionProposed_NodeLabelAndRelationshipTypeAreDistinctCounters
// proves the two ProposalKind vocabularies never share a recurrence counter,
// even for the identical label text (taxonomy's own proposalKey includes
// kind).
func TestOntologyExtensionProposed_NodeLabelAndRelationshipTypeAreDistinctCounters(t *testing.T) {
	w := NewWorld("tenant-1")

	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Runs", Proposer: "agent-1", Claim: "as a node label"})
	Reduce(w, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedRelationshipType, Label: "Runs", Proposer: "agent-1", Claim: "as a relationship type"})

	snapshot := w.OntologyProposalSnapshot()
	require.Len(t, snapshot, 2)
	for _, s := range snapshot {
		assert.Equal(t, 1, s.Recurrence, "each kind's first sighting of %q must count separately", s.Label)
	}
}

// TestOntologyExtensionProposed_IsPerTenant proves proposal recurrence is
// structurally per-tenant (ADR-0033 decision 1): proposing in one tenant's
// World never affects another's, mirroring TestDomainPack_Enable_IsPerTenant.
func TestOntologyExtensionProposed_IsPerTenant(t *testing.T) {
	acme := NewWorld("acme")
	other := NewWorld("other")

	Reduce(acme, OntologyExtensionProposed{ProposalKind: taxonomy.ProposedNodeLabel, Label: "Container", Proposer: "agent-1", Claim: "acme sighting"})

	assert.Len(t, acme.OntologyProposalSnapshot(), 1)
	assert.Empty(t, other.OntologyProposalSnapshot())
}

// -----------------------------------------------------------------------
// Engine.ProposeOntologyExtension: the ValidIdentifier safety gate.
// -----------------------------------------------------------------------

// newTestEngine returns an Engine with no Run loop started: tests drive
// folding explicitly via e.Tick() so assertions never race a background
// ticker.
func newTestEngine() *Engine {
	return NewEngine("tenant-1")
}

func TestProposeOntologyExtension_InvalidIdentifierIsRejectedFailClosed(t *testing.T) {
	e := newTestEngine()

	err := e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "not a valid identifier!", "agent-1", "a claim")
	require.Error(t, err)

	var invalid *taxonomy.InvalidProposalError
	assert.ErrorAs(t, err, &invalid)

	// Rejected fail-closed: nothing was ever Submitted, so a Tick folds
	// nothing and no recurrence accumulates for the rejected label.
	e.Tick()
	assert.Empty(t, e.OntologyProposals())
}

func TestProposeOntologyExtension_EmptyLabelIsRejected(t *testing.T) {
	e := newTestEngine()
	err := e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "", "agent-1", "a claim")
	require.Error(t, err)
	var invalid *taxonomy.InvalidProposalError
	assert.ErrorAs(t, err, &invalid)
}

func TestProposeOntologyExtension_RequiresProposer(t *testing.T) {
	e := newTestEngine()
	err := e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "", "a claim")
	require.Error(t, err)
}

func TestProposeOntologyExtension_RequiresClaim(t *testing.T) {
	e := newTestEngine()
	err := e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "agent-1", "")
	require.Error(t, err)
}

// TestProposeOntologyExtension_ValidProposalIsObservedAndCounted proves a
// valid proposal reaches the Timeline, folds, and is counted — the full
// gibson#391 acceptance path exercised through the exported Engine seam
// rather than Reduce directly.
func TestProposeOntologyExtension_ValidProposalIsObservedAndCounted(t *testing.T) {
	e := newTestEngine()

	require.NoError(t, e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "agent-1", "sighted a container node"))
	require.NoError(t, e.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "agent-2", "sighted it again"))
	e.Tick()

	snapshot := e.OntologyProposals()
	require.Len(t, snapshot, 1)
	assert.Equal(t, "Container", snapshot[0].Label)
	assert.Equal(t, taxonomy.ProposedNodeLabel, snapshot[0].ProposalKind)
	assert.Equal(t, 2, snapshot[0].Recurrence)
	assert.Equal(t, "agent-2", snapshot[0].LastProposer)
}

// TestOntologyDiscoveryEngine_EngineSatisfiesTheSeam is a compile-time-style
// proof, run at test time, that *Engine really does satisfy the interface a
// future RPC handler will be written against (gibson#391), mirroring
// belief_world_substrate_test's equivalent assertion pattern for
// BeliefSubstrate.
func TestOntologyDiscoveryEngine_EngineSatisfiesTheSeam(t *testing.T) {
	var seam OntologyDiscoveryEngine = NewEngine("tenant-1")
	err := seam.ProposeOntologyExtension(context.Background(), taxonomy.ProposedNodeLabel, "Container", "agent-1", "a claim")
	require.NoError(t, err)
}
