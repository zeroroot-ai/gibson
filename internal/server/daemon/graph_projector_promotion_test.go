// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// promoteLabel settles and promotes one node label, the way the gate requires,
// and returns it. The promotion registry is process-wide and has no removal, so
// each test uses a name of its own.
func promoteLabel(t *testing.T, label string) {
	t.Helper()
	base, err := taxonomy.New(1, []string{taxonomy.ObservationLabel, "Host"}, []string{"HAS_PORT"})
	require.NoError(t, err)
	gate := taxonomy.NewPromotionGate(base)

	for range taxonomy.MinRecurrenceForSettlement {
		gate.Observe(taxonomy.ProposedNodeLabel, label)
	}
	require.NoError(t, gate.Confirm(taxonomy.ProposedNodeLabel, label, "reviewer-1"))
	reg, err := gate.Promote(taxonomy.ProposedNodeLabel, label)
	require.NoError(t, err)
	require.NotNil(t, reg)
}

// TestEntityIdentity_PromotedLabelUsesThePromotionRegistry is the gibson#515
// fixture. The projector resolved a promoted label to `key` while the promotion
// record and the ontology pack an import carries both declared it as brain_id, so
// an imported contribution and a locally discovered node of one label would merge
// on different properties and split (gibson#1669).
func TestEntityIdentity_PromotedLabelUsesThePromotionRegistry(t *testing.T) {
	const label = "ContainerFromPromotionTest"
	promoteLabel(t, label)

	got, err := entityIdentity(label, "brain-7")
	require.NoError(t, err)
	assert.Equal(t, map[string]any{taxonomy.DiscoveredNodeIdentityProperty: "brain-7"}, got,
		"a promoted label is merged on the property its promotion recorded, not on key")
	assert.NotContains(t, got, "key", "key is the fallback for a label nothing declares")
}

// The schema must constrain the same property, or the constraint covers no node
// the projector writes — the inverse of the defect graph_projector_schema.go
// exists to fix.
func TestIdentityForLabel_PromotedLabelMatchesTheProjector(t *testing.T) {
	const label = "SidecarFromPromotionTest"
	promoteLabel(t, label)

	id := identityForLabel(label)
	require.True(t, id.unique, "a promoted label gets a uniqueness constraint")
	require.Len(t, id.props, 1)
	assert.Equal(t, taxonomy.DiscoveredNodeIdentityProperty, id.props[0])

	// The two resolvers agree because they are one function. Asserted rather than
	// trusted: they were two copies held together by a comment, and they drifted.
	merged, err := entityIdentity(label, "brain-9")
	require.NoError(t, err)
	_, ok := merged[id.props[0]]
	assert.True(t, ok, "the schema constrains %q and the projector merges on %v", id.props[0], merged)
}

// A first-class label keeps its compile-time property: the registry is consulted
// only for labels the map does not name, so a promotion can never redefine how
// Finding or Host is identified.
func TestIdentityPropertyFor_RegisteredLabelWinsOverTheRegistry(t *testing.T) {
	for label, want := range map[string]string{
		"Finding":                 "brain_id",
		"Host":                    "brain_id",
		taxonomy.ObservationLabel: "event_id",
	} {
		assert.Equal(t, want, identityPropertyFor(label), "label %s", label)
	}
}

// A label that is neither registered nor promoted still falls back to key.
func TestIdentityPropertyFor_UnknownLabelFallsBackToKey(t *testing.T) {
	assert.Equal(t, "key", identityPropertyFor("NeverPromotedNorRegistered"))
}

// The tracker is what stops the DDL re-running, so a promotion must clear it or a
// label promoted after the first projection tick never gets its constraint.
func TestSchemaTracker_InvalidateMakesEnsureRunAgain(t *testing.T) {
	var tr schemaTracker
	runs := 0
	apply := func() error { runs++; return nil }

	require.NoError(t, tr.ensure("acme", apply))
	require.NoError(t, tr.ensure("acme", apply))
	assert.Equal(t, 1, runs, "ensure runs once per tenant")

	tr.invalidate()
	require.NoError(t, tr.ensure("acme", apply))
	assert.Equal(t, 2, runs, "after a promotion the DDL runs again")
}

// Promotion is process-wide, so every tenant's graph gains the label at once and
// every tenant's schema has to be re-ensured — not just the one that happened to
// trigger it.
func TestSchemaTracker_InvalidateClearsEveryTenant(t *testing.T) {
	var tr schemaTracker
	runs := map[string]int{}
	for _, tenant := range []string{"acme", "globex"} {
		require.NoError(t, tr.ensure(tenant, func() error { runs[tenant]++; return nil }))
	}
	require.Equal(t, map[string]int{"acme": 1, "globex": 1}, runs)

	tr.invalidate()
	for _, tenant := range []string{"acme", "globex"} {
		require.NoError(t, tr.ensure(tenant, func() error { runs[tenant]++; return nil }))
	}
	assert.Equal(t, map[string]int{"acme": 2, "globex": 2}, runs)
}

// Invalidating before any tenant has been seen must not panic: the hook is
// registered at construction and a promotion can happen before the first write.
func TestSchemaTracker_InvalidateOnAnEmptyTrackerIsSafe(t *testing.T) {
	var tr schemaTracker
	tr.invalidate()
	runs := 0
	require.NoError(t, tr.ensure("acme", func() error { runs++; return nil }))
	assert.Equal(t, 1, runs)
}

// The writer registers the hook at construction, so a promotion reaches the
// tracker without anything else being wired.
func TestNewNeo4jGraphWriter_PromotionClearsItsSchemaTracker(t *testing.T) {
	w := newNeo4jGraphWriter(nil)
	runs := 0
	require.NoError(t, w.schema.ensure("acme", func() error { runs++; return nil }))
	require.NoError(t, w.schema.ensure("acme", func() error { runs++; return nil }))
	require.Equal(t, 1, runs)

	promoteLabel(t, "HookWiringFromPromotionTest")

	require.NoError(t, w.schema.ensure("acme", func() error { runs++; return nil }))
	assert.Equal(t, 2, runs, "promoting a label must re-open the DDL for the next tick")
}
