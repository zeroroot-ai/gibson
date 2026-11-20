// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainDomainPack_IsValid(t *testing.T) {
	pack := mainPack(t)
	require.NoError(t, pack.Validate())
	assert.Equal(t, MainDomainPackName, pack.Name)
	assert.Equal(t, "main", pack.Name)
	assert.NotZero(t, pack.Version)
	assert.Equal(t, PackVisibilityPublic, pack.Visibility)
	assert.NotEmpty(t, pack.Predicates, "a skeleton pack still needs at least one binding")
}

// TestMainDomainPack_RegistersIntoCatalog proves the seed pack is a valid
// catalog entry: NewDomainPackCatalog panics on any pack that fails
// Validate or carries a bad Name, so this also re-proves the main pack's
// shape end to end through the exact constructor the daemon calls.
func TestMainDomainPack_RegistersIntoCatalog(t *testing.T) {
	catalog := NewDomainPackCatalog(mainPack(t))

	got, ok := catalog.Get(MainDomainPackName)
	require.True(t, ok, "the seed pack must be reachable by its catalog name")
	assert.Equal(t, mainPack(t), got)

	list := catalog.List()
	require.Len(t, list, 1)
	assert.Equal(t, MainDomainPackName, list[0].Name)
}

// TestMainDomainPack_FreshValueEachCall proves EmbeddedCatalog().Get never hands
// back a shared, mutable instance: a caller that mutates one call's Predicates
// map must never affect another.
func TestMainDomainPack_FreshValueEachCall(t *testing.T) {
	a := mainPack(t)
	b := mainPack(t)
	want := len(b.Predicates)

	for technique := range a.Predicates {
		delete(a.Predicates, technique)
		break
	}
	assert.Len(t, b.Predicates, want, "mutating one call's map must never affect another")
}

// destructivePredicates is the decision of the author for each predicate that
// changes the target. The pack names the other predicates as non-destructive
// (ADR-0132). A new predicate is destructive until the author names it, so this
// test makes the author decide: a predicate is in the pack list or in this one.
var destructivePredicates = []string{
	// The proof writes one ConfigMap to the namespace of the target.
	"rbac_write_access_proven",
}

func TestMainDomainPack_StatesEveryPredicate(t *testing.T) {
	pack := mainPack(t)
	require.NoError(t, pack.Validate())
	assert.Len(t, pack.NonDestructivePredicates, len(pack.Predicates)-len(destructivePredicates))
	for _, name := range destructivePredicates {
		assert.Contains(t, pack.Predicates, name)
		assert.NotContains(t, pack.NonDestructivePredicates, name,
			"the predicate %s is destructive and must not be listed as non-destructive", name)
	}
	for name := range pack.Predicates {
		if !slices.Contains(destructivePredicates, name) {
			assert.Contains(t, pack.NonDestructivePredicates, name,
				"the predicate %s is not stated: list it as non-destructive or as destructive", name)
		}
	}
}
