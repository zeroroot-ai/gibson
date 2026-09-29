// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMainDomainPack_IsValid(t *testing.T) {
	pack := MainDomainPack()
	assert.NoError(t, pack.Validate())
	assert.Equal(t, MainDomainPackName, pack.Name)
	assert.Equal(t, "main", pack.Name)
	assert.NotZero(t, pack.Version)
	assert.Equal(t, PackVisibilityPublic, pack.Visibility)
	assert.Empty(t, pack.Entitlement, "the seed pack must be free — no entitlement gate")
	assert.NotEmpty(t, pack.Predicates, "a skeleton pack still needs at least one binding")
}

// TestMainDomainPack_RegistersIntoCatalog proves the seed pack is a valid
// catalog entry: NewDomainPackCatalog panics on any pack that fails
// Validate or carries a bad Name, so this also re-proves MainDomainPack's
// shape end to end through the exact constructor the daemon calls.
func TestMainDomainPack_RegistersIntoCatalog(t *testing.T) {
	catalog := NewDomainPackCatalog(MainDomainPack())

	got, ok := catalog.Get(MainDomainPackName)
	require.True(t, ok, "the seed pack must be reachable by its catalog name")
	assert.Equal(t, MainDomainPack(), got)

	list := catalog.List()
	require.Len(t, list, 1)
	assert.Equal(t, MainDomainPackName, list[0].Name)
}

// TestMainDomainPack_FreshValueEachCall proves MainDomainPack never hands
// back a shared, mutable instance: a caller that mutates one call's Predicates
// map must never affect another.
func TestMainDomainPack_FreshValueEachCall(t *testing.T) {
	a := MainDomainPack()
	b := MainDomainPack()
	want := len(b.Predicates)

	for technique := range a.Predicates {
		delete(a.Predicates, technique)
		break
	}
	assert.Len(t, b.Predicates, want, "mutating one call's map must never affect another")
}
