// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDomainPackCatalog_Empty(t *testing.T) {
	c := NewDomainPackCatalog()
	assert.Empty(t, c.List())
	_, ok := c.Get("main")
	assert.False(t, ok)
}

func TestDomainPackCatalog_ListIsSortedByName(t *testing.T) {
	c := NewDomainPackCatalog(
		DomainPack{Name: "web", Version: 1},
		DomainPack{Name: "k8s", Version: 1},
		DomainPack{Name: "healthcare", Version: 1},
	)
	list := c.List()
	require.Len(t, list, 3)
	assert.Equal(t, []string{"healthcare", "k8s", "web"}, []string{list[0].Name, list[1].Name, list[2].Name})
}

func TestDomainPackCatalog_Get(t *testing.T) {
	c := NewDomainPackCatalog(DomainPack{Name: "main", Version: 2, Author: "zeroroot"})
	p, ok := c.Get("main")
	require.True(t, ok)
	assert.Equal(t, 2, p.Version)
	assert.Equal(t, "zeroroot", p.Author)

	_, ok = c.Get("nonexistent")
	assert.False(t, ok)
}

func TestNewDomainPackCatalog_PanicsOnInvalidPack(t *testing.T) {
	assert.Panics(t, func() {
		NewDomainPackCatalog(DomainPack{Name: "bad", Predicates: map[string]string{"t": ""}})
	})
}

func TestNewDomainPackCatalog_PanicsOnEmptyName(t *testing.T) {
	assert.Panics(t, func() {
		NewDomainPackCatalog(DomainPack{Name: ""})
	})
}

func TestNewDomainPackCatalog_PanicsOnDuplicateName(t *testing.T) {
	assert.Panics(t, func() {
		NewDomainPackCatalog(
			DomainPack{Name: "main", Version: 1},
			DomainPack{Name: "main", Version: 2},
		)
	})
}

// TestDomainPackCatalog_ListReturnsCopy proves List's result is a fresh
// slice: mutating it must never corrupt the catalog's own state (the same
// defensive-copy discipline the brain package's *Snapshot accessors follow).
func TestDomainPackCatalog_ListReturnsCopy(t *testing.T) {
	c := NewDomainPackCatalog(DomainPack{Name: "main", Version: 1})
	list := c.List()
	list[0].Name = "TAMPERED"

	again := c.List()
	require.Len(t, again, 1)
	assert.Equal(t, "main", again[0].Name)
}

// TestDomainPackCatalog_NilReceiverIsSafe proves a nil *DomainPackCatalog
// behaves like an empty one rather than panicking — defensive against a
// daemon path that reaches DomainPackService before the catalog is wired.
func TestDomainPackCatalog_NilReceiverIsSafe(t *testing.T) {
	var c *DomainPackCatalog
	assert.Empty(t, c.List())
	_, ok := c.Get("main")
	assert.False(t, ok)
}
