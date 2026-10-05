// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"fmt"
	"sort"
)

// catalog.go: the curated, platform-owned Domain Pack catalog (ADR-0133's
// "tier 2"), gibson#381.
//
// A catalog Pack ships as SDK-sourced content via the standard release/
// rollout pipeline (ADR-0133) — never hot-reloaded, never written
// by a tenant. DomainPackCatalog is the in-process registry
// DomainPackService.ListCatalog reads and EnableDomainPack resolves a
// catalog name against. gibson#381 built the enablement mechanism; gibson#382
// seeds the catalog's content — see MainDomainPack in catalog_main_pack.go,
// the "main" pack ADR-0133 names, default-off.

// DomainPackCatalog is the curated set of catalog Domain Packs available to
// enable, keyed by Name. Immutable after construction — a catalog never
// changes underneath a running daemon (no hot-reload, ADR-0133);
// picking up new or changed catalog content is a daemon restart, like every
// other embedded-content catalog in this codebase (componentcatalog).
type DomainPackCatalog struct {
	packs map[string]DomainPack
}

// NewDomainPackCatalog builds a catalog over the given packs, keyed by Name.
// Every pack must pass Validate() and carry a non-empty Name; a name
// collision or a pack that fails Validate is a startup-time programming
// error (catalog content ships through code review, never through untrusted
// input), so NewDomainPackCatalog panics rather than fail silently or drop
// an entry.
func NewDomainPackCatalog(packs ...DomainPack) *DomainPackCatalog {
	m := make(map[string]DomainPack, len(packs))
	for _, p := range packs {
		if p.Name == "" {
			panic("ontology: catalog pack has an empty Name")
		}
		if err := p.Validate(); err != nil {
			panic(fmt.Sprintf("ontology: catalog pack %q: %v", p.Name, err))
		}
		if _, dup := m[p.Name]; dup {
			panic(fmt.Sprintf("ontology: catalog pack %q: duplicate name", p.Name))
		}
		m[p.Name] = p
	}
	return &DomainPackCatalog{packs: m}
}

// List returns every catalog pack, sorted by Name.
func (c *DomainPackCatalog) List() []DomainPack {
	if c == nil || len(c.packs) == 0 {
		return nil
	}
	out := make([]DomainPack, 0, len(c.packs))
	for _, p := range c.packs {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns the named catalog pack, and whether it exists.
func (c *DomainPackCatalog) Get(name string) (DomainPack, bool) {
	if c == nil {
		return DomainPack{}, false
	}
	p, ok := c.packs[name]
	return p, ok
}
