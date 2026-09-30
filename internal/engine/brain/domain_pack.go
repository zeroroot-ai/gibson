// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package brain — domain_pack.go: per-tenant Domain Pack enablement
// (ADR-0033, gibson#381, epic #376).
//
// A Domain Pack (internal/engine/ontology.DomainPack) is curated, versioned
// structure — taxonomy labels, ontology extensions, and technique -> CEL
// predicate bindings — never code (ADR-0033 decision 1). Pack CONTENT ships
// once, via the SDK release/rollout pipeline (ADR-0033 decision 4): it never
// hot-reloads. What DOES change per tenant, at any time, is ENABLEMENT — and
// that is a fact about this tenant's World, so it folds through the same
// log-first event-sourcing discipline as everything else here (ADR-0001):
// DomainPackEnabled/DomainPackDisabled are Timeline-durable, replayable, and
// (like every brain Event) implicitly mission-pinned by the tenant Timeline
// they land on.
//
// Enabling a pack loads its content into THIS tenant's live World only
// (w.domainPacks) — brain.Registry's one-World-per-tenant isolation
// (registry.go) is what makes "per-tenant, not per-install" structural
// rather than a checked invariant. Disabling removes it. A future consumer
// (gibson#388: compiling and evaluating a Predicates CEL expression at
// settlement time) reads w.domainPacks the same way bet_settlement.go reads
// any other per-tenant World state today.
package brain

import "sort"

// DomainPackState is the taxonomy/ontology/predicate content of one Domain
// Pack currently enabled for a tenant — the "live registry" ADR-0033
// decision 4 describes. It is a plain value, not an ecs.Map1 entity: like
// FlightRecorderPolicy, it is per-tenant singleton-shaped state keyed by pack
// name, not a growing collection of sighted facts.
type DomainPackState struct {
	// Version is the pack version that was enabled, carried through from the
	// catalog entry at enable time (never re-resolved against a possibly
	// newer catalog on replay — ADR-0033 decision 4's "version-pinned for
	// replay").
	Version int
	// TaxonomyNodeLabels and TaxonomyRelationshipTypes are the vocabulary
	// this pack layers on top of the platform's own core taxonomy
	// (ontology.DomainPack.Import's contract) while it is enabled.
	TaxonomyNodeLabels        []string
	TaxonomyRelationshipTypes []string
	// Predicates is this pack's technique -> CEL-expression bindings
	// (ADR-0031 decision 1), carried verbatim from ontology.DomainPack.
	// Opaque text here too — brain never compiles or evaluates CEL; that is
	// gibson#388's job, reading this map.
	Predicates map[string]string
}

// DomainPackEnabled records that a tenant enabled the named catalog Domain
// Pack — ADR-0033 decision 4: "per-tenant enable/disable folds a
// DomainPackEnabled brain event". The event carries the pack's full resolved
// content (never just a catalog_id to look up later) so replay is
// deterministic and self-contained: it never needs to re-resolve the
// catalog, which may have moved on to a newer version by then.
type DomainPackEnabled struct {
	Name                      string
	Version                   int
	TaxonomyNodeLabels        []string
	TaxonomyRelationshipTypes []string
	Predicates                map[string]string
}

// Kind identifies this event on the Timeline.
func (DomainPackEnabled) Kind() string { return "domain_pack.enabled" }

// DomainPackDisabled records that a tenant disabled a previously-enabled
// Domain Pack, removing its content from the tenant's live World.
type DomainPackDisabled struct {
	Name string
}

// Kind identifies this event on the Timeline.
func (DomainPackDisabled) Kind() string { return "domain_pack.disabled" }

func applyDomainPackEnabled(w *World, e DomainPackEnabled) {
	w.domainPacks[e.Name] = DomainPackState{
		Version:                   e.Version,
		TaxonomyNodeLabels:        append([]string(nil), e.TaxonomyNodeLabels...),
		TaxonomyRelationshipTypes: append([]string(nil), e.TaxonomyRelationshipTypes...),
		Predicates:                clonePredicateMap(e.Predicates),
	}
}

func applyDomainPackDisabled(w *World, e DomainPackDisabled) {
	delete(w.domainPacks, e.Name)
}

func clonePredicateMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// DomainPackSnapshot is a stable, comparable view of one tenant-enabled
// Domain Pack.
type DomainPackSnapshot struct {
	Name                      string
	Version                   int
	TaxonomyNodeLabels        []string
	TaxonomyRelationshipTypes []string
	Predicates                map[string]string
}

// DomainPackSnapshot returns the tenant's currently enabled Domain Packs, in
// deterministic (name) order.
func (w *World) DomainPackSnapshot() []DomainPackSnapshot {
	if len(w.domainPacks) == 0 {
		return nil
	}
	out := make([]DomainPackSnapshot, 0, len(w.domainPacks))
	for name, s := range w.domainPacks {
		out = append(out, DomainPackSnapshot{
			Name:                      name,
			Version:                   s.Version,
			TaxonomyNodeLabels:        append([]string(nil), s.TaxonomyNodeLabels...),
			TaxonomyRelationshipTypes: append([]string(nil), s.TaxonomyRelationshipTypes...),
			Predicates:                clonePredicateMap(s.Predicates),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// IsDomainPackEnabled reports whether the named pack is currently enabled for
// this tenant.
func (w *World) IsDomainPackEnabled(name string) bool {
	_, ok := w.domainPacks[name]
	return ok
}

// DomainPackPredicate returns the CEL expression text a currently-enabled
// pack binds to technique, and whether one is bound at all. A future
// settlement-predicate consumer (gibson#388) uses this to resolve a
// technique's binding without needing to know which pack it came from.
func (w *World) DomainPackPredicate(technique string) (string, bool) {
	for _, s := range w.domainPacks {
		if expr, ok := s.Predicates[technique]; ok {
			return expr, true
		}
	}
	return "", false
}
