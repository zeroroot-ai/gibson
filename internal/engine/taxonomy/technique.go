// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package taxonomy

import (
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// technique.go represents the technique hierarchy inside the Taxonomy
// (ADR-0035, gibson#379): coarse categories and fine-grained techniques are
// both taxonomy nodes — "Category" and "Technique" are admitted into the
// Global Registry's node vocabulary like any other materialised shape, and
// RollsUpToRelationshipType is the admitted edge a technique uses to declare
// its parent category. That edge is the whole bridge: there is no separate
// reconciliation table between the two vocabularies.
//
// Categories and techniques are themselves pack-defined content (ADR-0033),
// not schema, so their identifiers live in a TechniqueHierarchy rather than
// in the Registry's label/relationship-type sets. The core pack seeds only
// the coarse categories, one per types.TechniqueType value — the fixed Go
// enum this hierarchy supersedes as the authority (types.TechniqueType
// itself is untouched here; migrating its consumers is gibson#385).
// Fine-grained techniques are pack-extensible and are not seeded from any
// enum, because none exists at that grain.

// CategoryLabel is the node label a coarse category materialises as.
const CategoryLabel = "Category"

// TechniqueLabel is the node label a fine-grained technique materialises as.
const TechniqueLabel = "Technique"

// RollsUpToRelationshipType is the taxonomy relationship a Technique node
// uses to declare its parent Category node (ADR-0035 decision 2: "the
// hierarchy *is* the bridge").
const RollsUpToRelationshipType = "ROLLS_UP_TO"

// CategoryID identifies a coarse technique category, such as
// "prompt_injection". Core category ids are seeded from types.TechniqueType.
type CategoryID string

// TechniqueID identifies a fine-grained, pack-defined technique. Unlike
// CategoryID, no core set is seeded — the core pack only fixes the
// categories; techniques arrive from Domain Packs (ADR-0033).
type TechniqueID string

// TechniqueHierarchy is the technique vocabulary's value authority: the
// admitted category ids, the admitted technique ids, and the technique ->
// category rollup that bridges them. Every id, at both levels, is a
// validated plain identifier (ValidIdentifier) — the same non-negotiable
// safety control the Registry applies to node labels and relationship
// types, because a Category or Technique id is written to the graph as a
// node property that keys settlement, reputation and VoI dispatch.
//
// A TechniqueHierarchy is immutable once built; WithTechnique returns a new
// value with one more technique, leaving the receiver unchanged.
type TechniqueHierarchy struct {
	categories map[CategoryID]struct{}
	rollup     map[TechniqueID]CategoryID
}

// NewTechniqueHierarchy builds a TechniqueHierarchy from a set of category
// ids and a technique -> category rollup. It refuses:
//   - any category or technique id that fails ValidIdentifier;
//   - a duplicate category id;
//   - a technique whose declared category is not in categories — the
//     rollup edge would otherwise point at nothing.
func NewTechniqueHierarchy(categories []CategoryID, rollup map[TechniqueID]CategoryID) (*TechniqueHierarchy, error) {
	h := &TechniqueHierarchy{
		categories: make(map[CategoryID]struct{}, len(categories)),
		rollup:     make(map[TechniqueID]CategoryID, len(rollup)),
	}
	for _, category := range categories {
		if err := ValidIdentifier(string(category)); err != nil {
			return nil, fmt.Errorf("taxonomy: category: %w", err)
		}
		if _, dup := h.categories[category]; dup {
			return nil, fmt.Errorf("taxonomy: duplicate category %q", category)
		}
		h.categories[category] = struct{}{}
	}
	for technique, category := range rollup {
		if err := h.addTechnique(technique, category); err != nil {
			return nil, err
		}
	}
	return h, nil
}

// addTechnique validates and records one technique -> category rollup edge
// on h in place. It is the single validation path shared by
// NewTechniqueHierarchy and WithTechnique.
func (h *TechniqueHierarchy) addTechnique(technique TechniqueID, category CategoryID) error {
	if err := ValidIdentifier(string(technique)); err != nil {
		return fmt.Errorf("taxonomy: technique: %w", err)
	}
	if err := ValidIdentifier(string(category)); err != nil {
		return fmt.Errorf("taxonomy: technique %q category: %w", technique, err)
	}
	if _, ok := h.categories[category]; !ok {
		return fmt.Errorf("taxonomy: technique %q rolls up to category %q, which is not admitted",
			technique, category)
	}
	if existing, dup := h.rollup[technique]; dup {
		return fmt.Errorf("taxonomy: duplicate technique %q (already rolls up to %q)", technique, existing)
	}
	h.rollup[technique] = category
	return nil
}

// WithTechnique returns a new TechniqueHierarchy with technique added,
// rolling up to category. The receiver is unchanged. It fails under the same
// conditions as NewTechniqueHierarchy: an invalid identifier at either
// level, an unadmitted category, or a technique id already present.
func (h *TechniqueHierarchy) WithTechnique(technique TechniqueID, category CategoryID) (*TechniqueHierarchy, error) {
	next := &TechniqueHierarchy{
		categories: maps.Clone(h.categories),
		rollup:     maps.Clone(h.rollup),
	}
	if err := next.addTechnique(technique, category); err != nil {
		return nil, err
	}
	return next, nil
}

// Categories returns the admitted category ids, sorted.
func (h *TechniqueHierarchy) Categories() []CategoryID {
	out := slices.Collect(maps.Keys(h.categories))
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Techniques returns the admitted technique ids, sorted.
func (h *TechniqueHierarchy) Techniques() []TechniqueID {
	out := slices.Collect(maps.Keys(h.rollup))
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// HasCategory reports whether category is admitted.
func (h *TechniqueHierarchy) HasCategory(category CategoryID) bool {
	_, ok := h.categories[category]
	return ok
}

// HasTechnique reports whether technique is admitted.
func (h *TechniqueHierarchy) HasTechnique(technique TechniqueID) bool {
	_, ok := h.rollup[technique]
	return ok
}

// CategoryOf is the technique -> category rollup lookup: the bridge VoI
// dispatch gating needs to map a candidate's fine-grained technique to the
// coarse category a capability declares coverage for (ADR-0035 decision 4).
// ok is false when technique is not admitted.
func (h *TechniqueHierarchy) CategoryOf(technique TechniqueID) (category CategoryID, ok bool) {
	category, ok = h.rollup[technique]
	return category, ok
}

// coreCategories is the core pack's category seed: one CategoryID per
// types.TechniqueType value. Keeping the seed derived from AllTechniqueTypes
// rather than re-listing the strings means the two vocabularies cannot drift
// while types.TechniqueType still exists.
func coreCategories() []CategoryID {
	all := types.AllTechniqueTypes()
	out := make([]CategoryID, len(all))
	for i, t := range all {
		out[i] = CategoryID(t.String())
	}
	return out
}

// GlobalTechniques is the platform's core TechniqueHierarchy: the categories
// seeded from types.TechniqueType, and no techniques yet — the core pack
// fixes only the coarse level; fine-grained techniques are added by Domain
// Packs (ADR-0033) via WithTechnique. Building it at init means a seed that
// fails ValidIdentifier (it cannot, today — see TestCoreCategoriesAreValid —
// but a future enum value might) fails the process at startup rather than
// surfacing as a silently-missing category months later.
var GlobalTechniques = mustNewTechniqueHierarchy(coreCategories(), nil)

func mustNewTechniqueHierarchy(categories []CategoryID, rollup map[TechniqueID]CategoryID) *TechniqueHierarchy {
	h, err := NewTechniqueHierarchy(categories, rollup)
	if err != nil {
		panic("taxonomy: the global TechniqueHierarchy is invalid: " + err.Error())
	}
	return h
}
