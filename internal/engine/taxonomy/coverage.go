// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package taxonomy

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
)

// coverage.go is the capability side of the VoI dispatch bridge (ADR-0035
// decision 4, gibson#386): a capability (an Agent, Tool or Plugin catalog
// entry — CONTEXT.md "capability vs execution") declares the taxonomy
// categories and/or fine-grained techniques it covers. #387 resolves a VoI
// candidate's technique to its category (TechniqueHierarchy.CategoryOf) and
// matches it against capabilities whose Coverage includes that technique or
// its category — that resolution is out of scope here; this file only makes
// the declaration constructable, validated and queryable.

// Coverage is a capability's declared technique coverage: the set of
// category ids and technique ids it can address. The zero value is empty
// coverage (a capability that declares nothing) and is safe to query like
// any Coverage — reading a nil map is defined behavior in Go — but the only
// way to add entries is NewCoverage, which validates every id against a
// TechniqueHierarchy and always returns a Coverage with initialized maps
// (ADR-0003: no graceful-nil, construct fully or fail).
type Coverage struct {
	categories map[CategoryID]struct{}
	techniques map[TechniqueID]struct{}
}

// NewCoverage builds a Coverage from a set of category and technique ids,
// validating every one against hierarchy. It refuses:
//   - a nil hierarchy — coverage cannot be validated without one;
//   - any category id hierarchy does not admit (TechniqueHierarchy.HasCategory);
//   - any technique id hierarchy does not admit (TechniqueHierarchy.HasTechnique).
//
// Declaring the same category or technique id more than once is not an
// error; both dedupe on the set. categories and techniques may overlap in
// meaning (a technique's own category may also be listed) — that is a
// broader declaration, not a conflict.
func NewCoverage(hierarchy *TechniqueHierarchy, categories []CategoryID, techniques []TechniqueID) (Coverage, error) {
	if hierarchy == nil {
		return Coverage{}, errors.New("taxonomy: coverage: hierarchy must not be nil")
	}
	c := Coverage{
		categories: make(map[CategoryID]struct{}, len(categories)),
		techniques: make(map[TechniqueID]struct{}, len(techniques)),
	}
	for _, category := range categories {
		if !hierarchy.HasCategory(category) {
			return Coverage{}, fmt.Errorf("taxonomy: coverage: category %q is not in the technique hierarchy", category)
		}
		c.categories[category] = struct{}{}
	}
	for _, technique := range techniques {
		if !hierarchy.HasTechnique(technique) {
			return Coverage{}, fmt.Errorf("taxonomy: coverage: technique %q is not in the technique hierarchy", technique)
		}
		c.techniques[technique] = struct{}{}
	}
	return c, nil
}

// EmptyCoverage is an explicit, initialized empty declaration: a capability
// that covers nothing (yet). Equivalent in behavior to the zero value; use it
// where an initialized-looking value reads better than a bare Coverage{}.
func EmptyCoverage() Coverage {
	return Coverage{categories: map[CategoryID]struct{}{}, techniques: map[TechniqueID]struct{}{}}
}

// Categories returns the declared category ids, sorted.
func (c Coverage) Categories() []CategoryID {
	out := slices.Collect(maps.Keys(c.categories))
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Techniques returns the declared technique ids, sorted.
func (c Coverage) Techniques() []TechniqueID {
	out := slices.Collect(maps.Keys(c.techniques))
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// HasCategory reports whether c declares coverage of category.
func (c Coverage) HasCategory(category CategoryID) bool {
	_, ok := c.categories[category]
	return ok
}

// HasTechnique reports whether c declares coverage of technique.
func (c Coverage) HasTechnique(technique TechniqueID) bool {
	_, ok := c.techniques[technique]
	return ok
}

// IsEmpty reports whether c declares no coverage at all.
func (c Coverage) IsEmpty() bool {
	return len(c.categories) == 0 && len(c.techniques) == 0
}
