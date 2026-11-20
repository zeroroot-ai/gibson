// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// countermeasure.go: the countermeasure catalog of a pack (gibson#1484,
// ADR-0133). A countermeasure is one technique of a defensive framework, for
// example one MITRE D3FEND technique. It is taxonomy and ontology only: it
// has a place in a hierarchy, it counters ATT&CK techniques, and it maps to
// controls of a compliance framework. It holds no predicate. The proof of a
// fix is the rule of the fix loop, never a predicate of a countermeasure.

const (
	// D3FENDPackName is the catalog name of the MITRE D3FEND pack. The pack
	// holds taxonomy and ontology only: Validate refuses a predicate in it
	// (owner decision of 2026-11-19, gibson#1485). The proof of a fix is the
	// rule of the fix loop, never a predicate of a countermeasure.
	D3FENDPackName = "mitre-d3fend"

	// CountermeasureLabel is the node label of a countermeasure.
	CountermeasureLabel = "Countermeasure"
	// CountermeasureIdentityProperty is the property that a countermeasure node
	// is merged on. Its value is the id of the countermeasure.
	CountermeasureIdentityProperty = "countermeasure_id"
	// CountersRelationshipType is the edge from a countermeasure to an ATT&CK
	// technique that it counters.
	CountersRelationshipType = "COUNTERS"
	// AppliesCountermeasureRelationshipType is the edge from a merge request to
	// the countermeasure that its fix applies (gibson#1487).
	AppliesCountermeasureRelationshipType = "APPLIES_COUNTERMEASURE"

	// MaxCountermeasures bounds the countermeasures of one pack.
	MaxCountermeasures = 2048
	// MaxCountersPerCountermeasure bounds the ATT&CK techniques that one
	// countermeasure counters.
	MaxCountersPerCountermeasure = 2048
	// MaxControlsPerCountermeasure bounds the controls that one countermeasure
	// maps to.
	MaxControlsPerCountermeasure = 256
	// MaxCountermeasureTactics bounds the tactics of one pack.
	MaxCountermeasureTactics = 32
	// MaxSourceFieldBytes bounds each text field of a PackSource.
	MaxSourceFieldBytes = 512
)

// countermeasureID is the form of a countermeasure id, for example "D3-FA".
var countermeasureID = regexp.MustCompile(`^D3-[A-Z0-9]{1,16}$`)

// attackTechniqueID is the form of an ATT&CK technique id, for example
// "T1059" or "T1059.001".
var attackTechniqueID = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// Countermeasure is one defensive technique.
type Countermeasure struct {
	// ID is the id of the countermeasure in its framework, for example "D3-FA".
	ID string `json:"id"`
	// Name is the name that the framework gives the countermeasure.
	Name string `json:"name"`
	// Tactic is the tactic of the countermeasure. It is one of the
	// CountermeasureTactics of the pack.
	Tactic string `json:"tactic"`
	// Parent is the id of the countermeasure above this one in the hierarchy.
	// It is empty for a countermeasure at the top of its tactic.
	Parent string `json:"parent,omitempty"`
	// Counters is the ids of the ATT&CK techniques that this countermeasure
	// counters.
	Counters []string `json:"counters,omitempty"`
	// NISTControls is the ids of the NIST SP 800-53 rev 5 controls that the
	// framework maps to this countermeasure, in the id form of the pack
	// nist-800-53-r5 (for example "ac-17" or "ac-17.8").
	NISTControls []string `json:"nist_controls,omitempty"`
}

// PackSource records the release of the published data that a pack came from.
type PackSource struct {
	// Name is the name of the data set, for example "MITRE D3FEND".
	Name string `json:"name"`
	// Release is the exact release of the data set.
	Release string `json:"release"`
	// URL is the address that the data came from.
	URL string `json:"url"`
	// License is the license that the publisher gives the data.
	License string `json:"license"`
	// SHA256 is the SHA-256 of the file at URL for this release.
	SHA256 string `json:"sha256"`
}

// validate checks that each field is bounded, valid UTF-8 text.
func (s PackSource) validate() error {
	for name, v := range map[string]string{
		"name": s.Name, "release": s.Release, "url": s.URL, "license": s.License, "sha256": s.SHA256,
	} {
		if strings.TrimSpace(v) == "" || !utf8.ValidString(v) || len(v) > MaxSourceFieldBytes {
			return fmt.Errorf("source %s must be valid UTF-8 text of 1 to %d bytes", name, MaxSourceFieldBytes)
		}
	}
	return nil
}

// ValidAttackTechniqueID reports whether id has the form of an ATT&CK
// technique id.
func ValidAttackTechniqueID(id string) bool { return attackTechniqueID.MatchString(id) }

// CountermeasuresFor returns the countermeasures that counter the ATT&CK
// technique, in pack order. A technique that no countermeasure counters, and
// an id that is not an ATT&CK technique id, return nothing.
func (p *DomainPack) CountermeasuresFor(technique string) []Countermeasure {
	if !ValidAttackTechniqueID(technique) {
		return nil
	}
	var out []Countermeasure
	for _, c := range p.Countermeasures {
		if slices.Contains(c.Counters, technique) {
			out = append(out, c)
		}
	}
	return out
}

// Countermeasure returns the countermeasure with the id, and whether the pack
// holds it.
func (p *DomainPack) Countermeasure(id string) (Countermeasure, bool) {
	for _, c := range p.Countermeasures {
		if c.ID == id {
			return c, true
		}
	}
	return Countermeasure{}, false
}

// CountermeasuresForControl returns the countermeasures that the pack maps to
// the control, in pack order.
func (p *DomainPack) CountermeasuresForControl(controlID string) []Countermeasure {
	var out []Countermeasure
	for _, c := range p.Countermeasures {
		if slices.Contains(c.NISTControls, controlID) {
			out = append(out, c)
		}
	}
	return out
}

// validateCountermeasures checks the countermeasure catalog of the pack.
func (p *DomainPack) validateCountermeasures() error {
	if len(p.Countermeasures) == 0 {
		if len(p.CountermeasureTactics) > 0 {
			return fmt.Errorf("domain pack %q: countermeasure tactics with no countermeasure", p.Name)
		}
		return nil
	}
	if len(p.Countermeasures) > MaxCountermeasures {
		return fmt.Errorf("domain pack %q: %d countermeasures, over the %d cap",
			p.Name, len(p.Countermeasures), MaxCountermeasures)
	}
	if !slices.Contains(p.TaxonomyNodeLabels, CountermeasureLabel) ||
		!slices.Contains(p.TaxonomyRelationshipTypes, CountersRelationshipType) {
		return fmt.Errorf("domain pack %q: a pack with countermeasures must promote the label %q and the relationship type %q",
			p.Name, CountermeasureLabel, CountersRelationshipType)
	}
	if err := p.validateCountermeasureTactics(); err != nil {
		return err
	}
	ids := make(map[string]struct{}, len(p.Countermeasures))
	for _, c := range p.Countermeasures {
		if !countermeasureID.MatchString(c.ID) {
			return fmt.Errorf("domain pack %q: countermeasure id %q is not of the form D3-XXX", p.Name, c.ID)
		}
		if _, dup := ids[c.ID]; dup {
			return fmt.Errorf("domain pack %q: countermeasure %q is listed twice", p.Name, c.ID)
		}
		ids[c.ID] = struct{}{}
	}
	for _, c := range p.Countermeasures {
		if err := p.validateCountermeasure(c, ids); err != nil {
			return err
		}
	}
	return p.validateCountermeasureParents()
}

func (p *DomainPack) validateCountermeasureTactics() error {
	if len(p.CountermeasureTactics) == 0 || len(p.CountermeasureTactics) > MaxCountermeasureTactics {
		return fmt.Errorf("domain pack %q: a pack with countermeasures needs 1 to %d tactics", p.Name, MaxCountermeasureTactics)
	}
	seen := make(map[string]struct{}, len(p.CountermeasureTactics))
	for _, t := range p.CountermeasureTactics {
		if err := validCountermeasureText(t); err != nil {
			return fmt.Errorf("domain pack %q: countermeasure tactic: %w", p.Name, err)
		}
		if _, dup := seen[t]; dup {
			return fmt.Errorf("domain pack %q: countermeasure tactic %q is listed twice", p.Name, t)
		}
		seen[t] = struct{}{}
	}
	return nil
}

// validCountermeasureText reports whether s is bounded, valid UTF-8 text.
func validCountermeasureText(s string) error {
	if strings.TrimSpace(s) == "" || !utf8.ValidString(s) || len(s) > MaxControlTitleBytes {
		return fmt.Errorf("text must be valid UTF-8 of 1 to %d bytes", MaxControlTitleBytes)
	}
	return nil
}

func (p *DomainPack) validateCountermeasure(c Countermeasure, ids map[string]struct{}) error {
	if err := validCountermeasureText(c.Name); err != nil {
		return fmt.Errorf("domain pack %q: countermeasure %q: name: %w", p.Name, c.ID, err)
	}
	if !slices.Contains(p.CountermeasureTactics, c.Tactic) {
		return fmt.Errorf("domain pack %q: countermeasure %q: tactic %q is not a tactic of the pack", p.Name, c.ID, c.Tactic)
	}
	if c.Parent != "" {
		if _, ok := ids[c.Parent]; !ok {
			return fmt.Errorf("domain pack %q: countermeasure %q: parent %q is not a countermeasure of the pack",
				p.Name, c.ID, c.Parent)
		}
	}
	if len(c.Counters) > MaxCountersPerCountermeasure {
		return fmt.Errorf("domain pack %q: countermeasure %q counters %d techniques, over the %d cap",
			p.Name, c.ID, len(c.Counters), MaxCountersPerCountermeasure)
	}
	seen := make(map[string]struct{}, len(c.Counters))
	for _, t := range c.Counters {
		if !ValidAttackTechniqueID(t) {
			return fmt.Errorf("domain pack %q: countermeasure %q: %q is not an ATT&CK technique id", p.Name, c.ID, t)
		}
		if _, dup := seen[t]; dup {
			return fmt.Errorf("domain pack %q: countermeasure %q counters %q twice", p.Name, c.ID, t)
		}
		seen[t] = struct{}{}
	}
	if len(c.NISTControls) > MaxControlsPerCountermeasure {
		return fmt.Errorf("domain pack %q: countermeasure %q maps to %d controls, over the %d cap",
			p.Name, c.ID, len(c.NISTControls), MaxControlsPerCountermeasure)
	}
	seen = make(map[string]struct{}, len(c.NISTControls))
	for _, id := range c.NISTControls {
		if err := validControlID(id); err != nil {
			return fmt.Errorf("domain pack %q: countermeasure %q: %w", p.Name, c.ID, err)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("domain pack %q: countermeasure %q maps to control %q twice", p.Name, c.ID, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// validateCountermeasureParents refuses a parent cycle. A parent chain is
// never longer than the number of countermeasures.
func (p *DomainPack) validateCountermeasureParents() error {
	parent := make(map[string]string, len(p.Countermeasures))
	for _, c := range p.Countermeasures {
		parent[c.ID] = c.Parent
	}
	for _, c := range p.Countermeasures {
		cur := c.ID
		for steps := 0; parent[cur] != ""; steps++ {
			if steps > len(parent) {
				return errors.New("domain pack " + p.Name + ": the countermeasure hierarchy has a cycle at " + c.ID)
			}
			cur = parent[cur]
		}
	}
	return nil
}

// validateNoPredicates refuses a predicate in the D3FEND pack. It keys on the
// name of the pack.
func (p *DomainPack) validateNoPredicates() error {
	if p.Name != D3FENDPackName {
		return nil
	}
	if len(p.Predicates) > 0 || len(p.NonDestructivePredicates) > 0 {
		return fmt.Errorf("domain pack %q: the pack holds taxonomy and ontology only, and no predicate", p.Name)
	}
	return nil
}
