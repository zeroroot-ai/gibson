// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"fmt"
	"slices"

	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// domain_pack.go implements Domain Packs (ADR-0025, gibson#282): a portable,
// versioned bundle of ONE vertical's discovered taxonomy (promoted node
// labels / relationship types, gibson#281) and ontology (registered
// extensions: hierarchies, equivalences, IFPs, gibson#274).
//
// A Pack is structure, never a tenant's secrets or run data (ADR-0025 §1,
// "consequences"): its fields are strictly bounded, ValidIdentifier-shaped
// taxonomy names and prefix:localname ontology triples, and Validate
// enforces that shape on every Pack this package hands out or accepts,
// whichever install produced it.

// DomainPack is the discovered taxonomy and ontology for one vertical or
// target type (k8s, web, a LAN, defense, healthcare — ADR-0025), captured at
// a point in time.
type DomainPack struct {
	// Name identifies the vertical, e.g. "k8s", "healthcare".
	Name string `json:"name"`

	// Version is bumped every time the Pack's content changes — exported
	// content is always attributed to a specific version, so replaying an
	// import is unambiguous about what was seeded.
	Version int `json:"version"`

	// TaxonomyNodeLabels and TaxonomyRelationshipTypes are the node labels
	// and relationship types this domain's discovery has promoted ON TOP OF
	// the platform's own core Taxonomy (taxonomy.Global). Importing a Pack
	// layers these onto the receiving install's own core, never replacing
	// it — see Import.
	TaxonomyNodeLabels        []string `json:"taxonomy_node_labels,omitempty"`
	TaxonomyRelationshipTypes []string `json:"taxonomy_relationship_types,omitempty"`

	// Ontology is the set of registered ontology extensions this domain's
	// discovery has produced, keyed by the same extension name they were
	// registered under (e.g. gibson#274's "discovered/<proposer>/<hash>"),
	// so re-importing reproduces identical RegisterExtension calls.
	Ontology map[string]sdkgraphrag.OntologyExtension `json:"ontology,omitempty"`
}

// ExportDomainPack captures name's currently discovered structure:
//   - every node label / relationship type in taxonomyNow that
//     taxonomyBase does not already admit — the vertical-specific
//     promotions gibson#281's PromotionGate produced on top of the
//     platform's own core Taxonomy;
//   - every extension currently registered in reasoner, except the ones
//     named in excludeOntologyExtensions (the platform's own shared core,
//     common to every vertical — e.g. the "core/..." names
//     ontology.Loader.LoadCore registers).
//
// The result is validated (Validate) before it is returned, so
// ExportDomainPack fails closed — rather than silently dropping content —
// if reasoner holds an extension carrying RawTriples that the caller did not
// exclude: a Pack never ships unvalidated raw payload (see Validate).
func ExportDomainPack(name string, version int, taxonomyBase, taxonomyNow *taxonomy.Registry, reasoner *Reasoner, excludeOntologyExtensions ...string) (*DomainPack, error) {
	pack := &DomainPack{
		Name:                      name,
		Version:                   version,
		TaxonomyNodeLabels:        diffSorted(taxonomyNow.NodeLabels(), taxonomyBase.NodeLabels()),
		TaxonomyRelationshipTypes: diffSorted(taxonomyNow.RelationshipTypes(), taxonomyBase.RelationshipTypes()),
	}

	exclude := make(map[string]struct{}, len(excludeOntologyExtensions))
	for _, n := range excludeOntologyExtensions {
		exclude[n] = struct{}{}
	}
	all := reasoner.Extensions()
	if len(all) > 0 {
		pack.Ontology = make(map[string]sdkgraphrag.OntologyExtension, len(all))
		for n, ext := range all {
			if _, skip := exclude[n]; skip {
				continue
			}
			pack.Ontology[n] = ext
		}
	}

	if err := pack.Validate(); err != nil {
		return nil, fmt.Errorf("ontology: export domain pack %q: %w", name, err)
	}
	return pack, nil
}

// Validate reports whether p carries only structure — never a tenant's
// secrets or unvalidated payload (ADR-0025 §1, gibson#282 acceptance
// criterion 3):
//   - every taxonomy label/relationship type is a plain, bounded
//     ValidIdentifier (structurally incapable of holding an API key, a
//     token, or free-form secret text: those contain characters
//     ValidIdentifier's ASCII-letter/digit/underscore rule refuses, or
//     exceed taxonomy.MaxIdentifierBytes);
//   - no bundled ontology extension carries RawTriples — the one
//     OntologyExtension field that is never subject to prefix/cycle
//     validation, so a Pack never ships that unvalidated a payload.
func (p *DomainPack) Validate() error {
	for _, l := range p.TaxonomyNodeLabels {
		if err := taxonomy.ValidIdentifier(l); err != nil {
			return fmt.Errorf("domain pack %q: taxonomy node label: %w", p.Name, err)
		}
	}
	for _, r := range p.TaxonomyRelationshipTypes {
		if err := taxonomy.ValidIdentifier(r); err != nil {
			return fmt.Errorf("domain pack %q: taxonomy relationship type: %w", p.Name, err)
		}
	}
	for extName, ext := range p.Ontology {
		if len(ext.RawTriples) > 0 {
			return fmt.Errorf(
				"domain pack %q: ontology extension %q carries RawTriples; "+
					"a Pack ships only structured, validated triples (Hierarchies/Equivalences/IFPs), "+
					"never raw unvalidated payload",
				p.Name, extName,
			)
		}
	}
	return nil
}

// Import applies p onto taxonomyBase and reasoner, seeding a new environment
// (or extending one an earlier Pack version already seeded — gibson#282
// acceptance criterion 4). It returns the resulting taxonomy Registry;
// reasoner is mutated in place, the same way RegisterExtension always works.
//
// Import re-validates p first (Validate), then registers every bundled
// ontology extension through reasoner.RegisterExtension — so the SAME cycle
// and unknown-prefix checks that gated the content at discovery time on the
// exporting install gate it again at import time on the receiving one; a
// Pack never bypasses that seam. Taxonomy labels/relationship types already
// admitted by taxonomyBase (e.g. a re-import, or two overlapping Packs) are
// skipped rather than erroring, so Import is idempotent.
func (p *DomainPack) Import(taxonomyBase *taxonomy.Registry, reasoner *Reasoner) (*taxonomy.Registry, error) {
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("ontology: import domain pack %q: %w", p.Name, err)
	}

	for name, ext := range p.Ontology {
		if err := reasoner.RegisterExtension(name, ext); err != nil {
			return nil, fmt.Errorf("ontology: import domain pack %q: ontology extension %q: %w", p.Name, name, err)
		}
	}

	nodes := unionNew(taxonomyBase.NodeLabels(), p.TaxonomyNodeLabels)
	rels := unionNew(taxonomyBase.RelationshipTypes(), p.TaxonomyRelationshipTypes)
	imported, err := taxonomy.New(taxonomyBase.Version()+1, nodes, rels)
	if err != nil {
		return nil, fmt.Errorf("ontology: import domain pack %q: taxonomy: %w", p.Name, err)
	}
	return imported, nil
}

// diffSorted returns the elements of now not present in base, sorted. Both
// inputs are already sorted (Registry.NodeLabels/RelationshipTypes),
// preserved here as an explicit contract rather than an assumption.
func diffSorted(now, base []string) []string {
	baseSet := make(map[string]struct{}, len(base))
	for _, b := range base {
		baseSet[b] = struct{}{}
	}
	var out []string
	for _, n := range now {
		if _, ok := baseSet[n]; !ok {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// unionNew appends every element of add not already present in base,
// preserving base's order and skipping duplicates so the result never
// contains the same label twice (taxonomy.New rejects duplicates).
func unionNew(base, add []string) []string {
	seen := make(map[string]struct{}, len(base))
	for _, b := range base {
		seen[b] = struct{}{}
	}
	out := slices.Clone(base)
	for _, a := range add {
		if _, ok := seen[a]; ok {
			continue
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	return out
}
