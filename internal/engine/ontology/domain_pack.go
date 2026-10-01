// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

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
//
// Phase 2 (gibson#378, epic #376) grows a Pack with two more kinds of
// content, per ADR-0031 and ADR-0033:
//
//   - Predicates: technique -> CEL-expression bindings. ADR-0031 decision 1
//     makes a Pack the SOLE binding source for a technique's settlement
//     predicate — no Go evaluator is ever registered per technique. This
//     package carries the expression as opaque, validated TEXT; it never
//     compiles or type-checks it against the gibson-owned CEL environment
//     (ADR-0031 decision 2) — that is gibson#388, which runs strictly after
//     a Pack has already passed Validate here.
//   - Catalog metadata (Author, Visibility): a catalog pack carries who
//     curates it and whether it is shared or tenant-private. Every pack is
//     free — the owner withdrew the entitlement gate ADR-0033 decision 5
//     once planned, so a pack carries no billing key and enabling it runs no
//     entitlement check.

// MaxPredicateExpressionBytes bounds a Predicates CEL expression string, the
// same defense-in-depth reasoning as taxonomy.MaxIdentifierBytes: a Pack is
// bounded structure, never an arbitrary payload, even before gibson#388
// compiles the expression against the CEL environment.
const MaxPredicateExpressionBytes = 4096

// MaxAuthorBytes bounds the free-text Author field.
const MaxAuthorBytes = 256

// PackVisibility is a Pack's sharing scope (ADR-0033 decision 1): "public"
// names a curated catalog pack shared across tenants; "private" names a
// tenant extension, visible only to the tenant that owns it. The zero value
// means "not yet classified" and Validate accepts it, so a Pack captured
// before its metadata is assigned still round-trips.
type PackVisibility string

const (
	// PackVisibilityPublic marks a curated catalog pack (ADR-0033 decision
	// 1), shared across tenants. Every catalog pack is free.
	PackVisibilityPublic PackVisibility = "public"

	// PackVisibilityPrivate marks a tenant extension (ADR-0033 decision 1),
	// live in one tenant only.
	PackVisibilityPrivate PackVisibility = "private"
)

// Validate reports whether v is a recognized visibility: empty (not yet
// classified), "public", or "private". Any other value is rejected —
// Visibility is a closed set, never free text, so a typo can never silently
// leave a pack un-gated.
func (v PackVisibility) Validate() error {
	switch v {
	case "", PackVisibilityPublic, PackVisibilityPrivate:
		return nil
	default:
		return fmt.Errorf("visibility %q: must be %q, %q, or empty", v, PackVisibilityPublic, PackVisibilityPrivate)
	}
}

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

	// Predicates is this pack's technique -> CEL-expression bindings
	// (ADR-0031 decision 1), keyed by the technique's ValidIdentifier-shaped
	// name (ADR-0035's technique hierarchy). The value is a CEL expression,
	// evaluated at settlement time over the gibson-owned evidence
	// environment (gibson#388) — carried here as opaque text: Validate
	// checks only that it is well-formed TEXT (non-empty, valid UTF-8,
	// within MaxPredicateExpressionBytes), never that it parses or
	// type-checks as CEL.
	Predicates map[string]string `json:"predicates,omitempty"`

	// Author identifies who curates this pack (ADR-0033 decision 5): the
	// platform owner for a catalog pack, or the tenant that proposed a
	// tenant extension. Free text, never a secret — Validate only bounds
	// its length and encoding.
	Author string `json:"author,omitempty"`

	// Visibility is this pack's sharing scope (ADR-0033 decision 1). See
	// [PackVisibility].
	Visibility PackVisibility `json:"visibility,omitempty"`
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
//     validation, so a Pack never ships that unvalidated a payload;
//   - every Predicates key is a plain ValidIdentifier technique name, and
//     every value is well-formed CEL-expression TEXT (ADR-0031 decision 1)
//     — non-empty, valid UTF-8, within MaxPredicateExpressionBytes; this
//     never parses or type-checks the expression as CEL (gibson#388's job);
//   - Author is valid UTF-8 within MaxAuthorBytes, and Visibility is one of
//     the recognized [PackVisibility] values.
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
	for technique, expr := range p.Predicates {
		if err := taxonomy.ValidIdentifier(technique); err != nil {
			return fmt.Errorf("domain pack %q: predicate technique: %w", p.Name, err)
		}
		if err := validPredicateExpressionText(expr); err != nil {
			return fmt.Errorf("domain pack %q: predicate for technique %q: %w", p.Name, technique, err)
		}
	}
	if !utf8.ValidString(p.Author) {
		return fmt.Errorf("domain pack %q: author must be valid UTF-8", p.Name)
	}
	if len(p.Author) > MaxAuthorBytes {
		return fmt.Errorf("domain pack %q: author is %d bytes, over the %d-byte cap", p.Name, len(p.Author), MaxAuthorBytes)
	}
	if err := p.Visibility.Validate(); err != nil {
		return fmt.Errorf("domain pack %q: %w", p.Name, err)
	}
	return nil
}

// validPredicateExpressionText reports whether expr is well-formed TEXT for
// a Predicates CEL expression (ADR-0031 decision 1): non-empty after
// trimming, valid UTF-8, and within MaxPredicateExpressionBytes. It never
// parses or compiles expr as CEL — that is gibson#388's job, run strictly
// after a Pack has already passed this check, against the gibson-owned CEL
// environment (ADR-0031 decision 2). A Pack that fails only this check is
// malformed data; a Pack that passes it but references a field or helper
// outside the environment is merely out-of-environment, and gibson#388
// rejects that separately at load time.
func validPredicateExpressionText(expr string) error {
	if strings.TrimSpace(expr) == "" {
		return errors.New("predicate expression must not be empty")
	}
	if !utf8.ValidString(expr) {
		return errors.New("predicate expression must be valid UTF-8")
	}
	if len(expr) > MaxPredicateExpressionBytes {
		return fmt.Errorf("predicate expression is %d bytes, over the %d-byte cap", len(expr), MaxPredicateExpressionBytes)
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
