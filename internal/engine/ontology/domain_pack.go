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

// domain_pack.go implements Domain Packs (ADR-0133, gibson#282): a portable,
// versioned bundle of ONE vertical's discovered taxonomy (promoted node
// labels / relationship types, gibson#281) and ontology (registered
// extensions: hierarchies, equivalences, IFPs, gibson#274).
//
// A Pack is structure, never a tenant's secrets or run data (ADR-0133,
// "consequences"): its fields are strictly bounded, ValidIdentifier-shaped
// taxonomy names and prefix:localname ontology triples, and Validate
// enforces that shape on every Pack this package hands out or accepts,
// whichever install produced it.
//
// Phase 2 (gibson#378, epic #376) grows a Pack with two more kinds of
// content, per ADR-0131 and ADR-0133:
//
//   - Predicates: technique -> CEL-expression bindings. ADR-0131
//     makes a Pack the SOLE binding source for a technique's settlement
//     predicate — no Go evaluator is ever registered per technique. This
//     package carries the expression as opaque, validated TEXT; it never
//     compiles or type-checks it against the gibson-owned CEL environment
//     (ADR-0131) — that is gibson#388, which runs strictly after
//     a Pack has already passed Validate here.
//   - Catalog metadata (Author, Visibility): a catalog pack carries who
//     curates it and whether it is shared or tenant-private. Every pack is
//     free — the owner withdrew the entitlement gate ADR-0133
//     once planned, so a pack carries no billing key and enabling it runs no
//     entitlement check.

// MaxPredicateExpressionBytes bounds a Predicates CEL expression string, the
// same defense-in-depth reasoning as taxonomy.MaxIdentifierBytes: a Pack is
// bounded structure, never an arbitrary payload, even before gibson#388
// compiles the expression against the CEL environment.
const MaxPredicateExpressionBytes = 4096

// MaxAuthorBytes bounds the free-text Author field.
const MaxAuthorBytes = 256

// PackVisibility is a Pack's sharing scope (ADR-0133): "public"
// names a curated catalog pack shared across tenants; "private" names a
// tenant extension, visible only to the tenant that owns it. The zero value
// means "not yet classified" and Validate accepts it, so a Pack captured
// before its metadata is assigned still round-trips.
type PackVisibility string

const (
	// PackVisibilityPublic marks a curated catalog pack (ADR-0133),
	// shared across tenants. Every catalog pack is free.
	PackVisibilityPublic PackVisibility = "public"

	// PackVisibilityPrivate marks a tenant extension (ADR-0133),
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
// target type (k8s, web, a LAN, defense, healthcare — ADR-0133), captured at
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

	// TaxonomyNodeIdentity is the written key form of each node label in this
	// pack (gibson#484): node label -> the Neo4j property its nodes are merged
	// on. It travels WITH the pack so the receiving install keys an imported
	// label exactly as the producing install did, instead of falling back to
	// the projector's generic "key" default. Without it, two installs (or two
	// producers) spell one label's key differently and split it into two nodes,
	// each holding half the truth (the gibson#1669 defect class) — now a
	// uniqueness-constraint violation under charts/hosted#486.
	//
	// A label discovered at runtime carries taxonomy.DiscoveredNodeIdentityProperty
	// (brain_id, unique by construction); a curated label names its own
	// natural key (e.g. a URL). Relationship types are edges and have no entry.
	// Import requires every node label to have one — a pack never seeds another
	// install's Cypher with an unaccounted label.
	TaxonomyNodeIdentity map[string]string `json:"taxonomy_node_identity,omitempty"`

	// Ontology is the set of registered ontology extensions this domain's
	// discovery has produced, keyed by the same extension name they were
	// registered under (e.g. gibson#274's "discovered/<proposer>/<hash>"),
	// so re-importing reproduces identical RegisterExtension calls.
	Ontology map[string]sdkgraphrag.OntologyExtension `json:"ontology,omitempty"`

	// Predicates is this pack's technique -> CEL-expression bindings
	// (ADR-0131), keyed by the technique's ValidIdentifier-shaped
	// name (ADR-0135's technique hierarchy). The value is a CEL expression,
	// evaluated at settlement time over the gibson-owned evidence
	// environment (gibson#388) — carried here as opaque text: Validate
	// checks only that it is well-formed TEXT (non-empty, valid UTF-8,
	// within MaxPredicateExpressionBytes), never that it parses or
	// type-checks as CEL.
	Predicates map[string]string `json:"predicates,omitempty"`

	// NonDestructivePredicates names the Predicates keys whose demonstration
	// changes nothing on the target (ADR-0132). The pack states this, never
	// the agent that submits a proof. A predicate this list does not name is
	// destructive: its proof settles only after a human approves it. Validate
	// requires every entry to name a Predicates key, once.
	NonDestructivePredicates []string `json:"non_destructive_predicates,omitempty"`

	// Techniques is the fine-grained techniques that this pack adds to the
	// technique hierarchy (ADR-0135): technique id -> the category that it
	// rolls up to. The core hierarchy holds the categories only, so a pack is
	// the one source of a technique. Validate requires each category to be
	// one that the core hierarchy admits. ExtendTechniques adds the entries
	// to a hierarchy through TechniqueHierarchy.WithTechnique.
	Techniques map[string]string `json:"techniques,omitempty"`

	// BeliefSchema is the belief schema extension of this pack (ADR-0129):
	// more node types that bear belief, more variables, more enablement
	// edges. An empty extension means that the pack adds none. Validate requires it to
	// register on top of the core seed. RegisterBeliefSchema registers it
	// with a registry.
	BeliefSchema BeliefSchemaExtension `json:"belief_schema,omitzero"`

	// Author identifies who curates this pack (ADR-0133): the
	// platform owner for a catalog pack, or the tenant that proposed a
	// tenant extension. Free text, never a secret — Validate only bounds
	// its length and encoding.
	Author string `json:"author,omitempty"`

	// Visibility is this pack's sharing scope (ADR-0133). See
	// [PackVisibility].
	Visibility PackVisibility `json:"visibility,omitempty"`

	// MappingRules is the compliance mapping of this pack (ADR-0133,
	// gibson#765). Each rule names one control and one CEL predicate over
	// one audit event. An audit event that matches the predicate is
	// evidence for the control. It is never a verdict about the control.
	//
	// The expression is text here, as for Predicates. Validate checks the
	// shape of each rule. The package internal/engine/settlement/auditcel
	// compiles the expressions against the audit event environment.
	MappingRules []MappingRule `json:"mapping_rules,omitempty"`
}

// MappingRule maps audit events onto one control of a framework.
type MappingRule struct {
	// ControlID is the id of the control in its framework, for example
	// "ac-2" or "ac-2.4" for NIST SP 800-53 rev 5.
	ControlID string `json:"control_id"`
	// Expression is a CEL predicate over the variable "event".
	Expression string `json:"expression"`
}

// MaxControlIDBytes bounds the ControlID of a mapping rule.
const MaxControlIDBytes = 64

// validControlID reports whether id is a plain control id: 1 to
// MaxControlIDBytes ASCII letters, digits and the characters ".", "-", "_",
// "(" and ")".
func validControlID(id string) error {
	if id == "" {
		return errors.New("control id must not be empty")
	}
	if len(id) > MaxControlIDBytes {
		return fmt.Errorf("control id is %d bytes, over the %d-byte cap", len(id), MaxControlIDBytes)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_', r == '(', r == ')':
		default:
			return fmt.Errorf("control id %q has the character %q", id, r)
		}
	}
	return nil
}

// validateMappingRules checks the shape of each mapping rule: a plain
// control id, at most one rule for each control, and well-formed expression
// text. A rule that needs two conditions uses one expression with "||".
func (p *DomainPack) validateMappingRules() error {
	seen := make(map[string]struct{}, len(p.MappingRules))
	for i, rule := range p.MappingRules {
		if err := validControlID(rule.ControlID); err != nil {
			return fmt.Errorf("domain pack %q: mapping rule %d: %w", p.Name, i, err)
		}
		if _, dup := seen[rule.ControlID]; dup {
			return fmt.Errorf("domain pack %q: control %q has more than one mapping rule", p.Name, rule.ControlID)
		}
		seen[rule.ControlID] = struct{}{}
		if err := validPredicateExpressionText(rule.Expression); err != nil {
			return fmt.Errorf("domain pack %q: mapping rule for control %q: %w", p.Name, rule.ControlID, err)
		}
	}
	return nil
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
	nodeLabels := diffSorted(taxonomyNow.NodeLabels(), taxonomyBase.NodeLabels())
	pack := &DomainPack{
		Name:                      name,
		Version:                   version,
		TaxonomyNodeLabels:        nodeLabels,
		TaxonomyRelationshipTypes: diffSorted(taxonomyNow.RelationshipTypes(), taxonomyBase.RelationshipTypes()),
	}

	// Every captured node label carries its written key form (gibson#484).
	// A label captured from runtime discovery is identified the way the
	// PromotionGate assigned it: DiscoveredNodeIdentityProperty (unique by
	// construction). Export populates it here so the pack is accounted-for and
	// Import never refuses what this platform produced.
	if len(nodeLabels) > 0 {
		pack.TaxonomyNodeIdentity = make(map[string]string, len(nodeLabels))
		for _, l := range nodeLabels {
			pack.TaxonomyNodeIdentity[l] = taxonomy.DiscoveredNodeIdentityProperty
		}
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
// secrets or unvalidated payload (ADR-0133, gibson#282 acceptance
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
//     every value is well-formed CEL-expression TEXT (ADR-0131)
//     — non-empty, valid UTF-8, within MaxPredicateExpressionBytes; this
//     never parses or type-checks the expression as CEL (gibson#388's job);
//   - every Techniques entry is a plain identifier that rolls up to a
//     category of the core technique hierarchy (ADR-0135);
//   - BeliefSchema, when present, registers on top of the core belief
//     schema seed (ADR-0129);
//   - every NonDestructivePredicates entry names a Predicates key, once;
//   - Author is valid UTF-8 within MaxAuthorBytes, and Visibility is one of
//     the recognized [PackVisibility] values;
//   - every TaxonomyNodeIdentity entry (gibson#484) names a node label the
//     pack declares and a safe-identifier key-form property. Import, not
//     Validate, is where a node label is REQUIRED to carry one.
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
	if err := p.validateNodeIdentity(); err != nil {
		return err
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
	if _, err := p.ExtendTechniques(taxonomy.GlobalTechniques); err != nil {
		return err
	}
	if err := p.validateBeliefSchema(); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(p.NonDestructivePredicates))
	for _, technique := range p.NonDestructivePredicates {
		if _, ok := p.Predicates[technique]; !ok {
			return fmt.Errorf("domain pack %q: non-destructive predicate %q is not a predicate of this pack", p.Name, technique)
		}
		if _, dup := seen[technique]; dup {
			return fmt.Errorf("domain pack %q: non-destructive predicate %q is listed twice", p.Name, technique)
		}
		seen[technique] = struct{}{}
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
	return p.validateMappingRules()
}

// beliefSchemaExtensionName is the name under which the belief schema of a
// pack is registered. One name for each pack, so two packs do not collide.
func (p *DomainPack) beliefSchemaExtensionName() string {
	return "pack/" + p.Name + "/belief-schema"
}

// ExtendTechniques returns base with each technique of this pack added,
// each one through TechniqueHierarchy.WithTechnique. base is not changed. A
// pack with no technique returns base.
//
// It fails when a technique id or a category id is not a plain identifier,
// when base does not admit the category, or when base already holds the
// technique. The techniques are added in sorted order, so the first error
// is the same on each run.
func (p *DomainPack) ExtendTechniques(base *taxonomy.TechniqueHierarchy) (*taxonomy.TechniqueHierarchy, error) {
	techniques := make([]string, 0, len(p.Techniques))
	for technique := range p.Techniques {
		techniques = append(techniques, technique)
	}
	slices.Sort(techniques)

	out := base
	for _, technique := range techniques {
		next, err := out.WithTechnique(taxonomy.TechniqueID(technique), taxonomy.CategoryID(p.Techniques[technique]))
		if err != nil {
			return nil, fmt.Errorf("domain pack %q: technique: %w", p.Name, err)
		}
		out = next
	}
	return out, nil
}

// RegisterBeliefSchema registers the belief schema extension of this pack
// with reg, under a name of its own. A pack with no extension registers
// nothing. The registry runs its own checks: a duplicate variable, an
// unknown dependency, a cycle, or an enablement edge that conflicts with
// one that reg already holds fails the call and leaves reg unchanged.
func (p *DomainPack) RegisterBeliefSchema(reg *BeliefSchemaRegistry) error {
	if p.BeliefSchema.empty() {
		return nil
	}
	if err := reg.RegisterExtension(p.beliefSchemaExtensionName(), p.BeliefSchema); err != nil {
		return fmt.Errorf("domain pack %q: belief schema: %w", p.Name, err)
	}
	return nil
}

// validateBeliefSchema proves that the belief schema extension of the pack
// registers on top of the core seed, which each install has.
func (p *DomainPack) validateBeliefSchema() error {
	if p.BeliefSchema.empty() {
		return nil
	}
	reg := NewBeliefSchemaRegistry()
	if err := RegisterCoreBeliefSchemaSeed(reg); err != nil {
		return fmt.Errorf("domain pack %q: core belief schema seed: %w", p.Name, err)
	}
	return p.RegisterBeliefSchema(reg)
}

// validateNodeIdentity checks the written key forms a pack carries
// (gibson#484). It is lenient on PRESENCE — a pack may name identities for
// some, all, or none of its node labels — but strict on CONTENT: every entry
// must name a node label this pack actually declares (no stray keys), and every
// key-form property must be a safe, non-empty identifier (never a backtick
// injection, never a secret, which taxonomy.ValidIdentifier's rules exclude).
// Import, not Validate, is where a node label is REQUIRED to have an entry — a
// pack can be captured incrementally, but it cannot seed another install until
// every label it would add is accounted for (requireNodeIdentityAccounted).
func (p *DomainPack) validateNodeIdentity() error {
	if len(p.TaxonomyNodeIdentity) == 0 {
		return nil
	}
	labels := make(map[string]struct{}, len(p.TaxonomyNodeLabels))
	for _, l := range p.TaxonomyNodeLabels {
		labels[l] = struct{}{}
	}
	for label, prop := range p.TaxonomyNodeIdentity {
		if _, ok := labels[label]; !ok {
			return fmt.Errorf("domain pack %q: node identity names %q, which is not one of the pack's node labels", p.Name, label)
		}
		if err := taxonomy.ValidIdentifier(prop); err != nil {
			return fmt.Errorf("domain pack %q: node identity property for %q: %w", p.Name, label, err)
		}
	}
	return nil
}

// requireNodeIdentityAccounted reports the first node label that carries no
// written key form (gibson#484). Import calls it so a pack never seeds another
// install's Cypher with a label whose identity is unwritten — the exact
// condition that lets two producers split one label into two nodes (gibson#1669,
// now a uniqueness-constraint violation under charts/hosted#486).
func (p *DomainPack) requireNodeIdentityAccounted() error {
	for _, label := range p.TaxonomyNodeLabels {
		if _, ok := p.TaxonomyNodeIdentity[label]; !ok {
			return fmt.Errorf(
				"domain pack %q: node label %q has no written key form; a pack cannot seed an "+
					"environment with an unaccounted label (gibson#484)", p.Name, label)
		}
	}
	return nil
}

// validPredicateExpressionText reports whether expr is well-formed TEXT for
// a Predicates CEL expression (ADR-0131): non-empty after
// trimming, valid UTF-8, and within MaxPredicateExpressionBytes. It never
// parses or compiles expr as CEL — that is gibson#388's job, run strictly
// after a Pack has already passed this check, against the gibson-owned CEL
// environment (ADR-0131). A Pack that fails only this check is
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
// Import re-validates p first (Validate), then requires every node label to
// carry a written key form (requireNodeIdentityAccounted, gibson#484) so the
// receiving install keys it exactly as the producing install did. It then
// registers every bundled
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
	if err := p.requireNodeIdentityAccounted(); err != nil {
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
