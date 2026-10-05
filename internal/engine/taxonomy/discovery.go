// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package taxonomy

import (
	"fmt"
	"log/slog"
	"sync"
)

// discovery.go implements taxonomy discovery (ADR-0124, gibson#281): a
// fleet-proposed label lives as data — an Observation, per the package's
// existing ClassifyNode/ClassifyRelationship fallback — until it is promoted
// to actual Cypher query structure (a new Taxonomy Registry version). This
// supersedes the package doc's older rule that promotion is a reviewed code
// change to this file, replacing it with an automated safety gate plus
// settlement:
//
//   - Recording a sighting (Observe) is always safe, regardless of content,
//     because it never becomes structure — it is data the caller may choose
//     to log as an Observation node, same as any other out-of-taxonomy shape.
//   - Promoting a sighting into the Taxonomy (Promote) is gated on BOTH an
//     automated safety check (ValidIdentifier — completely non-negotiable,
//     a human reviewer cannot override it) and settlement: the SAME proposal
//     recurring at least MinRecurrenceForSettlement times (recurrence is
//     signal, not noise — the same principle brain.Hypothesis's
//     (ScopeID, Claim) identity already encodes for target-fact claims) PLUS
//     an explicit human (HITL) confirmation.
//
// PromotionGate is the only way this package hands back a Registry that
// admits a label it did not start with — there is no exported shortcut that
// constructs one from an unvalidated string, so "nothing unvalidated ever
// reaches Cypher" holds by construction, not by caller discipline.

// ProposalKind distinguishes a proposed node label from a proposed
// relationship type — the Taxonomy's own two vocabularies.
type ProposalKind int

const (
	// ProposedNodeLabel is a fleet-proposed Neo4j node label.
	ProposedNodeLabel ProposalKind = iota
	// ProposedRelationshipType is a fleet-proposed Neo4j relationship type.
	ProposedRelationshipType
)

// String renders k for error messages and the promotion log.
func (k ProposalKind) String() string {
	switch k {
	case ProposedNodeLabel:
		return "node_label"
	case ProposedRelationshipType:
		return "relationship_type"
	default:
		return "unknown"
	}
}

// MinRecurrenceForSettlement is how many independent sightings of the same
// proposed label are required before it can settle (ADR-0124).
const MinRecurrenceForSettlement = 3

// DiscoveredNodeIdentityProperty is the Neo4j node property a runtime-promoted
// node label is identified by (gibson#484). A label discovered at runtime has
// no human-authored natural key, so the gate assigns the one identity that is
// unique BY CONSTRUCTION: brain_id, the World entity id — the same property the
// graph projector's first-class entities (Host, Finding, ...) already merge on.
//
// Mandating one identity for every discovered label is what makes discovery
// collision-safe: two producers of the same label merge on the same property
// instead of each creating a second node that wears the label and holds half
// the truth (the gibson#1669 defect class), and the per-label uniqueness
// constraint (charts/hosted#486) is satisfied rather than violated. The
// collision-prone alternative — the projector's generic "key" default — is
// exactly the unwritten key form gibson#484 forbids: a bare key repeats across
// producers.
const DiscoveredNodeIdentityProperty = "brain_id"

// PromotedIdentityProperty reports the written key form a promotion of kind
// assigns (gibson#484):
//   - a node label is identified by DiscoveredNodeIdentityProperty;
//   - a relationship type is an edge — it has no node identity of its own, so
//     its key form is "" (accounted for as "not applicable", never "unwritten").
//
// PromotionGate.Promote records this on every PromotionRecord, so the promotion
// log carries not just WHICH label was promoted but HOW it is identified. A new
// ProposalKind added without a case here hands back "" for a node-bearing kind,
// which TestPromotedIdentityProperty_AccountsForEveryKind fails on.
func PromotedIdentityProperty(kind ProposalKind) string {
	switch kind {
	case ProposedNodeLabel:
		return DiscoveredNodeIdentityProperty
	case ProposedRelationshipType:
		// An edge carries no node identity of its own.
		return ""
	default:
		return ""
	}
}

// promotedIdentities is the process-wide registry of runtime-promoted node
// labels and their written key form (gibson#484), plus the OnPromote hooks.
//
// It is package-global on purpose. A promoted node label's identity is
// deterministic (DiscoveredNodeIdentityProperty) and does not vary by tenant,
// and the graph projector resolves it on EVERY entity write — a hot path that
// must not hold a PromotionGate or allocate. A single guarded map answers that
// in one read. PromotionGate.Promote is the only writer.
var promotedIdentities = struct {
	mu       sync.RWMutex
	identity map[string]string
	hooks    []func(label string)
}{identity: make(map[string]string)}

// IdentityProperty reports the property a runtime-promoted label is identified
// by (gibson#484). ok is false for a label that was never promoted. The graph
// projector calls this on every entity write to resolve an imported or
// discovered node label's Neo4j merge/constraint property (brain_id) from the
// authoritative promotion record, instead of re-deriving it. It is safe for
// concurrent reads while a promotion writes.
func IdentityProperty(label string) (prop string, ok bool) {
	promotedIdentities.mu.RLock()
	defer promotedIdentities.mu.RUnlock()
	prop, ok = promotedIdentities.identity[label]
	return prop, ok
}

// OnPromote registers fn to be called with the label of every node label that
// is subsequently promoted (gibson#484). It is the event seam the graph
// projector uses to invalidate its per-tenant constraint tracker and re-ensure
// the uniqueness constraint on the next tick. fn runs synchronously inside
// Promote, after the label is recorded, holding no lock — fn may itself call
// IdentityProperty. Relationship-type promotions do not fire it: an edge has no
// node identity and so no node uniqueness constraint. Registration is additive
// and process-wide; register once (not per tenant).
func OnPromote(fn func(label string)) {
	promotedIdentities.mu.Lock()
	defer promotedIdentities.mu.Unlock()
	promotedIdentities.hooks = append(promotedIdentities.hooks, fn)
}

// recordPromotion writes label's key form into the global registry and fires
// the OnPromote hooks (gibson#484). PromotionGate.Promote calls it for a node
// label after the promotion succeeds. Hooks fire without the lock held, so a
// hook may read back through IdentityProperty without deadlocking.
func recordPromotion(label, prop string) {
	promotedIdentities.mu.Lock()
	promotedIdentities.identity[label] = prop
	hooks := make([]func(label string), len(promotedIdentities.hooks))
	copy(hooks, promotedIdentities.hooks)
	promotedIdentities.mu.Unlock()
	for _, fn := range hooks {
		fn(label)
	}
}

// A promotion is always visible in the logs (gibson#484). External subscribers
// (the graph projector's constraint re-ensure) add their own via OnPromote;
// this default observer is registered once, from package init, so OnPromote has
// a reachable registrant and every promotion is observable out of the box.
func init() {
	OnPromote(func(label string) {
		slog.Info("taxonomy node label promoted",
			"label", label,
			"identity_property", DiscoveredNodeIdentityProperty)
	})
}

// InvalidProposalError is returned by Confirm and Promote when a proposed
// label fails the automated ValidIdentifier safety check. It is always
// returned regardless of recurrence or confirmation status — the automated
// check is not something settlement can outvote.
type InvalidProposalError struct {
	Kind  ProposalKind
	Label string
	Err   error
}

func (e *InvalidProposalError) Error() string {
	return fmt.Sprintf("taxonomy: proposed %s %q fails the safety gate: %v", e.Kind, e.Label, e.Err)
}

func (e *InvalidProposalError) Unwrap() error { return e.Err }

// NotSettledError is returned by Promote when a proposal has not yet met
// both halves of settlement: enough recurrence, and a HITL confirmation.
type NotSettledError struct {
	Kind       ProposalKind
	Label      string
	Recurrence int
	Confirmed  bool
}

func (e *NotSettledError) Error() string {
	return fmt.Sprintf(
		"taxonomy: proposed %s %q has not settled: recurrence=%d (need %d), confirmed=%v",
		e.Kind, e.Label, e.Recurrence, MinRecurrenceForSettlement, e.Confirmed,
	)
}

// proposalKey identifies one proposed label independent of how many times it
// has been sighted.
type proposalKey struct {
	kind  ProposalKind
	label string
}

// PromotionRecord is one completed promotion, kept so the sequence of
// promotions is replayable (gibson#281 acceptance criterion 4): a fresh
// PromotionGate fed the identical sequence of Observe/Confirm/Promote calls
// against the same base Registry reproduces an identical resulting Registry
// and an identical promotion log.
type PromotionRecord struct {
	Kind    ProposalKind
	Label   string
	Version int

	// IdentityProperty is the written key form the gate assigned this label at
	// promotion (gibson#484). For a node label it is
	// DiscoveredNodeIdentityProperty; for a relationship type it is "" (an edge
	// carries no node identity). It is recorded here, not re-derived, so the
	// replay log is self-describing: a reader of Promotions() knows how every
	// promoted label is identified without consulting the gate's code.
	IdentityProperty string
}

// PromotionGate is the taxonomy-discovery safety gate (ADR-0124). A
// fleet-proposed label is held as data — recurrence-tracked, never Cypher
// structure — until it passes BOTH the automated ValidIdentifier safety
// check and settlement (recurrence + an explicit HITL confirmation).
//
// Thread safety: all public methods are safe for concurrent use.
type PromotionGate struct {
	mu sync.Mutex

	base       *Registry
	recurrence map[proposalKey]int
	confirmed  map[proposalKey]string // reviewer, once confirmed
	promotions []PromotionRecord
}

// NewPromotionGate constructs a PromotionGate over base. base is never
// mutated; each successful Promote produces a new *Registry that becomes the
// gate's new Base() for any further promotion.
func NewPromotionGate(base *Registry) *PromotionGate {
	return &PromotionGate{
		base:       base,
		recurrence: make(map[proposalKey]int),
		confirmed:  make(map[proposalKey]string),
	}
}

// Base returns the gate's current Registry: the original base, plus every
// label Promote has accepted so far.
func (g *PromotionGate) Base() *Registry {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.base
}

// Observe records one sighting of a proposed label and returns its
// recurrence count so far. This is always safe regardless of label content —
// it is data, never Cypher structure — so Observe never rejects anything;
// only Promote enforces safety.
func (g *PromotionGate) Observe(kind ProposalKind, label string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := proposalKey{kind: kind, label: label}
	g.recurrence[key]++
	return g.recurrence[key]
}

// Confirm records a human reviewer's HITL approval of a proposed label — the
// second half of settlement, alongside recurrence (Observe). Confirm itself
// fails closed with an *InvalidProposalError if label does not pass
// ValidIdentifier: a human cannot approve past the automated safety check,
// so a confirmation is never recorded for a label that could not be promoted
// anyway.
func (g *PromotionGate) Confirm(kind ProposalKind, label, reviewer string) error {
	if err := ValidIdentifier(label); err != nil {
		return &InvalidProposalError{Kind: kind, Label: label, Err: err}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.confirmed[proposalKey{kind: kind, label: label}] = reviewer
	return nil
}

// Promote attempts to promote a proposed label into a new Taxonomy Registry
// version. It refuses unless ALL of:
//   - label passes ValidIdentifier (automated safety, checked independently
//     of whatever Confirm already checked — non-negotiable);
//   - it has recurred at least MinRecurrenceForSettlement times (Observe);
//   - a reviewer has Confirmed it (HITL).
//
// On success, Promote returns a new *Registry (version = current base
// version + 1) admitting the label, records the promotion (Promotions())
// together with its assigned key form (PromotedIdentityProperty, gibson#484),
// and that Registry becomes the gate's new Base() so a second promotion
// compounds on top of the first. On any failure, the gate and its Base() are
// unchanged, and the label never reaches the Taxonomy through this path.
func (g *PromotionGate) Promote(kind ProposalKind, label string) (*Registry, error) {
	if err := ValidIdentifier(label); err != nil {
		return nil, &InvalidProposalError{Kind: kind, Label: label, Err: err}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	key := proposalKey{kind: kind, label: label}
	recurrence := g.recurrence[key]
	reviewer, confirmed := g.confirmed[key]
	if recurrence < MinRecurrenceForSettlement || !confirmed {
		return nil, &NotSettledError{Kind: kind, Label: label, Recurrence: recurrence, Confirmed: confirmed}
	}

	promoted, err := promotedRegistry(g.base, kind, label)
	if err != nil {
		return nil, fmt.Errorf("taxonomy: promote %s %q (confirmed by %s): %w", kind, label, reviewer, err)
	}

	identity := PromotedIdentityProperty(kind)
	g.base = promoted
	g.promotions = append(g.promotions, PromotionRecord{
		Kind:             kind,
		Label:            label,
		Version:          promoted.Version(),
		IdentityProperty: identity,
	})
	// Publish a node label's key form to the process-wide registry and notify
	// subscribers (gibson#484). Relationship types carry no node identity, so
	// they are not published and do not fire OnPromote.
	if identity != "" {
		recordPromotion(label, identity)
	}
	return promoted, nil
}

// Promotions returns every completed promotion, in the order Promote
// accepted them — the replay log (acceptance criterion 4). The returned
// slice is a defensive copy.
func (g *PromotionGate) Promotions() []PromotionRecord {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]PromotionRecord, len(g.promotions))
	copy(out, g.promotions)
	return out
}

// promotedRegistry builds a new Registry with label added to the vocabulary
// kind names, versioned one past base. It reuses New's own validation
// (ValidIdentifier + duplicate check) as a second, independent line of
// defense: even if every check above this function were somehow bypassed,
// New itself still refuses an unsafe or duplicate identifier.
func promotedRegistry(base *Registry, kind ProposalKind, label string) (*Registry, error) {
	nodes := base.NodeLabels()
	rels := base.RelationshipTypes()
	switch kind {
	case ProposedNodeLabel:
		nodes = append(nodes, label)
	case ProposedRelationshipType:
		rels = append(rels, label)
	default:
		return nil, fmt.Errorf("taxonomy: unknown proposal kind %v", kind)
	}
	return New(base.Version()+1, nodes, rels)
}
