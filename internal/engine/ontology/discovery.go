// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package ontology

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// discovery.go implements ontology discovery (ADR-0124, gibson#274): the
// fleet proposes new classes, relationships (equivalences), and
// identifying-properties at runtime as structural hypotheses, registered
// through the existing Reasoner.RegisterExtension seam.
//
// ADR-0124 makes this explicitly DATA-LEVEL with a LIGHT gate: unlike
// taxonomy discovery (§2, gibson#281), a proposed ontology IRI never becomes
// Cypher query structure — it stays a prefix:localname string the Reasoner
// reasons over — so RegisterExtension's existing cycle and unknown-prefix
// validation IS the acceptance gate. There is no separate promotion review or
// HITL step here.
//
// A StructuralHypothesis is a claim about the ONTOLOGY SCHEMA itself (a new
// class belongs under this parent, this identifying property distinguishes
// nodes of this type, ...), which is a different kind of claim from
// internal/engine/brain.Hypothesis (a claim about a TARGET, e.g. "port 6443
// is unauthenticated"). The two intentionally do not share a Go type: folding
// a target-fact claim into the World's Evidence/Belief/Hypothesis provenance
// classes is brain's concern; reasoning over ontology vocabulary is this
// package's concern; ADR-0129 already draws exactly this line between the
// two engines. StructuralHypothesis mirrors brain.Hypothesis's Proposer/Claim
// vocabulary so a future integration (e.g. a harness tool or daemon RPC that
// accepts an agent-proposed ontology extension) has an obvious, low-friction
// seam to call through — without this package importing brain, or brain
// importing this package's discovery internals.

// StructuralHypothesis is a fleet-proposed extension to the ontology
// vocabulary: an agent's unproven claim that a new class, relationship
// (equivalence), or identifying-property belongs in the ontology.
type StructuralHypothesis struct {
	// Proposer identifies the agent (or agent run) that proposed this
	// extension, carried through for audit/attribution. Required: an
	// unattributed proposal is rejected (see ProposeExtension).
	Proposer string

	// Claim is a short, free-text rationale for the proposal (e.g. "IIS
	// hosts should subclass web-server"), carried through for the audit
	// trail. It plays no role in the acceptance decision — Extension does —
	// but an empty Claim is rejected, mirroring
	// brain.applyHypothesisObserved's rule that a claim with no text records
	// nothing: there would be no stable rationale for another agent (or a
	// reviewer) to evaluate.
	Claim string

	// Extension is the proposed ontology content: new classes (Hierarchies),
	// new relationships between existing vocabulary (Equivalences), and new
	// identifying properties (IFPs) — the three kinds gibson#274 names.
	Extension sdkgraphrag.OntologyExtension
}

// DiscoveryOutcome records the result of putting a StructuralHypothesis to
// the light ontology-discovery gate (ADR-0124).
type DiscoveryOutcome struct {
	// Accepted reports whether the proposal was registered into the
	// Reasoner.
	Accepted bool

	// ExtensionName is the name Extension was registered under, set only
	// when Accepted. It is a deterministic function of Proposer and
	// Extension's content (see ProposeExtension), never a random or
	// time-based id, so replaying the same StructuralHypothesis reproduces
	// the identical registration.
	ExtensionName string

	// Rejected is the reason the proposal was not accepted: an unattributed
	// or textless proposal (errors.New), or whatever RegisterExtension
	// itself rejected the content for — a *CycleError or
	// *UnknownPrefixError, unchanged from today's validation. Set only when
	// !Accepted.
	Rejected error
}

// ProposeExtension applies a fleet-proposed StructuralHypothesis to r. This
// IS ADR-0124's light gate: RegisterExtension's own cycle and
// unknown-prefix checks are the acceptance test. A rejected proposal changes
// nothing in r.
//
// The extension is registered under a name deterministically derived from
// Proposer and a content hash of Extension, so:
//   - replaying the identical StructuralHypothesis (e.g. after a daemon
//     restart re-folds a persisted proposal event) derives the same name and
//     reproduces the same registration — gibson#274's "accepted extensions
//     ... survive replay" criterion;
//   - the SAME proposer proposing the SAME content twice is idempotent —
//     RegisterExtension's replace-by-name semantics apply, and since the
//     content is unchanged nothing observably changes;
//   - two DIFFERENT proposers, or the same proposer with DIFFERENT content,
//     never collide and clobber each other's contribution — each gets its
//     own extension name and both merge into the live ontology the same way
//     any two independently-registered extensions do.
func ProposeExtension(r *Reasoner, h StructuralHypothesis) DiscoveryOutcome {
	if h.Proposer == "" {
		return DiscoveryOutcome{Rejected: errors.New("ontology: structural hypothesis has no proposer; an unattributed proposal cannot be audited")}
	}
	if h.Claim == "" {
		return DiscoveryOutcome{Rejected: errors.New("ontology: structural hypothesis has no claim text; an unmotivated proposal cannot be evaluated")}
	}

	name := structuralHypothesisExtensionName(h)
	if err := r.RegisterExtension(name, h.Extension); err != nil {
		return DiscoveryOutcome{Rejected: err}
	}
	return DiscoveryOutcome{Accepted: true, ExtensionName: name}
}

// structuralHypothesisExtensionName derives a deterministic RegisterExtension
// name from h: "discovered/<proposer>/<content-hash-prefix>". Including the
// content hash (not just Proposer) means the same proposer's two structurally
// different proposals register as two independent extensions rather than one
// replacing the other — only a byte-for-byte-identical Extension collides,
// which is exactly the idempotent-replay case ProposeExtension's doc
// describes.
func structuralHypothesisExtensionName(h StructuralHypothesis) string {
	return fmt.Sprintf("discovered/%s/%s", h.Proposer, extensionContentHash(h.Extension)[:16])
}

// extensionContentHash is a stable digest of ext's content, independent of
// slice/map iteration order, so the identical logical extension always
// hashes the same way regardless of how the caller assembled it.
func extensionContentHash(ext sdkgraphrag.OntologyExtension) string {
	sum := sha256.Sum256([]byte(canonicalExtensionString(ext)))
	return hex.EncodeToString(sum[:])
}

// canonicalExtensionString renders ext as an order-independent, delimiter-safe
// string: every field is sorted, and every value is length-prefixed so no
// combination of separators inside a prefix, IRI, or property name can forge
// the encoding of a different extension (the same technique
// taxonomy.ContentHash uses for Observation shapes).
func canonicalExtensionString(ext sdkgraphrag.OntologyExtension) string {
	var b strings.Builder

	prefixKeys := slices.Sorted(maps.Keys(ext.Prefixes))
	for _, k := range prefixKeys {
		writeField(&b, "prefix", k, ext.Prefixes[k])
	}

	hierarchies := slices.Clone(ext.Hierarchies)
	sort.Slice(hierarchies, func(i, j int) bool {
		a, c := hierarchies[i], hierarchies[j]
		if a.NodeType != c.NodeType {
			return a.NodeType < c.NodeType
		}
		if a.Label != c.Label {
			return a.Label < c.Label
		}
		return a.SubClassOf < c.SubClassOf
	})
	for _, h := range hierarchies {
		writeField(&b, "hier", h.NodeType, h.Label, h.SubClassOf)
	}

	// sameAs is symmetric: normalise pair order before sorting so {a,b} and
	// {b,a} hash identically.
	equivalences := make([][2]string, len(ext.Equivalences))
	copy(equivalences, ext.Equivalences)
	for i, pair := range equivalences {
		if pair[1] < pair[0] {
			equivalences[i] = [2]string{pair[1], pair[0]}
		}
	}
	sort.Slice(equivalences, func(i, j int) bool {
		if equivalences[i][0] != equivalences[j][0] {
			return equivalences[i][0] < equivalences[j][0]
		}
		return equivalences[i][1] < equivalences[j][1]
	})
	for _, pair := range equivalences {
		writeField(&b, "eq", pair[0], pair[1])
	}

	ifps := slices.Clone(ext.IFPs)
	sort.Slice(ifps, func(i, j int) bool {
		if ifps[i].NodeType != ifps[j].NodeType {
			return ifps[i].NodeType < ifps[j].NodeType
		}
		return ifps[i].Property < ifps[j].Property
	})
	for _, ifp := range ifps {
		writeField(&b, "ifp", ifp.NodeType, ifp.Property)
	}

	if len(ext.RawTriples) > 0 {
		rawSum := sha256.Sum256(ext.RawTriples)
		writeField(&b, "raw", hex.EncodeToString(rawSum[:]))
	}

	return b.String()
}

// writeField appends one length-prefixed record to b.
func writeField(b *strings.Builder, kind string, parts ...string) {
	fmt.Fprintf(b, "%d:%s", len(kind), kind)
	for _, p := range parts {
		fmt.Fprintf(b, "|%d:%s", len(p), p)
	}
	b.WriteByte('\n')
}
