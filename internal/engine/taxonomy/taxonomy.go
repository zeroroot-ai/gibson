// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package taxonomy is the global, platform-versioned allow-list of node labels
// and relationship types the Knowledge graph may materialise — the same for
// every tenant (ADR-0012).
//
// # The gate
//
// A shape inside the Taxonomy materialises as a typed node. A shape outside it
// is never rejected: it lands as an Observation, with the requested shape and
// the residue preserved as properties. That is the whole property this package
// exists for — an agent can always write, and can never invent schema.
//
// # Global, not per-tenant
//
// The Taxonomy *is* the schema. Per-tenant shapes would push multi-tenancy back
// into every query and let Host / HOST / host_v2 diverge silently between
// customers. Flexibility is paid for by Observations, not by schema divergence.
// Promotion of a recurring Observation shape into the Taxonomy is a reviewed
// code change to this file — that is the intended cost.
//
// # Why the identifier constraint is a security control, not a style rule
//
// It is tempting to believe apoc.merge.node makes labels inert, because it
// takes them as runtime arguments rather than as query text. It does not.
// APOC's Util.quote wraps any non-identifier in backticks and does NOT escape
// backticks inside the name, so a label carrying a backtick closes the quoting
// early and reaches the query as structure. Verified against a live
// neo4j:5.26.27-community: the call returns no rows and no error, so the caller
// sees success while nothing was written.
//
// So APOC is not what makes a label safe — Taxonomy membership is. Every label
// and relationship type this registry can hand back is checked at construction
// to be a plain ASCII identifier, and a registry that fails that check refuses
// to build. Since ClassifyNode only ever returns a registry member or the
// constant ObservationLabel, no caller-influenced string can reach Neo4j as
// query structure by way of this package.
package taxonomy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
)

// Version is the Taxonomy's platform-wide version. Bump it in the same change
// that promotes a shape, so a projected graph can be attributed to the schema
// that produced it.
const Version = 2

// ObservationLabel is the label every out-of-taxonomy shape lands on. It is a
// compile-time constant and a plain identifier, so it is never caller-influenced.
const ObservationLabel = "Observation"

// MaxIdentifierBytes bounds a Taxonomy identifier. Neo4j itself permits far
// longer names; the cap is here so a promotion cannot smuggle in something
// unreviewable.
const MaxIdentifierBytes = 64

// coreNodeLabels is the promoted node vocabulary. It tracks what the projector
// actually materialises (internal/server/daemon/graph_projector_neo4j.go) plus
// Observation, the open-world fallback.
var coreNodeLabels = []string{
	ObservationLabel,
	"Account",
	"AgentRun",
	"Credential",
	"Domain",
	"Finding",
	"Host",
	"LlmCall",
	"Mission",
	"Port",
	"Service",
	"Subdomain",

	// Application lifecycle (v2, gibson#1656; CONTEXT.md "Application
	// lifecycle"). Vulnerability is the identity of a weakness and never
	// carries a status; Finding is the occurrence and does.
	"Application",
	"Control",
	"Deployment",
	"Image",
	"MergeRequest",
	"Package",
	"Pipeline",
	"Repository",
	"Vulnerability",
}

// coreRelationshipTypes is the promoted edge vocabulary, likewise tracking the
// projector.
var coreRelationshipTypes = []string{
	"AFFECTS",
	"DELEGATED_TO",
	"HAS_PORT",
	"HAS_SUBDOMAIN",
	"ISSUED",
	"RESOLVES_TO",
	"RUNS_SERVICE",

	// Application lifecycle (v2, gibson#1656).
	"BUILT_FROM",     // Image -> Repository
	"CONTAINS",       // Image -> Package
	"EXPOSES",        // Deployment -> Host
	"FIXED_BY",       // Finding -> MergeRequest
	"HAS_DEPLOYMENT", // Application -> Deployment
	"HAS_REPOSITORY", // Application -> Repository
	"INSTANCE_OF",    // Finding -> Vulnerability
	"MERGED_INTO",    // MergeRequest -> Repository
	"RUNS",           // Deployment -> Image
	"TOUCHES",        // Finding -> Control
	"VERIFIED_BY",    // Finding -> Pipeline
}

// Registry is a Taxonomy: a version plus the labels and relationship types it
// admits. Every member is a validated plain identifier.
type Registry struct {
	version int
	nodes   map[string]struct{}
	rels    map[string]struct{}
}

// New builds a Registry, refusing any label or relationship type that is not a
// plain identifier. The error is the enforcement point described in the package
// doc: an invalid entry cannot reach a query because the registry holding it
// does not exist.
func New(version int, nodeLabels, relationshipTypes []string) (*Registry, error) {
	if version <= 0 {
		return nil, fmt.Errorf("taxonomy: version must be positive, got %d", version)
	}
	r := &Registry{
		version: version,
		nodes:   make(map[string]struct{}, len(nodeLabels)),
		rels:    make(map[string]struct{}, len(relationshipTypes)),
	}
	for _, label := range nodeLabels {
		if err := ValidIdentifier(label); err != nil {
			return nil, fmt.Errorf("taxonomy: node label: %w", err)
		}
		if _, dup := r.nodes[label]; dup {
			return nil, fmt.Errorf("taxonomy: duplicate node label %q", label)
		}
		r.nodes[label] = struct{}{}
	}
	for _, relType := range relationshipTypes {
		if err := ValidIdentifier(relType); err != nil {
			return nil, fmt.Errorf("taxonomy: relationship type: %w", err)
		}
		if _, dup := r.rels[relType]; dup {
			return nil, fmt.Errorf("taxonomy: duplicate relationship type %q", relType)
		}
		r.rels[relType] = struct{}{}
	}
	if _, ok := r.nodes[ObservationLabel]; !ok {
		return nil, fmt.Errorf("taxonomy: %q must be admitted; it is the fallback every "+
			"out-of-taxonomy shape lands on", ObservationLabel)
	}
	return r, nil
}

// Global is the platform Taxonomy. Building it at init means an invalid
// promotion fails the process at startup and every test in the package, rather
// than surfacing as a silently-empty write months later.
var Global = mustNew(Version, coreNodeLabels, coreRelationshipTypes)

func mustNew(version int, nodeLabels, relationshipTypes []string) *Registry {
	r, err := New(version, nodeLabels, relationshipTypes)
	if err != nil {
		panic("taxonomy: the global Taxonomy is invalid: " + err.Error())
	}
	return r
}

// Version returns the registry's version.
func (r *Registry) Version() int { return r.version }

// NodeLabels returns the admitted node labels, sorted.
func (r *Registry) NodeLabels() []string { return sortedKeys(r.nodes) }

// RelationshipTypes returns the admitted relationship types, sorted.
func (r *Registry) RelationshipTypes() []string { return sortedKeys(r.rels) }

func sortedKeys(m map[string]struct{}) []string {
	out := slices.Collect(maps.Keys(m))
	sort.Strings(out)
	return out
}

// Decision is the outcome of putting a shape to the Taxonomy. It is never an
// error: a shape the Taxonomy does not admit becomes an Observation.
type Decision struct {
	// Label is what to materialise as: a Taxonomy member when InTaxonomy, and
	// ObservationLabel otherwise. Always a plain identifier.
	Label string

	// InTaxonomy reports whether the requested shape was admitted.
	InTaxonomy bool

	// Requested is the shape the caller asked for, verbatim. When InTaxonomy is
	// false this is preserved as a property *value* on the Observation — data,
	// never structure — so nothing is lost and nothing becomes schema.
	Requested string

	// Reason says why the shape fell back. Empty when InTaxonomy.
	Reason string
}

// ClassifyNode puts a node label to the Taxonomy. Matching is exact: Host,
// HOST and host are three different strings and only the promoted one is
// admitted, because case-folding here is precisely the silent divergence a
// global Taxonomy exists to prevent.
func (r *Registry) ClassifyNode(label string) Decision {
	if _, ok := r.nodes[label]; ok {
		return Decision{Label: label, InTaxonomy: true, Requested: label}
	}
	return Decision{
		Label:      ObservationLabel,
		InTaxonomy: false,
		Requested:  label,
		Reason:     fmt.Sprintf("node label %q is not in Taxonomy v%d", label, r.version),
	}
}

// ClassifyRelationship puts a relationship type to the Taxonomy. An
// out-of-taxonomy edge has no Observation equivalent — an Observation is a
// node — so the caller records the intended edge inside the Observation's
// payload rather than materialising it.
func (r *Registry) ClassifyRelationship(relType string) Decision {
	if _, ok := r.rels[relType]; ok {
		return Decision{Label: relType, InTaxonomy: true, Requested: relType}
	}
	return Decision{
		Label:      ObservationLabel,
		InTaxonomy: false,
		Requested:  relType,
		Reason:     fmt.Sprintf("relationship type %q is not in Taxonomy v%d", relType, r.version),
	}
}

// ValidIdentifier reports whether s is a plain ASCII Cypher identifier: a
// letter followed by letters, digits or underscores, at most
// MaxIdentifierBytes long.
//
// Deliberately strict. Neo4j accepts much more once backtick-quoted, but the
// point here is to admit only names that need no quoting at all — see the
// package doc on why relying on APOC's quoting is not safe.
func ValidIdentifier(s string) error {
	if s == "" {
		return errors.New("identifier is empty")
	}
	if len(s) > MaxIdentifierBytes {
		return fmt.Errorf("identifier %q is %d bytes, over the %d-byte cap", s, len(s), MaxIdentifierBytes)
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case i > 0 && (c >= '0' && c <= '9' || c == '_'):
		default:
			return fmt.Errorf("identifier %q contains %q at offset %d; only ASCII letters, "+
				"digits and underscores are allowed, and it must start with a letter", s, string(c), i)
		}
	}
	return nil
}

// ContentHash is the recurrence key for an Observation: a stable digest of the
// requested shape and its payload, independent of map iteration order.
//
// It is NOT the node's identity. Two sightings of the same fact three weeks
// apart share a content hash and remain distinct nodes, because "seen again" is
// signal in this domain and is the input Sensing needs to decide what to
// promote. Identity is the Timeline event id (ADR-0012).
func ContentHash(shape string, payload map[string]string) string {
	keys := slices.Collect(maps.Keys(payload))
	sort.Strings(keys)

	var b strings.Builder
	// Length-prefix every field so no combination of separators inside a key or
	// value can forge the encoding of a different observation.
	fmt.Fprintf(&b, "%d:%s", len(shape), shape)
	for _, k := range keys {
		fmt.Fprintf(&b, "|%d:%s=%d:%s", len(k), k, len(payload[k]), payload[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
