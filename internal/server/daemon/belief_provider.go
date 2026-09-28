// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"os"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// resolveBeliefProvider selects the brain's belief-field provider (ADR-0005).
//
// When GIBSON_BELIEF_SIDECAR_URL is set, the daemon uses the pgmpy sidecar
// (exact, read-only, versioned Bayesian inference). GIBSON_BELIEF_MODEL_VERSION
// optionally pins a specific model artifact; empty means the sidecar's current
// default. When the sidecar URL is unset — OSS without the curated base model —
// the daemon falls back to the deterministic Go placeholder, so the brain still
// produces a (rough) field with zero external dependencies.
//
// No GIBSON_MODE branch: the binary boots identically everywhere; the sidecar is
// wired per-environment via Helm values, fail-loud only on a real dependency.
func resolveBeliefProvider() brain.BeliefProvider {
	url := os.Getenv("GIBSON_BELIEF_SIDECAR_URL")
	if url == "" {
		return brain.PlaceholderBeliefProvider()
	}
	version := os.Getenv("GIBSON_BELIEF_MODEL_VERSION")
	return brain.PgmpyBeliefProvider(url, version, nil)
}

// resolveSliceBeliefProvider selects the graph-coupled SliceBeliefProvider
// (ADR-0029, gibson#275): the belief engine consulted for a whole bounded
// slice (gibson#287) at once, instead of one host in isolation.
//
// This is deliberately always the deterministic placeholder for now, never
// the pgmpy sidecar's ground-slice solver (gibson#288's sidecar/belief/
// ground.py) — NOT an oversight. Grounding a slice's cross-node enablement
// edges needs two numbers ground.py has no source for yet: which of a target
// node's OWN declared variables an incoming enablement edge feeds (the
// ontology schema, gibson#296, declares intra-node DependsOn names but not a
// per-edge-type target variable), and the noisy-OR strength/leak for that
// contribution (braintrain, gibson#25, refits the OLD single-host CPT
// template; it does not yet produce relational-PRM noisy-OR parameters). Both
// are real ontology/training decisions, not values this wiring should invent
// silently. Once they exist, an HTTP-calling implementation of
// brain.SliceBeliefProvider plugs in here exactly the way pgmpyBelief already
// does for resolveBeliefProvider above.
func resolveSliceBeliefProvider() brain.SliceBeliefProvider {
	return brain.PlaceholderSliceBeliefProvider()
}

// newBeliefSchemaRegistry builds the ontology belief-PRM schema registry
// (gibson#296) the graph-coupled pipeline grounds every attack-graph
// derivation against: which node types are belief-bearing, their declared
// variables, and which relationship types propagate belief. Call once at
// daemon startup (mirrors d.beliefProvider) and share the result across every
// tenant engine — the registry is read-only after construction and safe for
// concurrent use. Independent of the taxonomy Reasoner's own registry
// (ontology_init.go); no startup-ordering dependency between the two.
func newBeliefSchemaRegistry() (*ontology.BeliefSchemaRegistry, error) {
	reg := ontology.NewBeliefSchemaRegistry()
	if err := ontology.RegisterCoreBeliefSchemaSeed(reg); err != nil {
		return nil, err
	}
	return reg, nil
}
