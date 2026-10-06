// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain/fit"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// beliefSet is one loaded belief version of a tenant: the providers that the
// brain scores with, built from the two artifacts of one version (ADR-0106,
// gibson#615). Inference runs in-process through beliefvi (ADR-0134), never
// over HTTP.
type beliefSet struct {
	// number is the stored version number. Zero is the embedded default,
	// which a tenant with no current version uses.
	number int64
	belief brain.BeliefProvider
	slice  brain.SliceBeliefProvider
	// edges is the fitted posterior of each strength (ADR-0137). It is the
	// cold-start prior for the embedded default.
	edges brain.StrengthPosteriorProvider
}

// label is the version that a mission records when it pins this set: the
// version of the belief model, which the store writes into the artifact
// ("tenant-<id>-v<n>"), or the version of the embedded default.
func (s *beliefSet) label() string { return s.belief.Version() }

// defaultBeliefSet builds the set of a tenant with no current version: the
// embedded OSS base model (beliefvi.DefaultArtifact) and the uninformative
// prior for every strength. This is the only fallback.
func defaultBeliefSet(schema *ontology.BeliefSchemaRegistry) (*beliefSet, error) {
	art, err := beliefvi.DefaultArtifact()
	if err != nil {
		return nil, fmt.Errorf("load the embedded default belief model: %w", err)
	}
	model, err := beliefvi.NewBeliefModel(art)
	if err != nil {
		return nil, fmt.Errorf("build the embedded default belief model: %w", err)
	}
	return &beliefSet{
		belief: brain.NativeBeliefProvider(model, nil),
		slice:  brain.NativeSliceBeliefProvider(schema, nil),
		edges:  brain.UninformativeEdgePosteriors{},
	}, nil
}

// storedBeliefSet builds the set of one stored version from its two artifacts.
func storedBeliefSet(schema *ontology.BeliefSchemaRegistry, number int64, beliefModel, edgePosteriors []byte) (*beliefSet, error) {
	art, err := beliefvi.ParseModelArtifact(beliefModel)
	if err != nil {
		return nil, fmt.Errorf("version %d: %w", number, err)
	}
	model, err := beliefvi.NewBeliefModel(art)
	if err != nil {
		return nil, fmt.Errorf("version %d: build the belief model: %w", number, err)
	}
	edgeArt, err := fit.ParseEdgePosteriorArtifact(edgePosteriors)
	if err != nil {
		return nil, fmt.Errorf("version %d: %w", number, err)
	}
	edges := braintrain.EdgePosteriorProvider(edgeArt)
	return &beliefSet{
		number: number,
		belief: brain.NativeBeliefProvider(model, nil),
		slice:  brain.NativeSliceBeliefProvider(schema, edges),
		edges:  edges,
	}, nil
}

// newBeliefSchemaRegistry builds the ontology belief-PRM schema registry
// (gibson#296) the graph-coupled pipeline grounds every attack-graph
// derivation against: which node types are belief-bearing, their declared
// variables, and which relationship types propagate belief. Call once at
// daemon startup and share the result across every tenant engine — the
// registry is read-only after construction and safe for concurrent use.
// Independent of the taxonomy Reasoner's own registry (ontology_init.go); no
// startup-ordering dependency between the two.
func newBeliefSchemaRegistry() (*ontology.BeliefSchemaRegistry, error) {
	reg := ontology.NewBeliefSchemaRegistry()
	if err := ontology.RegisterCoreBeliefSchemaSeed(reg); err != nil {
		return nil, fmt.Errorf("belief schema registry: register core seed: %w", err)
	}
	return reg, nil
}

// wireBrainRegistry registers the belief-engine OnEngine hooks — the per-host
// WireBelief pipeline, the graph-coupled WireSliceBelief pipeline
// (gibson#275), and value-of-information planning (WireVoIPlanner, ADR-0126,
// gibson#283) — onto registry, using the default bounded schedule
// (brain.DefaultSliceSchedule). Shared by daemon.go's Start() and grpc.go's
// lazy buildGRPCServer() fallback, which used to duplicate this wiring
// inline; extracting it here keeps the two construction paths from drifting
// apart and makes the wiring itself unit-testable independent of either
// call site's much larger bootstrap sequence (Redis, state client, ...).
//
// WireVoIPlanner requires VoIGateSystem to already be registered as a System
// on registry (brain.ExecutorSystems() carries it) — this hook only starts
// the off-tick worker; the caller's System list is what makes the in-tick
// gate half live.
//
// beliefs gives each engine the belief version of its own tenant (gibson#615).
// Every provider of the engine reads the active set of the tenant, so a
// version swap reaches all of them at once.
func wireBrainRegistry(
	ctx context.Context,
	registry *brain.Registry,
	beliefs *tenantBeliefs,
	beliefSchemaRegistry *ontology.BeliefSchemaRegistry,
) {
	wireBrainRegistryWithHierarchy(ctx, registry, beliefs, beliefSchemaRegistry, taxonomy.GlobalTechniques)
}

// wireBrainRegistryWithHierarchy is wireBrainRegistry with the technique
// hierarchy as a parameter. The daemon always passes taxonomy.GlobalTechniques.
// A test passes a hierarchy that holds a technique, because the global
// hierarchy holds none until a Domain Pack can declare one (gibson#699).
func wireBrainRegistryWithHierarchy(
	ctx context.Context,
	registry *brain.Registry,
	beliefs *tenantBeliefs,
	beliefSchemaRegistry *ontology.BeliefSchemaRegistry,
	hierarchy *taxonomy.TechniqueHierarchy,
) {
	sliceOpts, propagateOpts := brain.DefaultSliceSchedule()
	registry.OnEngine(func(e *brain.Engine) {
		tb := beliefs.forTenant(e.World.Tenant)
		brain.WireBelief(ctx, e, tenantBeliefProvider{tb}, 0)
		brain.WireSliceBelief(ctx, e, beliefSchemaRegistry, tenantSliceBeliefProvider{tb}, 0, sliceOpts, propagateOpts)
		// Reputation write loop (gibson#267): a settled bet recomputes its
		// technique×environment reputation off the tick, which voi_plan.go then
		// reads as both a new hypothesis's prior and its pursuit-priority
		// multiplier. Tap + off-tick drain, the same pattern WireVoIPlanner uses.
		brain.WireReputation(ctx, e, 0)
		// bamcp Thompson-samples the SAME fitted posterior that the slice
		// provider reads the mean of (ADR-0137's "one output, two uses").
		//
		// The planner reads the capability catalog of the mission from the
		// engine (brain.Engine.Capabilities). brain.WireExecutor sets that
		// catalog in a later OnEngine hook (daemon.go), and the planner reads
		// it when it plans, so the order of the two hooks does not matter
		// (gibson#693).
		bamcp := brain.NewBAMCPPlanner(beliefSchemaRegistry, tenantEdgePosteriors{tb}, brain.DefaultBAMCPConfig())
		brain.WireVoIPlanner(ctx, e, beliefSchemaRegistry, brain.ExactVoIScorer(), brain.DefaultVoITopK, 0, hierarchy, bamcp)
	})
}
