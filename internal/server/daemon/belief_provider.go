// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"os"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// resolveBeliefProvider selects the brain's belief-field provider (ADR-0134,
// ADR-0134). Inference runs IN-PROCESS via internal/engine/brain/beliefvi — the
// native Go port of the (now-retired) Python belief sidecar's exact
// variable-elimination engine — never over HTTP.
//
// GIBSON_BELIEF_MODEL_PATH optionally names an alternate model artifact file
// (e.g. the curated commercial base model the commercial layer drops in,
// sidecar/belief/README.md); unset uses the OSS-shipped base-v1 model, which
// is embedded into the binary (beliefvi.DefaultArtifact) so belief inference
// needs no external file, container or network dependency by default.
//
// No GIBSON_MODE branch: the binary boots identically everywhere; a curated
// model is wired per-environment via Helm values (a mounted file path), never
// a mode switch. There is no placeholder fallback here any more — unlike the
// pgmpy sidecar, the native engine has no extra deployment cost to opt out
// of, so OSS always gets a real (if minimal) belief field.
func resolveBeliefProvider() (brain.BeliefProvider, error) {
	art, err := loadBeliefModelArtifact()
	if err != nil {
		return nil, fmt.Errorf("resolve belief provider: %w", err)
	}
	model, err := beliefvi.NewBeliefModel(art)
	if err != nil {
		return nil, fmt.Errorf("resolve belief provider: build belief model: %w", err)
	}
	return brain.NativeBeliefProvider(model, nil), nil
}

// loadBeliefModelArtifact loads the model artifact GIBSON_BELIEF_MODEL_PATH
// names, or the embedded OSS default when the env var is unset.
func loadBeliefModelArtifact() (beliefvi.ModelArtifact, error) {
	if path := os.Getenv("GIBSON_BELIEF_MODEL_PATH"); path != "" {
		art, err := beliefvi.LoadModelArtifact(path)
		if err != nil {
			return beliefvi.ModelArtifact{}, fmt.Errorf("load model artifact %s: %w", path, err)
		}
		return art, nil
	}
	art, err := beliefvi.DefaultArtifact()
	if err != nil {
		return beliefvi.ModelArtifact{}, fmt.Errorf("load embedded default model artifact: %w", err)
	}
	return art, nil
}

// resolveSliceBeliefProvider selects the graph-coupled SliceBeliefProvider
// (ADR-0129, gibson#275): the belief engine consulted for a whole bounded
// slice (gibson#287) at once, instead of one host in isolation.
//
// This is now brain.NativeSliceBeliefProvider (gibson#394, ADR-0137):
// registry supplies both the schema data ground.py's cross-node enablement
// edges used to have no source for (which of a target node's OWN declared
// variables an incoming enablement edge feeds — ADR-0137's
// EnablementEdgeSpec.TargetVariable) and the exact VE + noisy-OR engine
// (internal/engine/brain/beliefvi's GroundSlice/SolveSlice, #401,
// parity-tested) that grounds it, entirely in-process; there is no sidecar
// HTTP path left anywhere in this seam to cut over to. posteriors is the
// per-edge-type Beta posterior resolveEdgePosteriorProvider resolved
// (gibson#395, ADR-0137); nil means no posterior is pinned, so
// every cause grounds at the uninformative-prior cold start
// (brain.UninformativePriorStrength, ADR-0137) — never a
// hand-authored number.
func resolveSliceBeliefProvider(registry *ontology.BeliefSchemaRegistry, posteriors brain.PinnedEdgeStrengthPosteriorProvider) brain.SliceBeliefProvider {
	return brain.NativeSliceBeliefProvider(registry, posteriors)
}

// resolveEdgePosteriorProvider selects braintrain's fitted per-edge-type Beta
// posterior (gibson#395, ADR-0137), the learned strength
// that replaces the uninformative-prior cold start (#394) once braintrain has
// fitted one.
//
// GIBSON_EDGE_POSTERIOR_PATH optionally names a braintrain-emitted
// fit.EdgePosteriorArtifact JSON file (mounted the same way GIBSON_BELIEF_MODEL_PATH mounts a curated CPT
// model). Unset returns a nil provider: production may have no recorded
// outcomes yet (this issue's documented data caveat), and a nil provider is
// exactly "no posterior pinned" — NativeSliceBeliefProvider and
// NewBAMCPPlanner both already treat that as the uninformative-prior cold
// start, never a hard error and never a second code path to maintain.
func resolveEdgePosteriorProvider() (brain.PinnedEdgeStrengthPosteriorProvider, error) {
	path := os.Getenv("GIBSON_EDGE_POSTERIOR_PATH")
	if path == "" {
		return nil, nil
	}
	art, err := braintrain.LoadEdgePosteriorArtifact(path)
	if err != nil {
		return nil, fmt.Errorf("resolve edge posterior provider: %w", err)
	}
	return braintrain.EdgePosteriorProvider(art), nil
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
// edgePosteriorProvider is braintrain's fitted per-edge-type Beta posterior
// (gibson#395, resolveEdgePosteriorProvider); nil means none is pinned, and
// every consumer below keeps its documented uninformative-prior cold start
// exactly as before this parameter existed.
func wireBrainRegistry(
	ctx context.Context,
	registry *brain.Registry,
	beliefProvider brain.BeliefProvider,
	sliceBeliefProvider brain.SliceBeliefProvider,
	beliefSchemaRegistry *ontology.BeliefSchemaRegistry,
	edgePosteriorProvider brain.PinnedEdgeStrengthPosteriorProvider,
) {
	wireBrainRegistryWithHierarchy(ctx, registry, beliefProvider, sliceBeliefProvider,
		beliefSchemaRegistry, edgePosteriorProvider, taxonomy.GlobalTechniques)
}

// wireBrainRegistryWithHierarchy is wireBrainRegistry with the technique
// hierarchy as a parameter. The daemon always passes taxonomy.GlobalTechniques.
// A test passes a hierarchy that holds a technique, because the global
// hierarchy holds none until a Domain Pack can declare one (gibson#699).
func wireBrainRegistryWithHierarchy(
	ctx context.Context,
	registry *brain.Registry,
	beliefProvider brain.BeliefProvider,
	sliceBeliefProvider brain.SliceBeliefProvider,
	beliefSchemaRegistry *ontology.BeliefSchemaRegistry,
	edgePosteriorProvider brain.PinnedEdgeStrengthPosteriorProvider,
	hierarchy *taxonomy.TechniqueHierarchy,
) {
	sliceOpts, propagateOpts := brain.DefaultSliceSchedule()
	// bamcp Thompson-samples edgePosteriorProvider's SAME fitted posterior
	// (ADR-0137's "one output, two uses" — sliceBeliefProvider
	// above, if built via resolveSliceBeliefProvider, already consumes its
	// MEAN). NewBAMCPPlanner defaults a nil provider to
	// UninformativeEdgePosteriors itself, so passing edgePosteriorProvider
	// straight through preserves the documented cold start when none is
	// pinned.
	bamcp := brain.NewBAMCPPlanner(beliefSchemaRegistry, edgePosteriorProvider, brain.DefaultBAMCPConfig())
	registry.OnEngine(func(e *brain.Engine) {
		brain.WireBelief(ctx, e, beliefProvider, 0)
		brain.WireSliceBelief(ctx, e, beliefSchemaRegistry, sliceBeliefProvider, 0, sliceOpts, propagateOpts)
		// Reputation write loop (gibson#267): a settled bet recomputes its
		// technique×environment reputation off the tick, which voi_plan.go then
		// reads as both a new hypothesis's prior and its pursuit-priority
		// multiplier. Tap + off-tick drain, the same pattern WireVoIPlanner uses.
		brain.WireReputation(ctx, e, 0)
		// gibson#333 ("complete the BAMCP sequential planner") is CLOSED,
		// superseded by the phase-2 decomposition (epic gibson#376): its
		// generative-simulator/Thompson-sampling item is this repo's
		// gibson#396 (brain.BAMCPPlanner, wired below).
		//
		// The planner reads the capability catalog of the mission from the
		// engine (brain.Engine.Capabilities). brain.WireExecutor sets that
		// catalog in a later OnEngine hook (daemon.go), and the planner reads
		// it when it plans, so the order of the two hooks does not matter
		// (gibson#693).
		brain.WireVoIPlanner(ctx, e, beliefSchemaRegistry, brain.ExactVoIScorer(), brain.DefaultVoITopK, 0, hierarchy, bamcp)
	})
}
