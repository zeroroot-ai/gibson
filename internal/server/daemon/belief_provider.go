// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"
	"os"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
	"github.com/zeroroot-ai/gibson/internal/engine/ontology"
)

// resolveBeliefProvider selects the brain's belief-field provider (ADR-0005,
// ADR-0034). Inference runs IN-PROCESS via internal/engine/brain/beliefvi — the
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
// (ADR-0029, gibson#275): the belief engine consulted for a whole bounded
// slice (gibson#287) at once, instead of one host in isolation.
//
// This is now brain.NativeSliceBeliefProvider (gibson#394, ADR-0037):
// registry supplies both the schema data ground.py's cross-node enablement
// edges used to have no source for (which of a target node's OWN declared
// variables an incoming enablement edge feeds — ADR-0037 decision 1's
// EnablementEdgeSpec.TargetVariable) and the exact VE + noisy-OR engine
// (internal/engine/brain/beliefvi's GroundSlice/SolveSlice, #401,
// parity-tested) that grounds it, entirely in-process; there is no sidecar
// HTTP path left anywhere in this seam to cut over to. The noisy-OR
// strength/leak ADR-0037 decision 2 assigns to a learned Beta posterior per
// edge-type is a separate, later slice (braintrain, gibson#395); until it
// lands, every cause grounds at the uninformative-prior cold start
// (brain.UninformativePriorStrength, ADR-0037 decision 3) — never a
// hand-authored number.
func resolveSliceBeliefProvider(registry *ontology.BeliefSchemaRegistry) brain.SliceBeliefProvider {
	return brain.NativeSliceBeliefProvider(registry)
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
// (gibson#275), and value-of-information planning (WireVoIPlanner, ADR-0026,
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
func wireBrainRegistry(
	ctx context.Context,
	registry *brain.Registry,
	beliefProvider brain.BeliefProvider,
	sliceBeliefProvider brain.SliceBeliefProvider,
	beliefSchemaRegistry *ontology.BeliefSchemaRegistry,
) {
	sliceOpts, propagateOpts := brain.DefaultSliceSchedule()
	registry.OnEngine(func(e *brain.Engine) {
		brain.WireBelief(ctx, e, beliefProvider, 0)
		brain.WireSliceBelief(ctx, e, beliefSchemaRegistry, sliceBeliefProvider, 0, sliceOpts, propagateOpts)
		// The deep BAMCP sequential tree search stays gibson#333; this is
		// ADR-0026's one-step-exact plan, re-triggered per evidence change via
		// the closed loop (VoIGateSystem/VoIWorker's gate/worker split).
		//
		// catalog is nil here (no covering-capability resolution yet, ADR-0035
		// decision 4/gibson#387): the live per-mission capability catalog
		// (brainExecutor.catalog) is built later in Start(), after this
		// per-tenant-engine wiring runs, the same way ExecutorDeps.Catalog is
		// wired onto DeciderWorker in a SEPARATE, later OnEngine registration
		// (daemon.go). Threading it through here is follow-up wiring for
		// gibson#396/#397, which consume VoICandidate.CoveringCapabilities;
		// nil is safe and documented (NewVoIWorker/WireVoIPlanner), and
		// preserves today's behavior exactly (no candidate resolves a
		// covering capability).
		brain.WireVoIPlanner(ctx, e, beliefSchemaRegistry, brain.ExactVoIScorer(), brain.DefaultVoITopK, 0, nil, nil)
	})
}
