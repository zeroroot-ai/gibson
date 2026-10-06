// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintrain

import (
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/braintrain/fit"
)

// edge_posterior.go is the runtime half of the per-edge-type Beta posterior
// (gibson#395, ADR-0137): it loads a fitted fit.EdgePosteriorArtifact and
// gives the brain its view of it. The fitter is fit.EdgePosteriors, which
// the belief trainer (cmd/belief-trainer, gibson#614) calls.
//
// The fitted artifact is "one output, two uses" (ADR-0137): its provider is a
// brain.PinnedEdgeStrengthPosteriorProvider that brain.NativeSliceBeliefProvider
// consumes via the posterior MEAN for exact inference, and that
// brain.NewBAMCPPlanner Thompson-samples for model-uncertainty planning.

// EdgePosteriorProvider returns a brain.PinnedEdgeStrengthPosteriorProvider
// backed by the fitted posteriors of a, identified by a.Version: each
// enablement edge type, each in-node strength and each leak. A strength with
// no fitted row falls back to brain.UninformativeEdgePosteriors: never a
// hand-authored number, and never a hard error.
func EdgePosteriorProvider(a *fit.EdgePosteriorArtifact) brain.PinnedEdgeStrengthPosteriorProvider {
	return &loadedEdgePosteriors{
		version:    a.Version,
		posteriors: toBrain(a.Posteriors),
		inNode:     toBrain(a.InNode),
		leaks:      toBrain(a.Leaks),
	}
}

// toBrain converts fitted posteriors to the runtime type.
func toBrain(in map[string]fit.BetaPosterior) map[string]brain.EdgeStrengthPosterior {
	out := make(map[string]brain.EdgeStrengthPosterior, len(in))
	for k, p := range in {
		out[k] = brain.EdgeStrengthPosterior{Alpha: p.Alpha, Beta: p.Beta}
	}
	return out
}

// loadedEdgePosteriors is the brain.PinnedEdgeStrengthPosteriorProvider that
// EdgePosteriorProvider builds.
type loadedEdgePosteriors struct {
	version    string
	posteriors map[string]brain.EdgeStrengthPosterior
	inNode     map[string]brain.EdgeStrengthPosterior
	leaks      map[string]brain.EdgeStrengthPosterior
}

// lookup returns the fitted posterior at key, or the uninformative prior.
func lookup(m map[string]brain.EdgeStrengthPosterior, key string) brain.EdgeStrengthPosterior {
	if p, ok := m[key]; ok {
		return p
	}
	return brain.UninformativeEdgePosteriors{}.Posterior(key)
}

// Posterior implements brain.EdgeStrengthPosteriorProvider.
func (l *loadedEdgePosteriors) Posterior(edgeType string) brain.EdgeStrengthPosterior {
	return lookup(l.posteriors, edgeType)
}

// InNodeStrength implements brain.PinnedEdgeStrengthPosteriorProvider.
func (l *loadedEdgePosteriors) InNodeStrength(kind, child, parent string) brain.EdgeStrengthPosterior {
	return lookup(l.inNode, fit.InNodeKey(kind, child, parent))
}

// Leak implements brain.PinnedEdgeStrengthPosteriorProvider.
func (l *loadedEdgePosteriors) Leak(kind, variable string) brain.EdgeStrengthPosterior {
	return lookup(l.leaks, fit.LeakKey(kind, variable))
}

// Version implements brain.PinnedEdgeStrengthPosteriorProvider.
func (l *loadedEdgePosteriors) Version() string { return l.version }
