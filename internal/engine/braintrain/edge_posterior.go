// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintrain

import (
	"fmt"
	"os"
	"path/filepath"

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

// LoadEdgePosteriorArtifact reads a fitted edge-posterior artifact JSON file
// (e.g. one GIBSON_EDGE_POSTERIOR_PATH names, internal/server/daemon/belief_provider.go).
func LoadEdgePosteriorArtifact(path string) (*fit.EdgePosteriorArtifact, error) {
	//nolint:gosec // G304: path is an operator-supplied config path
	// (GIBSON_EDGE_POSTERIOR_PATH), never end-user input, mirroring
	// beliefvi.LoadModelArtifact's identical seam.
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("braintrain: read edge posterior artifact: %w", err)
	}
	a, err := fit.ParseEdgePosteriorArtifact(b)
	if err != nil {
		return nil, fmt.Errorf("braintrain: %w", err)
	}
	return a, nil
}

// EdgePosteriorProvider returns a brain.PinnedEdgeStrengthPosteriorProvider
// backed by the fitted posteriors of a, identified by a.Version. An edge type
// with no fitted row falls back to brain.UninformativeEdgePosteriors: never a
// hand-authored number, and never a hard error.
func EdgePosteriorProvider(a *fit.EdgePosteriorArtifact) brain.PinnedEdgeStrengthPosteriorProvider {
	posteriors := make(map[string]brain.EdgeStrengthPosterior, len(a.Posteriors))
	for edgeType, p := range a.Posteriors {
		posteriors[edgeType] = brain.EdgeStrengthPosterior{Alpha: p.Alpha, Beta: p.Beta}
	}
	return &loadedEdgePosteriors{version: a.Version, posteriors: posteriors}
}

// loadedEdgePosteriors is the brain.PinnedEdgeStrengthPosteriorProvider that
// EdgePosteriorProvider builds.
type loadedEdgePosteriors struct {
	version    string
	posteriors map[string]brain.EdgeStrengthPosterior
}

// Posterior implements brain.EdgeStrengthPosteriorProvider.
func (l *loadedEdgePosteriors) Posterior(edgeType string) brain.EdgeStrengthPosterior {
	if p, ok := l.posteriors[edgeType]; ok {
		return p
	}
	return brain.UninformativeEdgePosteriors{}.Posterior(edgeType)
}

// Version implements brain.PinnedEdgeStrengthPosteriorProvider.
func (l *loadedEdgePosteriors) Version() string { return l.version }
