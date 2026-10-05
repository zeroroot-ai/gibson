// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintrain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// edge_posterior.go is gibson#395 (ADR-0137): a
// Beta(alpha, beta) posterior PER enablement-edge-type, shipped as a
// versioned artifact, for the thing ADR-0137 scopes as "learned, not
// authored": an enablement edge's noisy-OR strength. This file is the
// runtime half, the loader. The fitter and the trainer that wrote the
// artifact left with cmd/belief-trainer (gibson#507) and come back with the
// training lane (gibson#590).
//
// The fitted artifact is "one output, two uses" (ADR-0137): its
// Provider() is a brain.PinnedEdgeStrengthPosteriorProvider that
// brain.NativeSliceBeliefProvider (belief_slice_native.go) consumes via the
// posterior MEAN for exact inference, and brain.NewBAMCPPlanner consumes via
// Thompson sampling the full Beta distribution for model-uncertainty
// planning — the exact same fitted numbers, two different reads.
//
// Fit is the standard Beta-Bernoulli conjugate update: posterior alpha =
// prior alpha + successes, posterior beta = prior beta + failures. The prior
// is the SAME uninformative Beta(1,1) brain.UninformativeEdgePosteriors
// already grounds an edge type at cold-start (ADR-0137) — read
// from that type directly (never re-declared as a second magic-number pair),
// so the prior this fit starts from and the prior the belief runtime falls
// back to when no posterior is pinned are, structurally, the same number.

// edgePosteriorJSON is the on-disk JSON shape for one edge type's fitted Beta
// posterior. It is kept distinct from brain.EdgeStrengthPosterior (which
// carries no json tags of its own — that type is the RUNTIME shape
// bamcp.go/belief_slice_native.go consume, not a wire format) so the
// artifact's JSON keys stay lowercase and stable independent of that type's
// Go field names.
type edgePosteriorJSON struct {
	Alpha float64 `json:"alpha"`
	Beta  float64 `json:"beta"`
}

// EdgePosteriorArtifact is the on-disk, versioned output of
// FitEdgePosteriors: a per-enablement-edge-type Beta(alpha,beta) posterior
// (ADR-0137, gibson#395). It is what a mission pins for
// replay: see (*EdgePosteriorArtifact).Provider.
type EdgePosteriorArtifact struct {
	Version     string                       `json:"version"`
	Description string                       `json:"description,omitempty"`
	Posteriors  map[string]edgePosteriorJSON `json:"posteriors"`
}

// validate reports whether a is well-formed: a version, and every fitted row
// a valid Beta shape (both parameters strictly positive — a non-positive
// shape parameter is not a Beta distribution at all).
func (a *EdgePosteriorArtifact) validate() error {
	if a.Version == "" {
		return errors.New("braintrain: edge posterior artifact missing version")
	}
	for edgeType, p := range a.Posteriors {
		if p.Alpha <= 0 || p.Beta <= 0 {
			return fmt.Errorf("braintrain: edge posterior artifact %q: edge type %q has a non-positive Beta shape (alpha=%v, beta=%v)",
				a.Version, edgeType, p.Alpha, p.Beta)
		}
	}
	return nil
}

// LoadEdgePosteriorArtifact reads a fitted edge-posterior artifact JSON file
// (e.g. one GIBSON_EDGE_POSTERIOR_PATH names, internal/server/daemon/belief_provider.go).
func LoadEdgePosteriorArtifact(path string) (*EdgePosteriorArtifact, error) {
	//nolint:gosec // G304: path is an operator-supplied config path
	// (GIBSON_EDGE_POSTERIOR_PATH / a CLI -out artifact), never end-user
	// input, mirroring beliefvi.LoadModelArtifact's identical seam.
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("braintrain: read edge posterior artifact: %w", err)
	}
	var a EdgePosteriorArtifact
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("braintrain: decode edge posterior artifact: %w", err)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// Provider returns a brain.PinnedEdgeStrengthPosteriorProvider backed by a's
// fitted posteriors, identified by a.Version — the SAME artifact both
// brain.NativeSliceBeliefProvider (the posterior MEAN, exact inference) and
// brain.NewBAMCPPlanner (the full posterior, Thompson-sampled) consume
// (ADR-0137, "one output, two uses"). An edge type with no fitted
// row — never observed yet, or the artifact predates that Domain Pack's edge
// type — falls back to brain.UninformativeEdgePosteriors' own Beta(1,1) cold
// start: never a hand-authored number, and never a hard error, the same
// graceful degradation groundAttackGraph already applies to an unknown
// enablement edge type.
func (a *EdgePosteriorArtifact) Provider() brain.PinnedEdgeStrengthPosteriorProvider {
	posteriors := make(map[string]brain.EdgeStrengthPosterior, len(a.Posteriors))
	for edgeType, p := range a.Posteriors {
		posteriors[edgeType] = brain.EdgeStrengthPosterior{Alpha: p.Alpha, Beta: p.Beta}
	}
	return &loadedEdgePosteriors{version: a.Version, posteriors: posteriors}
}

// loadedEdgePosteriors is the concrete brain.PinnedEdgeStrengthPosteriorProvider
// EdgePosteriorArtifact.Provider builds.
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
