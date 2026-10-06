// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package fit

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/zeroroot-ai/gibson/internal/engine/brain/beliefvi"
)

// BetaPosterior is one fitted Beta(alpha, beta) posterior in an artifact.
type BetaPosterior struct {
	Alpha float64 `json:"alpha"`
	Beta  float64 `json:"beta"`
}

// OutcomeCount is the outcome count of one edge type: the cause was active
// and the effect was seen (Successes) or was not seen (Failures).
type OutcomeCount struct {
	Successes float64
	Failures  float64
}

// EdgePosteriorArtifact holds the fitted Beta posterior of each learned
// noisy-OR strength (ADR-0137): each enablement edge type (gibson#395), each
// dependency inside one node, and the leak of each variable (gibson#720). It
// is one of the two artifacts of a tenant version.
// braintrain.EdgePosteriorProvider gives the runtime view of it.
type EdgePosteriorArtifact struct {
	Version     string                   `json:"version"`
	Description string                   `json:"description,omitempty"`
	Posteriors  map[string]BetaPosterior `json:"posteriors"`
	// InNode is keyed by InNodeKey, and Leaks by LeakKey (strengths.go).
	InNode map[string]BetaPosterior `json:"in_node,omitempty"`
	Leaks  map[string]BetaPosterior `json:"leaks,omitempty"`
}

// EdgePosteriors adds the outcome counts of each edge type to the
// uninformative Beta prior (the Beta-Bernoulli conjugate update) and stamps
// version on the result.
func EdgePosteriors(counts map[string]OutcomeCount, version string) (*EdgePosteriorArtifact, error) {
	if version == "" {
		return nil, errors.New("fit: empty version")
	}
	posteriors := make(map[string]BetaPosterior, len(counts))
	var outcomes float64
	for edgeType, c := range counts {
		if c.Successes < 0 || c.Failures < 0 {
			return nil, fmt.Errorf("fit: edge type %q has a negative outcome count", edgeType)
		}
		posteriors[edgeType] = BetaPosterior{
			Alpha: beliefvi.UninformativeBetaAlpha + c.Successes,
			Beta:  beliefvi.UninformativeBetaBeta + c.Failures,
		}
		outcomes += c.Successes + c.Failures
	}
	a := &EdgePosteriorArtifact{
		Version: version,
		Description: fmt.Sprintf("Beta posterior of each enablement edge type, fitted from %.0f recorded outcomes "+
			"of %d edge types on a Beta(%.0f,%.0f) prior (ADR-0137).",
			outcomes, len(counts), beliefvi.UninformativeBetaAlpha, beliefvi.UninformativeBetaBeta),
		Posteriors: posteriors,
	}
	return a, nil
}

// ParseEdgePosteriorArtifact decodes and validates an edge posterior artifact.
func ParseEdgePosteriorArtifact(raw []byte) (*EdgePosteriorArtifact, error) {
	var a EdgePosteriorArtifact
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("fit: decode edge posterior artifact: %w", err)
	}
	if err := a.Validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

// Validate reports whether a has a version and a valid Beta shape (both
// parameters above 0) for each strength.
func (a *EdgePosteriorArtifact) Validate() error {
	if a.Version == "" {
		return errors.New("fit: edge posterior artifact has no version")
	}
	for _, group := range []struct {
		kind string
		set  map[string]BetaPosterior
	}{{"edge type", a.Posteriors}, {"in-node strength", a.InNode}, {"leak", a.Leaks}} {
		kind, set := group.kind, group.set
		keys := make([]string, 0, len(set))
		for k := range set {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if p := set[k]; p.Alpha <= 0 || p.Beta <= 0 {
				return fmt.Errorf("fit: edge posterior artifact %q: %s %q has a non-positive Beta shape (alpha=%v, beta=%v)",
					a.Version, kind, k, p.Alpha, p.Beta)
			}
		}
	}
	return nil
}
