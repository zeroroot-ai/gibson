// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package braintrain

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// edge_posterior.go is gibson#395 (ADR-0037 decisions 2 and 5): braintrain
// fits a Beta(alpha, beta) posterior PER enablement-edge-type from recorded
// outcomes, and ships it as a NEW versioned artifact — the same
// out-of-band, event-log-driven discipline train.go already applies to the
// belief-CPT model (ADR-0006), applied here to the OTHER thing ADR-0037
// scopes as "learned, not authored": an enablement edge's noisy-OR strength.
//
// The fitted artifact is "one output, two uses" (ADR-0037 decision 4): its
// Provider() is a brain.PinnedEdgeStrengthPosteriorProvider that
// brain.NativeSliceBeliefProvider (belief_slice_native.go) consumes via the
// posterior MEAN for exact inference, and brain.NewBAMCPPlanner consumes via
// Thompson sampling the full Beta distribution for model-uncertainty
// planning — the exact same fitted numbers, two different reads.
//
// Fit is the standard Beta-Bernoulli conjugate update: posterior alpha =
// prior alpha + successes, posterior beta = prior beta + failures. The prior
// is the SAME uninformative Beta(1,1) brain.UninformativeEdgePosteriors
// already grounds an edge type at cold-start (ADR-0037 decision 3) — read
// from that type directly (never re-declared as a second magic-number pair),
// so the prior this fit starts from and the prior the belief runtime falls
// back to when no posterior is pinned are, structurally, the same number.

// EdgeOutcome is one recorded (cause-active -> effect-observed?) observation
// for a single enablement-edge TYPE (ADR-0037 decision 2): braintrain
// conditions only on instances where the edge's cause fired (its source
// node's own terminal belief variable resolved true — the same "From node
// reaches its own terminal state" semantics groundAttackGraph/bamcpGround
// already ground an enablement edge's SOURCE side on, belief_slice_native.go).
// Success reports whether the effect — the edge type's declared TARGET
// variable on its destination node — was ALSO observed true.
//
// One EdgeOutcome is one row, the same granularity train.go's Row is one
// observed host: FitEdgePosteriors aggregates by EdgeType itself, so a
// caller (e.g. a Timeline-derived extraction, or a fixture/synthetic
// dataset) never needs to pre-aggregate counts. json tags match
// cmd/belief-trainer's -edge-outcomes input format.
type EdgeOutcome struct {
	EdgeType string `json:"edge_type"`
	Success  bool   `json:"success"`
}

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
// (ADR-0037 decisions 2 and 5, gibson#395). It is what a mission pins for
// replay: see (*EdgePosteriorArtifact).Provider.
type EdgePosteriorArtifact struct {
	Version     string                       `json:"version"`
	Description string                       `json:"description,omitempty"`
	Posteriors  map[string]edgePosteriorJSON `json:"posteriors"`
}

// EdgePosteriorTrainResult is the outcome of one offline edge-posterior
// training run (mirrors TrainResult for the belief-CPT model).
type EdgePosteriorTrainResult struct {
	Version  string // the per-tenant version stamped, e.g. "tenant-acme-edges-v3"
	Path     string // where the artifact was written
	Outcomes int    // recorded outcomes the fit consumed
	Artifact *EdgePosteriorArtifact
}

// FitEdgePosteriors fits a Beta(alpha,beta) posterior per distinct edge type
// present in outcomes, by the standard Beta-Bernoulli conjugate update from
// the uninformative Beta(1,1) prior brain.UninformativeEdgePosteriors already
// establishes (ADR-0037 decision 3) — read from it directly rather than
// re-declared, so this fit's starting prior and the belief runtime's
// cold-start fallback are structurally the same number.
//
// version is the full artifact version string the caller assigns (e.g.
// "tenant-acme-edges-v3"); it is what a mission pins and what replay
// re-loads. An edge type with zero recorded outcomes gets no entry: the
// runtime provider (Provider) falls back to the same uninformative prior for
// any type absent from Posteriors, so writing out a redundant Beta(1,1) row
// would be dead weight, not a real fitted value.
func FitEdgePosteriors(outcomes []EdgeOutcome, version string) (*EdgePosteriorArtifact, error) {
	if version == "" {
		return nil, errors.New("braintrain: empty version")
	}

	prior := brain.UninformativeEdgePosteriors{}.Posterior("")

	type counts struct{ successes, failures float64 }
	byType := map[string]counts{}
	for _, o := range outcomes {
		c := byType[o.EdgeType]
		if o.Success {
			c.successes++
		} else {
			c.failures++
		}
		byType[o.EdgeType] = c
	}

	posteriors := make(map[string]edgePosteriorJSON, len(byType))
	for edgeType, c := range byType {
		posteriors[edgeType] = edgePosteriorJSON{
			Alpha: prior.Alpha + c.successes,
			Beta:  prior.Beta + c.failures,
		}
	}

	return &EdgePosteriorArtifact{
		Version: version,
		Description: fmt.Sprintf(
			"Per-edge-type Beta posterior trained offline from %d recorded outcomes across %d edge types "+
				"(gibson#395, ADR-0037). Beta-Bernoulli update from an uninformative Beta(%.1f,%.1f) prior.",
			len(outcomes), len(byType), prior.Alpha, prior.Beta,
		),
		Posteriors: posteriors,
	}, nil
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

// Write serialises the artifact to path as indented JSON (matching
// artifact.go's Write style so artifacts diff cleanly).
func (a *EdgePosteriorArtifact) Write(path string) error {
	if err := a.validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return fmt.Errorf("braintrain: encode edge posterior artifact: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return fmt.Errorf("braintrain: write edge posterior artifact: %w", err)
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
// (ADR-0037 decision 4, "one output, two uses"). An edge type with no fitted
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

// edgePosteriorVersionPrefix is the per-tenant edge-posterior artifact
// filename prefix — distinct from tenantVersionPrefix's belief-CPT-model
// "tenant-<id>-v" prefix so the two artifact kinds never collide in the same
// modelsDir and a directory listing tells them apart at a glance.
func edgePosteriorVersionPrefix(tenant string) string {
	return "tenant-" + sanitizeTenant(tenant) + "-edges-v"
}

// NextEdgePosteriorVersion scans modelsDir for existing
// `tenant-<id>-edges-v<n>.json` artifacts and returns the next version string
// (one past the highest n; v1 if none) — mirrors NextVersion exactly, for the
// edge-posterior artifact kind. Past versions are never reused, so a mission
// that pinned vN can always re-load it.
func NextEdgePosteriorVersion(modelsDir, tenant string) string {
	return nextVersionWithPrefix(modelsDir, edgePosteriorVersionPrefix(tenant))
}

// TrainTenantEdgePosteriors fits a NEW versioned per-tenant edge-posterior
// artifact from a tenant's recorded (cause-active -> effect-observed?)
// outcomes and writes it to modelsDir (ADR-0006's per-tenant discipline,
// ADR-0037 decisions 2 and 5). tenant must be the SAME tenant whose outcomes
// came from — the caller guarantees this, mirroring TrainTenant's own
// contract; no cross-tenant pooling.
func TrainTenantEdgePosteriors(tenant string, outcomes []EdgeOutcome, modelsDir string) (*EdgePosteriorTrainResult, error) {
	if strings.TrimSpace(tenant) == "" {
		return nil, errors.New("braintrain: empty tenant")
	}
	version := NextEdgePosteriorVersion(modelsDir, tenant)
	fitted, err := FitEdgePosteriors(outcomes, version)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(modelsDir, 0o750); err != nil {
		return nil, fmt.Errorf("braintrain: create models dir: %w", err)
	}
	path := filepath.Join(modelsDir, version+".json")
	if err := fitted.Write(path); err != nil {
		return nil, err
	}
	return &EdgePosteriorTrainResult{Version: version, Path: path, Outcomes: len(outcomes), Artifact: fitted}, nil
}
