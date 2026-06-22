package daemon

import (
	"os"

	"github.com/zeroroot-ai/gibson/internal/brain"
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
