package daemon

import "testing"

// TestResolveBeliefProvider_DefaultsToPlaceholder proves that without the sidecar
// URL the daemon uses the deterministic Go placeholder (OSS-without-base-model),
// so the brain still produces a field with zero external dependencies.
func TestResolveBeliefProvider_DefaultsToPlaceholder(t *testing.T) {
	t.Setenv("GIBSON_BELIEF_SIDECAR_URL", "")
	p := resolveBeliefProvider()
	if got := p.Version(); got != "placeholder-v0" {
		t.Fatalf("default provider version = %q, want placeholder-v0", got)
	}
}

// TestResolveBeliefProvider_PinsConfiguredVersion proves the sidecar provider is
// selected when the URL is set and pins GIBSON_BELIEF_MODEL_VERSION (ADR-0005 §5).
func TestResolveBeliefProvider_PinsConfiguredVersion(t *testing.T) {
	t.Setenv("GIBSON_BELIEF_SIDECAR_URL", "http://127.0.0.1:8087/score")
	t.Setenv("GIBSON_BELIEF_MODEL_VERSION", "base-v3")
	p := resolveBeliefProvider()
	if got := p.Version(); got != "base-v3" {
		t.Fatalf("pinned provider version = %q, want base-v3", got)
	}
}
