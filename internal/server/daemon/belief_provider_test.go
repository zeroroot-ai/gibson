// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

// TestResolveSliceBeliefProvider_IsTheDeterministicPlaceholder pins today's
// documented state (belief_provider.go): the graph-coupled SliceBeliefProvider
// is always the placeholder until the ontology's per-edge-type target
// variable and noisy-OR strength/leak parameters exist for ground.py to
// consume (gibson#275/#288).
func TestResolveSliceBeliefProvider_IsTheDeterministicPlaceholder(t *testing.T) {
	p := resolveSliceBeliefProvider()
	if got := p.Version(); got != "placeholder-slice-v0" {
		t.Fatalf("resolveSliceBeliefProvider version = %q, want placeholder-slice-v0", got)
	}
}

// TestNewBeliefSchemaRegistry_RegistersTheCoreSeed proves the daemon's
// belief-schema registry is the real, shipped core seed (gibson#296) — Host
// belief-bearing with the reachable/exploitable/juicy funnel — not an empty
// or hand-rolled registry.
func TestNewBeliefSchemaRegistry_RegistersTheCoreSeed(t *testing.T) {
	reg, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	if !reg.IsBeliefBearing("Host") {
		t.Fatalf("registry does not declare Host belief-bearing")
	}
	if !reg.IsEnablementEdge("RESOLVES_TO") {
		t.Fatalf("registry does not declare RESOLVES_TO an enablement edge")
	}
}
