// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// TestNewVertexProvider_MissingCredentialsIsAnErrorNotAPanic — the Google auth
// the Vertex client uses panics when it can find no Application Default
// Credentials. A tenant misconfiguration must refuse the launch, never take the
// daemon down.
func TestNewVertexProvider_MissingCredentialsIsAnErrorNotAPanic(t *testing.T) {
	// Point the credential path at a file that does not exist, so the lookup
	// fails the same way on a developer machine that happens to have ADC and on
	// a CI runner that does not.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "absent.json"))

	p, err := NewVertexProvider(context.Background(), llm.ProviderConfig{
		Type:         llm.ProviderVertex,
		DefaultModel: "claude-sonnet-4-5",
		Extra:        map[string]string{"vertex_project_id": "proj", "vertex_region": "us-east5"},
	})
	if err == nil {
		t.Fatalf("expected an error with no credentials, got provider %v", p)
	}
	if p != nil {
		t.Errorf("a failed construction must return no provider, got %v", p)
	}
}

// TestNewVertexProvider_NeedsProjectAndRegion — a config that names neither is
// refused before any credential lookup.
func TestNewVertexProvider_NeedsProjectAndRegion(t *testing.T) {
	if _, err := NewVertexProvider(context.Background(), llm.ProviderConfig{
		Type: llm.ProviderVertex, DefaultModel: "m",
	}); err == nil {
		t.Fatal("expected an error when the project and the region are absent")
	}
}

// TestNewFoundryProvider_NeedsAResourceOrABaseURL — Foundry serves the
// Anthropic shape at a per-resource endpoint, so one of the two is required.
func TestNewFoundryProvider_NeedsAResourceOrABaseURL(t *testing.T) {
	if _, err := NewFoundryProvider(context.Background(), llm.ProviderConfig{
		Type: llm.ProviderFoundry, DefaultModel: "m",
		Extra: map[string]string{"foundry_api_key": "k"},
	}); err == nil {
		t.Fatal("expected an error when neither foundry_resource nor base_url is set")
	}
}

// TestNewFoundryProvider_BuildsTheResourceEndpoint — with a resource and a key
// the provider constructs and reports its own name.
func TestNewFoundryProvider_BuildsTheResourceEndpoint(t *testing.T) {
	p, err := NewFoundryProvider(context.Background(), llm.ProviderConfig{
		Type: llm.ProviderFoundry, DefaultModel: "claude-sonnet-4-5",
		Extra: map[string]string{"foundry_api_key": "k", "foundry_resource": "my-resource"},
	})
	if err != nil {
		t.Fatalf("NewFoundryProvider: %v", err)
	}
	if p.Name() != string(llm.ProviderFoundry) {
		t.Errorf("name = %q, want foundry", p.Name())
	}
}

// TestAnthropicProvider_NameDefaults — a provider built without a name still
// reports anthropic, so the registry never sees an empty provider name.
func TestAnthropicProvider_NameDefaults(t *testing.T) {
	p := &AnthropicProvider{}
	if p.Name() != string(llm.ProviderAnthropic) {
		t.Errorf("name = %q, want anthropic", p.Name())
	}
}
