// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// agent_floor_real_resolver_test.go — gibson#1193, review N1 and N2.
//
// A dispatched agent with a context floor (cve-triage declares 32000) is
// measured against the window stored with the tenant's saved model. The chain
// here is real from the manifest to the provider: the embedded cve-triage
// manifest, harness.CatalogAgentResolver, slotModelResolver, DaemonSlotManager,
// tenantprovider.Resolver and the production provider factory. Only the
// provider store is a fixture.

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/providers"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantprovider"
	"github.com/zeroroot-ai/sdk/auth"
)

type floorStore struct {
	cfg *providerconfig.ProviderConfig
}

func (s *floorStore) List(context.Context, string) ([]*providerconfig.ProviderConfig, error) {
	return []*providerconfig.ProviderConfig{s.cfg}, nil
}

func (s *floorStore) Resolve(context.Context, string, string) (*providerconfig.DecryptedConfig, error) {
	return &providerconfig.DecryptedConfig{ProviderConfig: *s.cfg, Credentials: map[string]string{"api_key": "k"}}, nil
}

// realFloorChain wires the production objects for one tenant whose saved
// Anthropic provider has the given model and stored window.
func realFloorChain(t *testing.T, model string, window int) *harness.CatalogAgentResolver {
	t.Helper()
	store := &floorStore{cfg: &providerconfig.ProviderConfig{
		Name: "anthropic", Type: llm.ProviderAnthropic, Enabled: true, IsDefault: true,
		DefaultModel: model, DefaultModelContextWindow: window,
	}}
	tp := tenantprovider.NewResolver(store, providers.NewProvider, false, slog.New(slog.DiscardHandler))
	forTenant := func(ctx context.Context, tenant string) (llm.SlotManager, llm.LLMRegistry, error) {
		set, err := tp.Resolve(ctx, tenant)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve: %w", err)
		}
		sm := NewDaemonSlotManager(set.Registry, slog.New(slog.DiscardHandler)).WithDefaultProvider(set.DefaultName)
		return sm, set.Registry, nil
	}
	return harness.NewCatalogAgentResolver("agent", nil).
		WithTenantModelResolver(&slotModelResolver{forTenant: forTenant})
}

func dispatchCVETriage(r *harness.CatalogAgentResolver) (string, error) {
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	spec, err := r.ResolveAgentLaunchSpec(ctx, harness.AgentLaunchRequest{AgentName: "cve-triage", Mode: harness.ModeOneShot})
	if err != nil {
		return "", fmt.Errorf("dispatch: %w", err)
	}
	return spec.Model, nil
}

func TestCVETriageFloor_PassesWithAStoredWindowThatClearsIt(t *testing.T) {
	model, err := dispatchCVETriage(realFloorChain(t, "claude-saved", 200000))
	require.NoError(t, err, "a stored window of 200000 clears the floor of 32000")
	assert.Equal(t, "claude-saved", model)
}

func TestCVETriageFloor_FailsWithAStoredWindowBelowIt(t *testing.T) {
	_, err := dispatchCVETriage(realFloorChain(t, "claude-small", 8192))
	require.Error(t, err, "the slot constraint is real again: a stored window below the floor is refused")
	assert.Contains(t, err.Error(), "8192")
	assert.Contains(t, err.Error(), "32000")
}

func TestCVETriageFloor_FailsWithNoStoredWindowAndTellsThePersonToSaveAgain(t *testing.T) {
	_, err := dispatchCVETriage(realFloorChain(t, "claude-legacy", 0))
	require.Error(t, err, "an unproven window never clears a floor")
	require.ErrorIs(t, err, harness.ErrModelBelowFloor)
	assert.Contains(t, err.Error(), "Settings, Providers")
	assert.Contains(t, err.Error(), "claude-legacy")
}

func TestCVETriageFloor_APinnedModelOtherThanTheSavedOneIsUnproven(t *testing.T) {
	// A stored window belongs to the saved model only. Another model has no
	// stored window, so it cannot clear a floor.
	ctx := auth.ContextWithTenantString(context.Background(), "acme")
	model, window, err := (&slotModelResolver{forTenant: func(ctx context.Context, tenant string) (llm.SlotManager, llm.LLMRegistry, error) {
		tp := tenantprovider.NewResolver(&floorStore{cfg: &providerconfig.ProviderConfig{
			Name: "anthropic", Type: llm.ProviderAnthropic, Enabled: true, IsDefault: true,
			DefaultModel: "claude-saved", DefaultModelContextWindow: 200000,
		}}, providers.NewProvider, false, slog.New(slog.DiscardHandler))
		set, err := tp.Resolve(ctx, tenant)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve: %w", err)
		}
		return NewDaemonSlotManager(set.Registry, slog.New(slog.DiscardHandler)).WithDefaultProvider(set.DefaultName), set.Registry, nil
	}}).ResolveAgentModel(ctx, "acme", "some-other-model", 32000)
	require.NoError(t, err)
	assert.Equal(t, "some-other-model", model)
	assert.Zero(t, window, "the window of a model other than the saved one is unknown")
}
