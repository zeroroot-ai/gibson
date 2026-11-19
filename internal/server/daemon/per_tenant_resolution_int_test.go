// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
)

// intStore is a provider record store for the per-tenant integration test.
type intStore struct {
	configs map[string][]*providerconfig.ProviderConfig
}

func (s *intStore) List(_ context.Context, tenant string) ([]*providerconfig.ProviderConfig, error) {
	return s.configs[tenant], nil
}

// TestPerTenantResolution_EndToEnd exercises the per-tenant model path that the
// daemon wires for each mission: the provider records of the tenant, the slot
// providers that they give, a per-tenant DaemonSlotManager, and ResolveSlot. A
// tenant with a configured provider resolves its primary slot. A tenant with
// none fails fast with the actionable message.
func TestPerTenantResolution_EndToEnd(t *testing.T) {
	store := &intStore{configs: map[string][]*providerconfig.ProviderConfig{
		"tenant-with": {{
			Name: "anthropic", Type: providerconfig.ProviderAnthropic, Enabled: true, IsDefault: true,
			DefaultModel: "anthropic-model", DefaultModelContextWindow: 200000,
		}},
		// "tenant-none" is absent: it has no configured providers.
	}}
	slot := agent.NewSlotDefinition("primary", "primary", true)
	ctx := context.Background()

	managerFor := func(tenant string) *DaemonSlotManager {
		recs, err := store.List(ctx, tenant)
		require.NoError(t, err)
		providers, defaultName := SlotProvidersFromRecords(recs)
		return NewDaemonSlotManager(providers, slotTestLogger()).WithDefaultProvider(defaultName)
	}

	t.Run("tenant with a provider resolves the primary slot", func(t *testing.T) {
		picked, err := managerFor("tenant-with").ResolveSlot(ctx, slot, nil)
		require.NoError(t, err, "a tenant with a configured provider must resolve its primary slot")
		assert.Equal(t, string(providerconfig.ProviderAnthropic), picked.Provider)
		assert.Equal(t, "anthropic-model", picked.Model)
	})

	t.Run("tenant with no provider fails fast with an actionable message", func(t *testing.T) {
		_, err := managerFor("tenant-none").ResolveSlot(ctx, slot, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Settings → Providers")
	})

	t.Run("a tenant never resolves the provider of another tenant", func(t *testing.T) {
		_, err := managerFor("tenant-none").ResolveSlot(ctx, slot, &agent.SlotConfig{Provider: "anthropic"})
		require.Error(t, err)
	})
}
