package daemon

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/tenantprovider"
)

// intStore is a tenantprovider.Store for the per-tenant integration test.
type intStore struct {
	configs map[string][]*providerconfig.ProviderConfig
}

func (s *intStore) List(_ context.Context, tenant string) ([]*providerconfig.ProviderConfig, error) {
	return s.configs[tenant], nil
}

func (s *intStore) Resolve(_ context.Context, tenant, name string) (*providerconfig.DecryptedConfig, error) {
	for _, c := range s.configs[tenant] {
		if c.Name == name {
			return &providerconfig.DecryptedConfig{ProviderConfig: *c, Credentials: map[string]string{"api_key": "k"}}, nil
		}
	}
	return nil, providerconfig.ErrNotFound
}

// TestPerTenantResolution_EndToEnd exercises the full per-tenant LLM path the
// daemon wires for each mission: TenantProviderResolver -> per-tenant
// DaemonSlotManager -> ResolveSlot. A tenant with a configured provider resolves
// its primary slot; a tenant with none fails fast with the actionable message.
func TestPerTenantResolution_EndToEnd(t *testing.T) {
	store := &intStore{configs: map[string][]*providerconfig.ProviderConfig{
		"tenant-with": {{Name: "anthropic", Type: llm.ProviderAnthropic, Enabled: true, IsDefault: true}},
		// "tenant-none" intentionally absent — no configured providers.
	}}
	factory := func(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
		return provWithModel(string(cfg.Type), string(cfg.Type)+"-model"), nil
	}
	resolver := tenantprovider.NewResolver(store, factory)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	slot := agent.NewSlotDefinition("primary", "primary", true)
	ctx := context.Background()

	t.Run("tenant with a provider resolves the primary slot", func(t *testing.T) {
		set, err := resolver.Resolve(ctx, "tenant-with")
		require.NoError(t, err)
		sm := NewDaemonSlotManager(set.Registry, logger).WithDefaultProvider(set.DefaultName)

		provider, _, err := sm.ResolveSlot(ctx, slot, nil)
		require.NoError(t, err, "a tenant with a configured provider must resolve its primary slot")
		assert.Equal(t, string(llm.ProviderAnthropic), provider.Name())
	})

	t.Run("tenant with no provider fails fast with an actionable message", func(t *testing.T) {
		set, err := resolver.Resolve(ctx, "tenant-none")
		require.NoError(t, err)
		sm := NewDaemonSlotManager(set.Registry, logger)

		_, _, err = sm.ResolveSlot(ctx, slot, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Settings → Providers")
	})
}
