package tenantprovider_test

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantprovider"
)

// fakeProvider is a minimal llm.LLMProvider. Real providers name themselves by
// type, so the fake does too — that is the registry key.
type fakeProvider struct{ name string }

func (f *fakeProvider) Name() string                                    { return f.name }
func (f *fakeProvider) Models(context.Context) ([]llm.ModelInfo, error) { return nil, nil }
func (f *fakeProvider) Complete(context.Context, llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return nil, nil
}
func (f *fakeProvider) CompleteWithTools(context.Context, llm.CompletionRequest, []llm.ToolDef) (*llm.CompletionResponse, error) {
	return nil, nil
}
func (f *fakeProvider) Stream(context.Context, llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	return nil, nil
}
func (f *fakeProvider) Health(context.Context) types.HealthStatus { return types.HealthStatus{} }

func factory(cfg llm.ProviderConfig) (llm.LLMProvider, error) {
	return &fakeProvider{name: string(cfg.Type)}, nil
}

type fakeStore struct {
	configs      map[string][]*providerconfig.ProviderConfig
	resolveCalls int
}

func (s *fakeStore) List(_ context.Context, tenant string) ([]*providerconfig.ProviderConfig, error) {
	return s.configs[tenant], nil
}

func (s *fakeStore) Resolve(_ context.Context, tenant, name string) (*providerconfig.DecryptedConfig, error) {
	s.resolveCalls++
	for _, c := range s.configs[tenant] {
		if c.Name == name {
			return &providerconfig.DecryptedConfig{
				ProviderConfig: *c,
				Credentials:    map[string]string{"api_key": "secret-" + name},
			}, nil
		}
	}
	return nil, providerconfig.ErrNotFound
}

func cfg(name string, t llm.ProviderType, isDefault bool) *providerconfig.ProviderConfig {
	return &providerconfig.ProviderConfig{Name: name, Type: t, Enabled: true, IsDefault: isDefault}
}

func newStore() *fakeStore {
	return &fakeStore{configs: map[string][]*providerconfig.ProviderConfig{
		"tenant-a": {cfg("primary-anthropic", llm.ProviderAnthropic, true), cfg("backup-openai", llm.ProviderOpenAI, false)},
		"tenant-b": {cfg("b-google", llm.ProviderGoogle, true)},
	}}
}

func TestResolve_BuildsTenantSetWithDefault(t *testing.T) {
	r := tenantprovider.NewResolver(newStore(), factory)
	set, err := r.Resolve(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := set.Registry.ListProviders()
	if len(names) != 2 {
		t.Fatalf("want 2 providers for tenant-a, got %v", names)
	}
	if set.DefaultName != string(llm.ProviderAnthropic) {
		t.Fatalf("want default %q, got %q", llm.ProviderAnthropic, set.DefaultName)
	}
	if _, err := set.Registry.GetProvider(set.DefaultName); err != nil {
		t.Fatalf("default name %q not resolvable in registry: %v", set.DefaultName, err)
	}
}

func TestResolve_TenantIsolation(t *testing.T) {
	r := tenantprovider.NewResolver(newStore(), factory)
	a, _ := r.Resolve(context.Background(), "tenant-a")
	b, _ := r.Resolve(context.Background(), "tenant-b")

	if _, err := b.Registry.GetProvider(string(llm.ProviderAnthropic)); err == nil {
		t.Fatal("tenant-b must not see tenant-a's anthropic provider")
	}
	if _, err := a.Registry.GetProvider(string(llm.ProviderGoogle)); err == nil {
		t.Fatal("tenant-a must not see tenant-b's google provider")
	}
}

func TestResolve_RequiresTenant(t *testing.T) {
	r := tenantprovider.NewResolver(newStore(), factory)
	if _, err := r.Resolve(context.Background(), ""); err == nil {
		t.Fatal("empty tenant must error")
	}
}

func TestResolve_NoProvidersYieldsEmptySet(t *testing.T) {
	r := tenantprovider.NewResolver(&fakeStore{configs: map[string][]*providerconfig.ProviderConfig{}}, factory)
	set, err := r.Resolve(context.Background(), "tenant-empty")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(set.Registry.ListProviders()) != 0 || set.DefaultName != "" {
		t.Fatalf("want empty set, got providers=%v default=%q", set.Registry.ListProviders(), set.DefaultName)
	}
}

func TestResolve_CachesUntilInvalidated(t *testing.T) {
	store := newStore()
	r := tenantprovider.NewResolver(store, factory)

	_, _ = r.Resolve(context.Background(), "tenant-a")
	callsAfterFirst := store.resolveCalls
	if callsAfterFirst == 0 {
		t.Fatal("first resolve should hit the store")
	}

	_, _ = r.Resolve(context.Background(), "tenant-a")
	if store.resolveCalls != callsAfterFirst {
		t.Fatal("second resolve should be served from cache (no store hits)")
	}

	r.Invalidate("tenant-a")
	_, _ = r.Resolve(context.Background(), "tenant-a")
	if store.resolveCalls <= callsAfterFirst {
		t.Fatal("after invalidate, resolve should rebuild from the store")
	}
}
