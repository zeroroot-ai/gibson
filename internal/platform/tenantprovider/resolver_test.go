// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantprovider_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantprovider"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	// resolveErr[name] simulates a provider that IS configured (present in
	// List) but whose credential cannot be resolved — e.g. the secrets broker
	// is down or the secret never persisted.
	resolveErr map[string]error
}

func (s *fakeStore) List(_ context.Context, tenant string) ([]*providerconfig.ProviderConfig, error) {
	return s.configs[tenant], nil
}

func (s *fakeStore) Resolve(_ context.Context, tenant, name string) (*providerconfig.DecryptedConfig, error) {
	s.resolveCalls++
	if err, ok := s.resolveErr[name]; ok {
		return nil, err
	}
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
	r := tenantprovider.NewResolver(newStore(), factory, false, nil)
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
	r := tenantprovider.NewResolver(newStore(), factory, false, nil)
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
	r := tenantprovider.NewResolver(newStore(), factory, false, nil)
	if _, err := r.Resolve(context.Background(), ""); err == nil {
		t.Fatal("empty tenant must error")
	}
}

func TestResolve_NoProvidersYieldsEmptySet(t *testing.T) {
	r := tenantprovider.NewResolver(&fakeStore{configs: map[string][]*providerconfig.ProviderConfig{}}, factory, false, nil)
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
	r := tenantprovider.NewResolver(store, factory, false, nil)

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

// TestBuild_ConfiguredButUnresolvable_IsRecorded is the failing fixture for the
// de-masking fix: a provider that is configured (present in List) but whose
// credential cannot be resolved (broker down / secret never persisted) must be
// RECORDED in set.Skipped with the real reason, not silently dropped — a silent
// drop is what surfaced downstream as the misleading "provider not found".
func TestBuild_ConfiguredButUnresolvable_IsRecorded(t *testing.T) {
	store := &fakeStore{
		configs: map[string][]*providerconfig.ProviderConfig{
			"tenant-a": {cfg("anthropic", llm.ProviderAnthropic, true)},
		},
		resolveErr: map[string]error{
			"anthropic": errors.New("secrets circuit open: secrets: unavailable"),
		},
	}
	r := tenantprovider.NewResolver(store, factory, false, nil)

	set, err := r.Resolve(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if _, gErr := set.Registry.GetProvider("anthropic"); gErr == nil {
		t.Fatal("expected anthropic absent from the registry (credential unresolvable)")
	}
	reason, ok := set.Skipped["anthropic"]
	if !ok {
		t.Fatal("expected anthropic recorded in set.Skipped, not silently dropped")
	}
	if !strings.Contains(reason.Error(), "credential unreadable") {
		t.Errorf("skip reason should name the real cause; got %v", reason)
	}
}

// TestResolve_TransientSkip_NotCached is the regression fixture for the actual
// incident: a provider skipped during a transient broker outage must NOT be
// cached, so the next resolve picks it up once the broker recovers. Caching the
// incomplete set is what froze a 15-minute OpenBao blip into a permanent
// "provider not found: anthropic".
func TestResolve_TransientSkip_NotCached(t *testing.T) {
	store := &fakeStore{
		configs: map[string][]*providerconfig.ProviderConfig{
			"tenant-a": {cfg("anthropic", llm.ProviderAnthropic, true)},
		},
		resolveErr: map[string]error{
			"anthropic": errors.New("secrets circuit open: secrets: unavailable"),
		},
	}
	r := tenantprovider.NewResolver(store, factory, false, nil)

	// During the outage: anthropic is skipped.
	set1, err := r.Resolve(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if _, gErr := set1.Registry.GetProvider("anthropic"); gErr == nil {
		t.Fatal("anthropic should be absent while the broker is unavailable")
	}

	// Broker recovers.
	store.resolveErr = nil

	// The transient-incomplete set must not have been cached, so this rebuilds
	// and now resolves anthropic.
	set2, err := r.Resolve(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if _, gErr := set2.Registry.GetProvider(string(llm.ProviderAnthropic)); gErr != nil {
		t.Fatalf("after broker recovery anthropic must resolve; got %v", gErr)
	}
}

// TestResolve_FactoryFailure_RecordedAndCached covers the factory-failure skip
// branch: a build error is permanent (not transient), so it is recorded in
// Skipped, the provider is absent, and — unlike a transient skip — the set IS
// cached (retrying the same bad config would not help; fixing it invalidates).
func TestResolve_FactoryFailure_RecordedAndCached(t *testing.T) {
	store := &fakeStore{configs: map[string][]*providerconfig.ProviderConfig{
		"tenant-a": {cfg("anthropic", llm.ProviderAnthropic, true)},
	}}
	failFactory := func(llm.ProviderConfig) (llm.LLMProvider, error) {
		return nil, errors.New("unsupported model configuration")
	}
	r := tenantprovider.NewResolver(store, failFactory, false, nil)

	set, err := r.Resolve(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := set.Skipped["anthropic"]; !ok {
		t.Fatal("a factory failure must be recorded in Skipped")
	}
	if _, gErr := set.Registry.GetProvider("anthropic"); gErr == nil {
		t.Fatal("a provider whose factory failed must be absent from the registry")
	}
	before := store.resolveCalls
	if _, err := r.Resolve(context.Background(), "tenant-a"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if store.resolveCalls != before {
		t.Fatal("a permanently-incomplete set should be cached (no re-resolve)")
	}
}

// TestResolve_TransientViaGRPCStatus_NotCached covers the codes.Unavailable
// classifier path: the secrets Service maps a broker outage to a gRPC status
// error, which must be treated as transient (not cached) so it recovers.
func TestResolve_TransientViaGRPCStatus_NotCached(t *testing.T) {
	store := &fakeStore{
		configs: map[string][]*providerconfig.ProviderConfig{
			"tenant-a": {cfg("anthropic", llm.ProviderAnthropic, true)},
		},
		resolveErr: map[string]error{
			"anthropic": status.Error(codes.Unavailable, "broker down"),
		},
	}
	r := tenantprovider.NewResolver(store, factory, false, nil)

	set1, err := r.Resolve(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if _, gErr := set1.Registry.GetProvider("anthropic"); gErr == nil {
		t.Fatal("anthropic should be skipped during the codes.Unavailable outage")
	}
	store.resolveErr = nil
	set2, err := r.Resolve(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if _, gErr := set2.Registry.GetProvider(string(llm.ProviderAnthropic)); gErr != nil {
		t.Fatalf("after recovery anthropic must resolve; got %v", gErr)
	}
}

// TestResolve_DuplicateRegistration_Recorded covers the registration-failed
// skip branch: two configs of the same provider type build providers with the
// same registry name, so the second RegisterProvider fails and is recorded.
func TestResolve_DuplicateRegistration_Recorded(t *testing.T) {
	store := &fakeStore{configs: map[string][]*providerconfig.ProviderConfig{
		"tenant-a": {
			cfg("anthropic-primary", llm.ProviderAnthropic, true),
			cfg("anthropic-backup", llm.ProviderAnthropic, false),
		},
	}}
	r := tenantprovider.NewResolver(store, factory, false, nil)

	set, err := r.Resolve(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// The factory names both by type ("anthropic"); the second registration is a
	// duplicate and must be recorded, not silently dropped.
	if len(set.Skipped) == 0 {
		t.Fatal("expected the duplicate registration to be recorded in Skipped")
	}
	var sawRegFail bool
	for _, e := range set.Skipped {
		if strings.Contains(e.Error(), "registration failed") {
			sawRegFail = true
		}
	}
	if !sawRegFail {
		t.Fatalf("expected a 'registration failed' skip reason; got %v", set.Skipped)
	}
}

// TestResolve_NilResolve_SkippedNotTransient covers the (nil, nil) resolve path
// (a provider present in List whose credential resolves to nothing without an
// error): it is skipped and recorded, and — not being a transient error — the
// set is cached. This also exercises isTransientResolveErr's nil guard.
func TestResolve_NilResolve_SkippedNotTransient(t *testing.T) {
	store := &fakeStore{
		configs: map[string][]*providerconfig.ProviderConfig{
			"tenant-a": {cfg("anthropic", llm.ProviderAnthropic, true)},
		},
		resolveErr: map[string]error{"anthropic": nil}, // Resolve returns (nil, nil)
	}
	r := tenantprovider.NewResolver(store, factory, false, nil)

	set, err := r.Resolve(context.Background(), "tenant-a")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if _, ok := set.Skipped["anthropic"]; !ok {
		t.Fatal("a (nil, nil) resolve must be recorded in Skipped")
	}
	before := store.resolveCalls
	if _, err := r.Resolve(context.Background(), "tenant-a"); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if store.resolveCalls != before {
		t.Fatal("a non-transient skip should be cached (no re-resolve)")
	}
}
