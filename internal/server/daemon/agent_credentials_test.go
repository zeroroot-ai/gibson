// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
)

type fakeProviderStore struct {
	providerconfig.ProviderConfigStore
	configs []*providerconfig.ProviderConfig
	secrets map[string]map[string]string // name -> credentials
}

func (f *fakeProviderStore) List(_ context.Context, _ string) ([]*providerconfig.ProviderConfig, error) {
	return f.configs, nil
}

func (f *fakeProviderStore) Resolve(_ context.Context, _, name string) (*providerconfig.DecryptedConfig, error) {
	for _, c := range f.configs {
		if c.Name == name {
			return &providerconfig.DecryptedConfig{ProviderConfig: *c, Credentials: f.secrets[name]}, nil
		}
	}
	return nil, errors.New("not found")
}

func TestProviderCredentialSource(t *testing.T) {
	anthropic := &providerconfig.ProviderConfig{Name: "anthropic-prod", Type: llm.ProviderType("anthropic"), Enabled: true}
	openai := &providerconfig.ProviderConfig{Name: "oai", Type: llm.ProviderType("openai"), Enabled: true}
	secrets := map[string]map[string]string{"anthropic-prod": {"api_key": "sk-ant-1"}}

	t.Run("the only enabled provider of the type wins", func(t *testing.T) {
		s := &providerCredentialSource{store: &fakeProviderStore{configs: []*providerconfig.ProviderConfig{openai, anthropic}, secrets: secrets}}
		got, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key")
		if err != nil || got != "sk-ant-1" {
			t.Fatalf("got %q, %v; want the anthropic key", got, err)
		}
	})

	t.Run("no provider of the type is ErrTenantCredentialMissing", func(t *testing.T) {
		s := &providerCredentialSource{store: &fakeProviderStore{configs: []*providerconfig.ProviderConfig{openai}}}
		_, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key")
		if !errors.Is(err, harness.ErrTenantCredentialMissing) {
			t.Fatalf("err = %v, want ErrTenantCredentialMissing", err)
		}
	})

	t.Run("two enabled providers with no default is refused, the default wins when set", func(t *testing.T) {
		second := &providerconfig.ProviderConfig{Name: "anthropic-lab", Type: llm.ProviderType("anthropic"), Enabled: true}
		st := &fakeProviderStore{configs: []*providerconfig.ProviderConfig{anthropic, second}, secrets: map[string]map[string]string{"anthropic-prod": {"api_key": "prod"}, "anthropic-lab": {"api_key": "lab"}}}
		s := &providerCredentialSource{store: st}
		if _, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key"); !errors.Is(err, harness.ErrTenantCredentialMissing) {
			t.Fatalf("err = %v, want a refusal on ambiguity", err)
		}
		second.IsDefault = true
		got, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key")
		if err != nil || got != "lab" {
			t.Fatalf("got %q, %v; want the default provider's key", got, err)
		}
	})

	t.Run("a disabled provider does not count", func(t *testing.T) {
		off := &providerconfig.ProviderConfig{Name: "anthropic-prod", Type: llm.ProviderType("anthropic"), Enabled: false}
		s := &providerCredentialSource{store: &fakeProviderStore{configs: []*providerconfig.ProviderConfig{off}, secrets: secrets}}
		if _, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key"); !errors.Is(err, harness.ErrTenantCredentialMissing) {
			t.Fatalf("err = %v, want ErrTenantCredentialMissing for a disabled provider", err)
		}
	})
}

type failingProviderStore struct {
	providerconfig.ProviderConfigStore
	listErr    error
	resolveErr error
	configs    []*providerconfig.ProviderConfig
}

func (f *failingProviderStore) List(_ context.Context, _ string) ([]*providerconfig.ProviderConfig, error) {
	return f.configs, f.listErr
}

func (f *failingProviderStore) Resolve(_ context.Context, _, _ string) (*providerconfig.DecryptedConfig, error) {
	if f.resolveErr != nil {
		return nil, f.resolveErr
	}
	return &providerconfig.DecryptedConfig{Credentials: map[string]string{}}, nil
}

func TestProviderCredentialSource_Failures(t *testing.T) {
	anthropic := &providerconfig.ProviderConfig{Name: "anthropic-prod", Type: llm.ProviderType("anthropic"), Enabled: true}

	t.Run("nil source and nil store are a missing credential, never a panic", func(t *testing.T) {
		var nilSource *providerCredentialSource
		if _, err := nilSource.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key"); !errors.Is(err, harness.ErrTenantCredentialMissing) {
			t.Fatalf("nil source: err = %v", err)
		}
		empty := &providerCredentialSource{}
		if _, err := empty.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key"); !errors.Is(err, harness.ErrTenantCredentialMissing) {
			t.Fatalf("nil store: err = %v", err)
		}
	})

	t.Run("a store that cannot list is an error, not a missing credential", func(t *testing.T) {
		s := &providerCredentialSource{store: &failingProviderStore{listErr: errors.New("broker down")}}
		_, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key")
		if err == nil || errors.Is(err, harness.ErrTenantCredentialMissing) {
			t.Fatalf("err = %v, want a plain list error", err)
		}
	})

	t.Run("a provider that cannot be decrypted is an error", func(t *testing.T) {
		s := &providerCredentialSource{store: &failingProviderStore{configs: []*providerconfig.ProviderConfig{anthropic}, resolveErr: errors.New("secret unreadable")}}
		if _, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key"); err == nil {
			t.Fatal("want a resolve error")
		}
	})

	t.Run("a provider without the requested key is a missing credential", func(t *testing.T) {
		s := &providerCredentialSource{store: &failingProviderStore{configs: []*providerconfig.ProviderConfig{anthropic}}}
		if _, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key"); !errors.Is(err, harness.ErrTenantCredentialMissing) {
			t.Fatalf("err = %v, want ErrTenantCredentialMissing", err)
		}
	})
}

// TestProviderCredentialSource_ResolvesTheStoreLazily: the harness factory
// is built before the pool and the broker stack exist, so the source must
// bind to the store at first use, not at construction. Until the daemon has
// both, a dispatch is refused with ErrTenantCredentialMissing; once it does,
// the same source resolves without a restart.
func TestProviderCredentialSource_ResolvesTheStoreLazily(t *testing.T) {
	anthropic := &providerconfig.ProviderConfig{Name: "anthropic-prod", Type: llm.ProviderType("anthropic"), Enabled: true}
	var ready providerconfig.ProviderConfigStore
	calls := 0
	s := &providerCredentialSource{resolve: func() (providerconfig.ProviderConfigStore, error) {
		calls++
		if ready != nil {
			return ready, nil
		}
		return nil, errors.New("not up yet")
	}}
	if _, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key"); !errors.Is(err, harness.ErrTenantCredentialMissing) {
		t.Fatalf("before wiring: err = %v, want ErrTenantCredentialMissing", err)
	}
	ready = &fakeProviderStore{configs: []*providerconfig.ProviderConfig{anthropic}, secrets: map[string]map[string]string{"anthropic-prod": {"api_key": "sk-ant-1"}}}
	got, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key")
	if err != nil || got != "sk-ant-1" {
		t.Fatalf("after wiring: got %q, %v; want the anthropic key", got, err)
	}
	if _, err := s.ResolveProviderCredential(context.Background(), "acme", "anthropic", "api_key"); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if calls != 2 {
		t.Errorf("resolve called %d times, want 2 (once while nil, once to bind; then cached)", calls)
	}
}

// TestTenantCredentialResolver_BindsOnceTheDaemonHasPoolAndBroker: the
// daemon-side resolver refuses while either dependency is missing and
// returns a broker-backed store once both are up.
func TestTenantCredentialResolver_BindsOnceTheDaemonHasPoolAndBroker(t *testing.T) {
	d := &daemonImpl{}
	resolve := d.tenantCredentialResolver()
	if _, err := resolve(); err == nil {
		t.Fatal("expected an error with no pool and no broker stack")
	}
	d.pool = &mockPool{}
	if _, err := resolve(); err == nil {
		t.Fatal("expected an error with a pool but no broker stack")
	}
	d.secretsService = &secrets.Service{}
	store, err := resolve()
	if err != nil || store == nil {
		t.Fatalf("store=%v err=%v, want a store once both dependencies exist", store, err)
	}
}
