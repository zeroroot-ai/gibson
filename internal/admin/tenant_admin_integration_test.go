package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/secrets"

	adminv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/admin/v1"
	"github.com/zero-day-ai/sdk/auth"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
)

// This file is the regression-guard for the spec's central bug.
//
// Before this spec, SetBrokerConfig persisted the row but did not invalidate
// the secrets.Registry's per-tenant cache. The next call to Registry.For
// returned the *previously* cached provider until the daemon restarted —
// meaning a tenant who switched from Postgres to Vault would keep hitting
// Postgres for every Resolve/Put/Delete/List until the next pod restart.
//
// These tests drive the full handler → real Registry path and assert that
// the post-Set Registry.For returns the just-configured provider, not the
// stale one.

// ---------------------------------------------------------------------------
// In-memory fakes
// ---------------------------------------------------------------------------

// inMemoryConfigGetter implements secrets.RegistryConfigGetter and is also
// the writer side: SetBrokerConfig's writer.Set calls update the same map
// the Registry reads on Reload.
type inMemoryConfigGetter struct {
	rows map[auth.TenantID]secrets.BrokerConfig
}

func (g *inMemoryConfigGetter) Get(_ context.Context, tenant auth.TenantID) (secrets.BrokerConfig, error) {
	if row, ok := g.rows[tenant]; ok {
		return row, nil
	}
	return secrets.BrokerConfig{}, secrets.ErrBrokerConfigNotFound
}

// memoryWriter implements admin.TenantConfigStoreWriter by writing into the
// same map inMemoryConfigGetter reads from. This is the closest thing to
// "real ConfigStore" without standing up a Postgres.
type memoryWriter struct {
	getter *inMemoryConfigGetter
}

func (w *memoryWriter) Set(_ context.Context, tenant auth.TenantID, cfg secrets.BrokerConfig, _ string) error {
	w.getter.rows[tenant] = cfg
	return nil
}

// labelledBroker is a sentinel SecretsBroker that records which factory
// produced it so tests can assert which provider Registry.For returned.
type labelledBroker struct{ label string }

func (b *labelledBroker) Get(context.Context, auth.TenantID, string) ([]byte, error) {
	return []byte(b.label), nil
}
func (b *labelledBroker) Put(context.Context, auth.TenantID, string, []byte) error { return nil }
func (b *labelledBroker) Delete(context.Context, auth.TenantID, string) error      { return nil }
func (b *labelledBroker) List(context.Context, auth.TenantID, sdksecrets.Filter) ([]string, error) {
	return nil, nil
}
func (b *labelledBroker) Health(context.Context) error { return nil }
func (b *labelledBroker) Probe(context.Context) error  { return nil }
func (b *labelledBroker) Capabilities() sdksecrets.Capabilities {
	return sdksecrets.Capabilities{}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRegistry_ReloadInvalidatesCache is the minimal regression-guard at the
// Registry level. It does not involve the admin handler — it just asserts
// that the cache invalidation primitive works. If Registry.Reload ever
// regresses to a no-op, this test fails before any handler-level test even
// runs.
func TestRegistry_ReloadInvalidatesCache(t *testing.T) {
	awssmFake := &labelledBroker{label: "awssm"}
	vaultFake := &labelledBroker{label: "vault"}

	tenant := mustTenant(t, "acme")
	// gibson#101: every tenant needs an explicit broker config row.
	getter := &inMemoryConfigGetter{rows: map[auth.TenantID]secrets.BrokerConfig{
		tenant: {Provider: "awssm", ConfigBlob: []byte(`{}`)},
	}}
	reg, err := secrets.NewRegistry(getter, secrets.RegistryConfig{
		AWSSMFactory: func(_ []byte) (sdksecrets.Broker, error) {
			return awssmFake, nil
		},
		VaultFactory: func(_ []byte) (sdksecrets.Broker, error) {
			return vaultFake, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	ctx := context.Background()

	// Initial state: explicit awssm config row → awssm provider.
	got, err := reg.For(ctx, tenant)
	if err != nil {
		t.Fatalf("For(initial): %v", err)
	}
	if got != awssmFake {
		t.Fatalf("initial: got %v, want awssm fake", got)
	}

	// Simulate writer.Set landing a vault row.
	getter.rows[tenant] = secrets.BrokerConfig{
		Provider:   "vault",
		ConfigBlob: []byte(`{"address":"https://vault"}`),
	}

	// Without Reload, the Registry still returns the cached awssm provider
	// (this is the pre-spec bug surface).
	got, _ = reg.For(ctx, tenant)
	if got != awssmFake {
		t.Fatalf("pre-Reload: cache should still be awssm, got %v", got)
	}

	// Reload invalidates the cache.
	reg.Reload(ctx, tenant)

	got, err = reg.For(ctx, tenant)
	if err != nil {
		t.Fatalf("For(post-Reload): %v", err)
	}
	if got != vaultFake {
		t.Fatalf("post-Reload: got %v, want vault fake", got)
	}
}

// TestSetBrokerConfig_PersistAndReload_FullPath drives the handler through
// the full Set flow against a real secrets.Registry and asserts that the
// post-Set Registry.For returns the new provider. Without task 6's Reload
// call, this test fails at the post-Set assertion — that is the regression
// this spec exists to prevent.
func TestSetBrokerConfig_PersistAndReload_FullPath(t *testing.T) {
	awssmFake := &labelledBroker{label: "awssm"}
	vaultFake := &labelledBroker{label: "vault"}

	getter := &inMemoryConfigGetter{rows: map[auth.TenantID]secrets.BrokerConfig{}}
	reg, err := secrets.NewRegistry(getter, secrets.RegistryConfig{
		AWSSMFactory: func(_ []byte) (sdksecrets.Broker, error) {
			return awssmFake, nil
		},
		VaultFactory: func(_ []byte) (sdksecrets.Broker, error) {
			return vaultFake, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	srv, err := NewTenantAdminServer(TenantAdminConfig{
		Reader:         getter,
		Writer:         &memoryWriter{getter: getter},
		ProbeFactory:   &fakeProbeFactory{}, // probe always succeeds
		Auditor:        &fakeAuditor{},
		Reloader:       reg, // <- the production Registry
		SecretsService: &fakeSecretsLister{},
		Now:            func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewTenantAdminServer: %v", err)
	}

	tenant := mustTenant(t, "acme")
	ctx := withTenant(t, "acme")

	// gibson#101: seed an explicit awssm row. The "pre-Set" assertion
	// below remains valid.
	getter.rows[tenant] = secrets.BrokerConfig{
		Provider: "awssm", ConfigBlob: []byte(`{}`),
	}

	// Initial: explicit awssm row → awssm provider.
	if got, _ := reg.For(ctx, tenant); got != awssmFake {
		t.Fatalf("pre-Set: got %v, want awssm", got)
	}

	// Drive SetBrokerConfig with a vault candidate.
	if _, err := srv.SetBrokerConfig(ctx, &adminv1.SetBrokerConfigRequest{
		Candidate: &adminv1.CandidateConfig{
			Provider:   adminv1.BrokerProvider_BROKER_PROVIDER_VAULT,
			Address:    "https://vault",
			VaultToken: []byte("hvs.xyz"),
		},
	}); err != nil {
		t.Fatalf("SetBrokerConfig: %v", err)
	}

	// CRITICAL: post-Set, Registry.For MUST return the vault fake. If
	// SetBrokerConfig didn't call Reload, the cache still serves awssm
	// and the test fails.
	got, err := reg.For(ctx, tenant)
	if err != nil {
		t.Fatalf("For(post-Set): %v", err)
	}
	if got != vaultFake {
		t.Fatalf("post-Set: cache not invalidated — got %v, want vault fake (the spec's central regression)", got)
	}
}

// TestSetBrokerConfig_PersistFailure_NoReload_FullPath asserts that when
// the writer fails (e.g., DB down), the cache is NOT invalidated. The
// handler must report the persist failure and leave the cached provider
// alone — invalidating after a failed write would be lying about state.
func TestSetBrokerConfig_PersistFailure_NoReload_FullPath(t *testing.T) {
	awssmFake := &labelledBroker{label: "awssm"}
	vaultFake := &labelledBroker{label: "vault"}

	getter := &inMemoryConfigGetter{rows: map[auth.TenantID]secrets.BrokerConfig{}}
	reg, err := secrets.NewRegistry(getter, secrets.RegistryConfig{
		AWSSMFactory: func(_ []byte) (sdksecrets.Broker, error) {
			return awssmFake, nil
		},
		VaultFactory: func(_ []byte) (sdksecrets.Broker, error) {
			return vaultFake, nil
		},
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	failingWriter := &fakeTenantConfigWriter{err: errors.New("db unavailable")}

	srv, err := NewTenantAdminServer(TenantAdminConfig{
		Reader:         getter,
		Writer:         failingWriter,
		ProbeFactory:   &fakeProbeFactory{},
		Auditor:        &fakeAuditor{},
		Reloader:       reg,
		SecretsService: &fakeSecretsLister{},
		Now:            func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewTenantAdminServer: %v", err)
	}

	tenant := mustTenant(t, "acme")
	ctx := withTenant(t, "acme")

	// gibson#101: seed an explicit awssm row so the warm-up path
	// resolves cleanly.
	getter.rows[tenant] = secrets.BrokerConfig{
		Provider: "awssm", ConfigBlob: []byte(`{}`),
	}

	// Warm the cache with the configured awssm provider.
	if got, _ := reg.For(ctx, tenant); got != awssmFake {
		t.Fatalf("warm-up: got %v, want awssm", got)
	}

	// Drive SetBrokerConfig — writer fails.
	_, err = srv.SetBrokerConfig(ctx, &adminv1.SetBrokerConfigRequest{
		Candidate: &adminv1.CandidateConfig{
			Provider:   adminv1.BrokerProvider_BROKER_PROVIDER_VAULT,
			Address:    "https://vault",
			VaultToken: []byte("hvs.xyz"),
		},
	})
	if err == nil {
		t.Fatal("expected SetBrokerConfig to fail on writer error")
	}

	// The cache should still serve awssm — Reload must not have fired.
	if got, _ := reg.For(ctx, tenant); got != awssmFake {
		t.Fatalf("post-failure: cache should still be awssm, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustTenant(t *testing.T, raw string) auth.TenantID {
	t.Helper()
	id, err := auth.NewTenantID(raw)
	if err != nil {
		t.Fatalf("NewTenantID(%q): %v", raw, err)
	}
	return id
}

// withTenant returns a context with the given tenant attached, mirroring
// ctxWithTenant in tenant_admin_test.go but without the identity bits the
// other tests need.
func withTenant(t *testing.T, raw string) context.Context {
	t.Helper()
	return ctxWithTenant(t, raw)
}
