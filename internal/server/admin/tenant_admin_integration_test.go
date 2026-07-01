package admin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/secrets"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
	"github.com/zeroroot-ai/gibson/internal/infra/secrets/vault/brokercodec"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// vaultBlobFactory returns a Registry VaultFactory that hands back one of two
// sentinel brokers depending on the config blob: initialBroker for the bare
// "{}" blob a freshly-seeded row carries, and configuredBroker once the blob
// carries an "address" (the shape SetBrokerConfig persists for a Vault
// candidate). Vault is the only broker backend since gibson#1109, so cache
// invalidation is exercised across two blob shapes of the same provider.
func vaultBlobFactory(initialBroker, configuredBroker sdksecrets.Broker) secrets.ProviderConstructor {
	return func(blob []byte) (sdksecrets.Broker, error) {
		if strings.Contains(string(blob), "address") {
			return configuredBroker, nil
		}
		return initialBroker, nil
	}
}

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
	initialFake := &labelledBroker{label: "vault-initial"}
	configuredFake := &labelledBroker{label: "vault-configured"}

	tenant := mustTenant(t, "acme")
	// gibson#101: every tenant needs an explicit broker config row.
	getter := &inMemoryConfigGetter{rows: map[auth.TenantID]secrets.BrokerConfig{
		tenant: {Provider: "vault", ConfigBlob: []byte(`{}`)},
	}}
	reg, err := secrets.NewRegistry(getter, secrets.RegistryConfig{
		VaultFactory: vaultBlobFactory(initialFake, configuredFake),
	})
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}

	ctx := context.Background()

	// Initial state: bare "{}" vault config row → initial provider.
	got, err := reg.For(ctx, tenant)
	if err != nil {
		t.Fatalf("For(initial): %v", err)
	}
	if got != initialFake {
		t.Fatalf("initial: got %v, want initial fake", got)
	}

	// Simulate writer.Set landing a configured vault row.
	getter.rows[tenant] = secrets.BrokerConfig{
		Provider:   "vault",
		ConfigBlob: []byte(`{"address":"https://vault"}`),
	}

	// Without Reload, the Registry still returns the cached initial provider
	// (this is the pre-spec bug surface).
	got, _ = reg.For(ctx, tenant)
	if got != initialFake {
		t.Fatalf("pre-Reload: cache should still be initial, got %v", got)
	}

	// Reload invalidates the cache.
	reg.Reload(ctx, tenant)

	got, err = reg.For(ctx, tenant)
	if err != nil {
		t.Fatalf("For(post-Reload): %v", err)
	}
	if got != configuredFake {
		t.Fatalf("post-Reload: got %v, want configured fake", got)
	}
}

// TestSetBrokerConfig_PersistAndReload_FullPath drives the handler through
// the full Set flow against a real secrets.Registry and asserts that the
// post-Set Registry.For returns the new provider. Without task 6's Reload
// call, this test fails at the post-Set assertion — that is the regression
// this spec exists to prevent.
func TestSetBrokerConfig_PersistAndReload_FullPath(t *testing.T) {
	initialFake := &labelledBroker{label: "vault-initial"}
	configuredFake := &labelledBroker{label: "vault-configured"}

	getter := &inMemoryConfigGetter{rows: map[auth.TenantID]secrets.BrokerConfig{}}
	reg, err := secrets.NewRegistry(getter, secrets.RegistryConfig{
		VaultFactory: vaultBlobFactory(initialFake, configuredFake),
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

	// gibson#101: seed a bare vault row. The "pre-Set" assertion below
	// remains valid.
	getter.rows[tenant] = secrets.BrokerConfig{
		Provider: "vault", ConfigBlob: []byte(`{}`),
	}

	// Initial: bare "{}" vault row → initial provider.
	if got, _ := reg.For(ctx, tenant); got != initialFake {
		t.Fatalf("pre-Set: got %v, want initial", got)
	}

	// Drive SetBrokerConfig with a vault candidate.
	if _, err := srv.SetBrokerConfig(ctx, &tenantv1.SetBrokerConfigRequest{
		Candidate: &tenantv1.CandidateConfig{
			Provider:   tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED,
			Address:    "https://vault",
			VaultToken: []byte("hvs.xyz"),
		},
	}); err != nil {
		t.Fatalf("SetBrokerConfig: %v", err)
	}

	// CRITICAL: post-Set, Registry.For MUST return the configured fake. If
	// SetBrokerConfig didn't call Reload, the cache still serves the initial
	// provider and the test fails.
	got, err := reg.For(ctx, tenant)
	if err != nil {
		t.Fatalf("For(post-Set): %v", err)
	}
	if got != configuredFake {
		t.Fatalf("post-Set: cache not invalidated — got %v, want configured fake (the spec's central regression)", got)
	}
}

// TestSetBrokerConfig_PersistFailure_NoReload_FullPath asserts that when
// the writer fails (e.g., DB down), the cache is NOT invalidated. The
// handler must report the persist failure and leave the cached provider
// alone — invalidating after a failed write would be lying about state.
func TestSetBrokerConfig_PersistFailure_NoReload_FullPath(t *testing.T) {
	initialFake := &labelledBroker{label: "vault-initial"}
	configuredFake := &labelledBroker{label: "vault-configured"}

	getter := &inMemoryConfigGetter{rows: map[auth.TenantID]secrets.BrokerConfig{}}
	reg, err := secrets.NewRegistry(getter, secrets.RegistryConfig{
		VaultFactory: vaultBlobFactory(initialFake, configuredFake),
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

	// gibson#101: seed a bare vault row so the warm-up path resolves cleanly.
	getter.rows[tenant] = secrets.BrokerConfig{
		Provider: "vault", ConfigBlob: []byte(`{}`),
	}

	// Warm the cache with the initial provider.
	if got, _ := reg.For(ctx, tenant); got != initialFake {
		t.Fatalf("warm-up: got %v, want initial", got)
	}

	// Drive SetBrokerConfig — writer fails.
	_, err = srv.SetBrokerConfig(ctx, &tenantv1.SetBrokerConfigRequest{
		Candidate: &tenantv1.CandidateConfig{
			Provider:   tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED,
			Address:    "https://vault",
			VaultToken: []byte("hvs.xyz"),
		},
	})
	if err == nil {
		t.Fatal("expected SetBrokerConfig to fail on writer error")
	}

	// The cache should still serve the initial provider — Reload must not
	// have fired.
	if got, _ := reg.For(ctx, tenant); got != initialFake {
		t.Fatalf("post-failure: cache should still be initial, got %v", got)
	}
}

// TestGetBrokerConfig_ReflectsActiveBackend is the read-side active-backend
// guard for gibson#1107. It asserts the three states GetBrokerConfig must
// distinguish:
//
//  1. a genuinely-unprovisioned tenant (no row) → configured:false;
//  2. a provisioned tenant carrying the operator's Hosted seed row →
//     configured:true + VAULT_HOSTED, with NO explicit SetBrokerConfig call
//     (the fix for the "configure backend" deadlock);
//  3. after the tenant switches to BYO via SetBrokerConfig → the same read
//     flips to VAULT_BYO.
//
// The active enum is derived from the persisted blob shape (namespace vs
// path_prefix) via brokercodec.Redact, so this exercises the exact bytes the
// operator seed and the daemon Set path write.
func TestGetBrokerConfig_ReflectsActiveBackend(t *testing.T) {
	getter := &inMemoryConfigGetter{rows: map[auth.TenantID]secrets.BrokerConfig{}}
	srv, err := NewTenantAdminServer(TenantAdminConfig{
		Reader:         getter,
		Writer:         &memoryWriter{getter: getter},
		ProbeFactory:   &fakeProbeFactory{}, // probe always succeeds
		Auditor:        &fakeAuditor{},
		Reloader:       &fakeReloader{},
		SecretsService: &fakeSecretsLister{},
		Now:            func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewTenantAdminServer: %v", err)
	}

	tenant := mustTenant(t, "acme")
	ctx := withTenant(t, "acme")

	// (1) Genuinely-unprovisioned tenant: no row → configured:false.
	resp, err := srv.GetBrokerConfig(ctx, &tenantv1.GetBrokerConfigRequest{})
	if err != nil {
		t.Fatalf("GetBrokerConfig(unprovisioned): %v", err)
	}
	if resp.GetConfigured() {
		t.Fatalf("unprovisioned tenant must report configured:false, got %+v", resp)
	}

	// (2) Provisioned tenant: seed the Hosted row exactly as the operator saga
	// does (namespace mode via brokercodec.Encode with Hosted:true).
	provider, blob, err := brokercodec.Encode(brokercodec.Fields{
		Hosted:          true,
		Address:         "https://vault.internal:8200",
		NamespaceOrPath: "tenant/acme",
		KVMount:         "secret",
		Auth:            vault.AuthConfig{Method: vault.AuthMethod("jwt"), Role: "gibson-plugin-acme"},
		Tenant:          tenant,
	})
	if err != nil {
		t.Fatalf("seed Encode: %v", err)
	}
	getter.rows[tenant] = secrets.BrokerConfig{Provider: provider, ConfigBlob: blob}

	resp, err = srv.GetBrokerConfig(ctx, &tenantv1.GetBrokerConfigRequest{})
	if err != nil {
		t.Fatalf("GetBrokerConfig(seeded): %v", err)
	}
	if !resp.GetConfigured() {
		t.Fatalf("seeded tenant must report configured:true, got %+v", resp)
	}
	if got := resp.GetConfig().GetProvider(); got != tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_HOSTED {
		t.Fatalf("seeded active backend: got %v, want VAULT_HOSTED", got)
	}

	// (3) Tenant switches to BYO via SetBrokerConfig; the write lands in the
	// same store the reader sees, so the next read flips to VAULT_BYO.
	if _, err := srv.SetBrokerConfig(ctx, &tenantv1.SetBrokerConfigRequest{
		Candidate: &tenantv1.CandidateConfig{
			Provider:        tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_BYO,
			Address:         "https://byo-vault.example:8200",
			NamespaceOrPath: "tenant/acme",
			AuthMethod:      "token",
			VaultToken:      []byte("hvs.byo"),
		},
	}); err != nil {
		t.Fatalf("SetBrokerConfig(BYO): %v", err)
	}

	resp, err = srv.GetBrokerConfig(ctx, &tenantv1.GetBrokerConfigRequest{})
	if err != nil {
		t.Fatalf("GetBrokerConfig(after BYO): %v", err)
	}
	if !resp.GetConfigured() {
		t.Fatalf("BYO tenant must report configured:true, got %+v", resp)
	}
	if got := resp.GetConfig().GetProvider(); got != tenantv1.BrokerProvider_BROKER_PROVIDER_VAULT_BYO {
		t.Fatalf("after BYO set: got %v, want VAULT_BYO", got)
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
