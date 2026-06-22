package daemon

// broker_init_vault_lookup_test.go — regression tests for gibson#262.
//
// The bug: broker_init.go used to seed the AuthCache key from the
// `cfg.Namespace` (e.g. "tenant-<id>") and the refresh closure then
// tried to parse that string AS a tenant_id and look up the
// `tenant_secrets_broker_config` row keyed by it. For SaaS tenants
// where the operator renders `GIBSON_VAULT_NAMESPACE_TEMPLATE=
// tenant-{tenant_id}` to "tenant-whatwhat" while the broker_config
// row is keyed by `whatwhat`, this conflation produced
// `configstore: broker config not found` on every authenticated RPC
// and the circuit breaker opened after 5 consecutive failures.
//
// The fix wires the existing `vaultRefreshLookup` so the factory and
// refresh closure share a stable blob-hash key — the refresh closure
// never queries configStore at all, sidestepping the conflation.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/secrets"
	sdkvault "github.com/zeroroot-ai/gibson/internal/infra/secrets/vault"
)

// TestVaultRefreshLookup_KeyByBlobHashIsolatesDistinctConfigs verifies
// that two distinct Vault configs hash to distinct cache keys and that
// each retrieves its own config back. This is the load-bearing
// invariant the lookup-based refresh closure depends on: collisions
// would silently route one tenant's refresh to a different tenant's
// config.
func TestVaultRefreshLookup_KeyByBlobHashIsolatesDistinctConfigs(t *testing.T) {
	t.Parallel()

	lookup := newVaultRefreshLookup()
	cfgA := sdkvault.Config{
		Address:   "https://vault.example:8200",
		Namespace: "tenant-acme",
	}
	cfgB := sdkvault.Config{
		Address:   "https://vault.example:8200",
		Namespace: "tenant-globex",
	}
	blobA, _ := json.Marshal(cfgA)
	blobB, _ := json.Marshal(cfgB)

	keyA := vaultConfigCacheKey(blobA)
	keyB := vaultConfigCacheKey(blobB)
	if keyA == keyB {
		t.Fatalf("expected distinct cache keys for distinct configs, got %q == %q", keyA, keyB)
	}
	lookup.put(keyA, cfgA)
	lookup.put(keyB, cfgB)

	gotA, ok := lookup.get(keyA)
	if !ok || gotA.Namespace != "tenant-acme" {
		t.Errorf("lookup.get(keyA) = %v, ok=%v; want Namespace=tenant-acme", gotA, ok)
	}
	gotB, ok := lookup.get(keyB)
	if !ok || gotB.Namespace != "tenant-globex" {
		t.Errorf("lookup.get(keyB) = %v, ok=%v; want Namespace=tenant-globex", gotB, ok)
	}
}

// TestVaultRefreshLookup_SameConfigSameKey verifies the singleflight
// invariant: byte-identical configs (which the operator writes
// idempotently after every reconcile) must hash to the same key so
// concurrent factory invocations for the same tenant collapse onto
// one Vault auth round-trip.
func TestVaultRefreshLookup_SameConfigSameKey(t *testing.T) {
	t.Parallel()

	cfg := sdkvault.Config{
		Address:   "https://vault.example:8200",
		Namespace: "tenant-whatwhat",
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodJWT,
			Role:   "gibson-plugin-whatwhat",
		},
	}
	blob1, _ := json.Marshal(cfg)
	blob2, _ := json.Marshal(cfg)

	if vaultConfigCacheKey(blob1) != vaultConfigCacheKey(blob2) {
		t.Fatal("byte-identical configs must hash to the same cache key")
	}
}

// TestVaultAuthCache_LookupBasedRefreshDoesNotQueryConfigStore is the
// direct regression test for gibson#262. It constructs an AuthCache
// with a refresh closure that mirrors broker_init.go's fixed wiring —
// read the config from the lookup, no configStore involved — and
// feeds it the exact shape that broke production: Namespace=
// "tenant-<id>" that happens to parse as a valid TenantID but is NOT
// the tenant_id used to key the broker_config row.
//
// The closure returns a synthetic token; the test passes iff the
// refresh succeeds despite the cache key being a "tenant-prefixed"
// string. The negation — querying configStore with the cache key —
// is exactly the path that returned ErrNotFound in production.
func TestVaultAuthCache_LookupBasedRefreshDoesNotQueryConfigStore(t *testing.T) {
	t.Parallel()

	cfg := sdkvault.Config{
		Address:   "https://vault.example.invalid:8200",
		Namespace: "tenant-whatwhat", // the exact shape that broke production
		Auth: sdkvault.AuthConfig{
			Method: sdkvault.AuthMethodToken, // skip the JWT mint for this unit-level test
			Token:  "static",
		},
	}
	blob, _ := json.Marshal(cfg)
	key := vaultConfigCacheKey(blob)
	lookup := newVaultRefreshLookup()
	lookup.put(key, cfg)

	refreshFn := func(_ context.Context, k, _ string) (string, time.Duration, error) {
		got, ok := lookup.get(k)
		if !ok {
			return "", 0, &sdkvault.VaultRefreshError{
				TenantID: k,
				Cause:    nil,
			}
		}
		// Synthetic token — proves the closure reached the config
		// without going through configStore.
		return "tok-for-" + got.Namespace, time.Minute, nil
	}
	cache := secrets.NewAuthCache(refreshFn, nil, nil)

	tok, err := cache.GetOrRefresh(context.Background(), key, "vault")
	if err != nil {
		t.Fatalf("GetOrRefresh: %v", err)
	}
	if tok != "tok-for-tenant-whatwhat" {
		t.Errorf("token = %q, want tok-for-tenant-whatwhat", tok)
	}
}
