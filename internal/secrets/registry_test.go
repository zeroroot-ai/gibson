package secrets

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
	sdksecrets "github.com/zero-day-ai/sdk/secrets"
)

// --- fakes ---

// fakeConfigGetter implements RegistryConfigGetter backed by an in-memory map.
type fakeConfigGetter struct {
	mu   sync.RWMutex
	rows map[string]BrokerConfig
}

func newFakeConfigGetter() *fakeConfigGetter {
	return &fakeConfigGetter{rows: make(map[string]BrokerConfig)}
}

func (f *fakeConfigGetter) Set(tenant auth.TenantID, cfg BrokerConfig) {
	f.mu.Lock()
	f.rows[tenant.String()] = cfg
	f.mu.Unlock()
}

func (f *fakeConfigGetter) Get(_ context.Context, tenant auth.TenantID) (BrokerConfig, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	cfg, ok := f.rows[tenant.String()]
	if !ok {
		return BrokerConfig{}, ErrBrokerConfigNotFound
	}
	return cfg, nil
}

// namedProvider is a fakeSecretsBroker with an identifiable name.
type namedProvider struct {
	fakeSecretsBroker
	name string
}

func newNamedProv(name string) *namedProvider { return &namedProvider{name: name} }

// buildTestRegistry constructs a Registry with the given config getter and
// factories. pgProv is the pre-built Postgres fallback.
func buildTestRegistry(
	t *testing.T,
	getter RegistryConfigGetter,
	pgProv sdksecrets.SecretsBroker,
	extras map[string]ProviderConstructor,
) *Registry {
	t.Helper()
	cfg := RegistryConfig{PostgresProvider: pgProv}
	if f, ok := extras["vault"]; ok {
		cfg.VaultFactory = f
	}
	if f, ok := extras["awssm"]; ok {
		cfg.AWSSMFactory = f
	}
	if f, ok := extras["gcpsm"]; ok {
		cfg.GCPSMFactory = f
	}
	if f, ok := extras["azurekv"]; ok {
		cfg.AzureKVFactory = f
	}
	reg, err := NewRegistry(getter, cfg)
	require.NoError(t, err)
	return reg
}

// --- tests ---

var (
	regTenantA = auth.MustNewTenantID("alpha-co")
	regTenantB = auth.MustNewTenantID("beta-co")
)

func TestRegistry_DefaultFallbackToPostgres(t *testing.T) {
	pg := newNamedProv("postgres")
	getter := newFakeConfigGetter() // no rows → fallback
	reg := buildTestRegistry(t, getter, pg, nil)

	broker, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)
	assert.Same(t, pg, broker.(*namedProvider))
}

func TestRegistry_ConfiguredProviderReturned(t *testing.T) {
	pg := newNamedProv("postgres")
	vaultProv := newNamedProv("vault")

	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)})

	extras := map[string]ProviderConstructor{
		"vault": func(_ []byte) (sdksecrets.SecretsBroker, error) { return vaultProv, nil },
	}
	reg := buildTestRegistry(t, getter, pg, extras)

	broker, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)
	assert.Same(t, vaultProv, broker.(*namedProvider))
}

func TestRegistry_CachesProvider(t *testing.T) {
	pg := newNamedProv("postgres")
	getter := newFakeConfigGetter()
	reg := buildTestRegistry(t, getter, pg, nil)

	b1, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)
	b2, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)

	assert.Same(t, b1, b2, "second For call must return cached instance")
}

func TestRegistry_ReloadEvictsCache(t *testing.T) {
	pg := newNamedProv("postgres")
	getter := newFakeConfigGetter()
	reg := buildTestRegistry(t, getter, pg, nil)

	_, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)

	reg.Reload(context.Background(), regTenantA)

	// After reload, For must succeed without panic.
	_, err = reg.For(context.Background(), regTenantA)
	require.NoError(t, err)
}

func TestRegistry_TenantIsolation(t *testing.T) {
	pg := newNamedProv("postgres")
	vaultProv := newNamedProv("vault")

	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)})
	// regTenantB has no config → falls back to Postgres.

	extras := map[string]ProviderConstructor{
		"vault": func(_ []byte) (sdksecrets.SecretsBroker, error) { return vaultProv, nil },
	}
	reg := buildTestRegistry(t, getter, pg, extras)

	bA, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)
	assert.Same(t, vaultProv, bA.(*namedProvider))

	bB, err := reg.For(context.Background(), regTenantB)
	require.NoError(t, err)
	assert.Same(t, pg, bB.(*namedProvider))
}

func TestRegistry_HealthReturnsPerTenant(t *testing.T) {
	pg := newNamedProv("postgres")
	getter := newFakeConfigGetter()
	reg := buildTestRegistry(t, getter, pg, nil)

	_, _ = reg.For(context.Background(), regTenantA)
	_, _ = reg.For(context.Background(), regTenantB)

	h := reg.Health(context.Background())
	require.Contains(t, h, regTenantA)
	require.Contains(t, h, regTenantB)
	assert.NoError(t, h[regTenantA])
	assert.NoError(t, h[regTenantB])
}

func TestRegistry_UnknownProviderReturnsError(t *testing.T) {
	pg := newNamedProv("postgres")
	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "not-a-real-provider", ConfigBlob: []byte(`{}`)})
	reg := buildTestRegistry(t, getter, pg, nil)

	_, err := reg.For(context.Background(), regTenantA)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestRegistry_ConstructorFailureReturnsError(t *testing.T) {
	pg := newNamedProv("postgres")
	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{"bad":"config"}`)})

	extras := map[string]ProviderConstructor{
		"vault": func(_ []byte) (sdksecrets.SecretsBroker, error) {
			return nil, errors.New("vault: invalid config")
		},
	}
	reg := buildTestRegistry(t, getter, pg, extras)

	_, err := reg.For(context.Background(), regTenantA)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault: invalid config")
}

func TestRegistry_ConcurrentForSameTenant(t *testing.T) {
	pg := newNamedProv("postgres")
	getter := newFakeConfigGetter()
	reg := buildTestRegistry(t, getter, pg, nil)

	const goroutines = 50
	results := make([]sdksecrets.SecretsBroker, goroutines)
	errs := make([]error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i], errs[i] = reg.For(context.Background(), regTenantA)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d failed", i)
		// All results must be the same cached instance.
		assert.Same(t, results[0], results[i], "goroutine %d got a different instance", i)
	}
}
