package secrets

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
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
// optional cloud provider factories.
func buildTestRegistry(
	t *testing.T,
	getter RegistryConfigGetter,
	extras map[string]ProviderConstructor,
) *Registry {
	t.Helper()
	cfg := RegistryConfig{}
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

// TestRegistry_NoConfigRowSurfacesAsError — gibson#101 replaced the
// implicit Postgres fallback (which caused infinite-recursion-style
// 60s timeouts) with a hard error. Callers see ErrBrokerConfigNotFound,
// which daemon handlers map to codes.FailedPrecondition.
func TestRegistry_NoConfigRowSurfacesAsError(t *testing.T) {
	getter := newFakeConfigGetter() // no rows
	reg := buildTestRegistry(t, getter, nil)

	broker, err := reg.For(context.Background(), regTenantA)
	require.Error(t, err)
	require.Nil(t, broker)
	require.ErrorIs(t, err, ErrBrokerConfigNotFound)
}

func TestRegistry_ConfiguredProviderReturned(t *testing.T) {
	vaultProv := newNamedProv("vault")

	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)})

	extras := map[string]ProviderConstructor{
		"vault": func(_ []byte) (sdksecrets.Broker, error) { return vaultProv, nil },
	}
	reg := buildTestRegistry(t, getter, extras)

	broker, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)
	assert.Same(t, vaultProv, broker.(*namedProvider))
}

func TestRegistry_CachesProvider(t *testing.T) {
	vaultProv := newNamedProv("vault")
	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)})
	extras := map[string]ProviderConstructor{
		"vault": func(_ []byte) (sdksecrets.Broker, error) { return vaultProv, nil },
	}
	reg := buildTestRegistry(t, getter, extras)

	b1, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)
	b2, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)

	assert.Same(t, b1, b2, "second For call must return cached instance")
}

func TestRegistry_ReloadEvictsCache(t *testing.T) {
	vaultProv := newNamedProv("vault")
	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)})
	extras := map[string]ProviderConstructor{
		"vault": func(_ []byte) (sdksecrets.Broker, error) { return vaultProv, nil },
	}
	reg := buildTestRegistry(t, getter, extras)

	_, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)

	reg.Reload(context.Background(), regTenantA)

	// After reload, For must succeed without panic.
	_, err = reg.For(context.Background(), regTenantA)
	require.NoError(t, err)
}

func TestRegistry_TenantIsolation(t *testing.T) {
	vaultProvA := newNamedProv("vault-a")
	awssmProvB := newNamedProv("awssm-b")

	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)})
	getter.Set(regTenantB, BrokerConfig{Provider: "awssm", ConfigBlob: []byte(`{}`)})

	extras := map[string]ProviderConstructor{
		"vault":  func(_ []byte) (sdksecrets.Broker, error) { return vaultProvA, nil },
		"awssm":  func(_ []byte) (sdksecrets.Broker, error) { return awssmProvB, nil },
	}
	reg := buildTestRegistry(t, getter, extras)

	bA, err := reg.For(context.Background(), regTenantA)
	require.NoError(t, err)
	assert.Same(t, vaultProvA, bA.(*namedProvider))

	bB, err := reg.For(context.Background(), regTenantB)
	require.NoError(t, err)
	assert.Same(t, awssmProvB, bB.(*namedProvider))
}

func TestRegistry_HealthReturnsPerTenant(t *testing.T) {
	vaultProv := newNamedProv("vault")
	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)})
	getter.Set(regTenantB, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)})
	extras := map[string]ProviderConstructor{
		"vault": func(_ []byte) (sdksecrets.Broker, error) { return vaultProv, nil },
	}
	reg := buildTestRegistry(t, getter, extras)

	_, _ = reg.For(context.Background(), regTenantA)
	_, _ = reg.For(context.Background(), regTenantB)

	h := reg.Health(context.Background())
	require.Contains(t, h, regTenantA)
	require.Contains(t, h, regTenantB)
	assert.NoError(t, h[regTenantA])
	assert.NoError(t, h[regTenantB])
}

// TestRegistry_NoConfigRowReturnsNotProvisioned — gibson#101: the
// implicit Postgres fallback for tenants without a broker config row
// caused an infinite-recursion-style 60s timeout on every list call.
// Verify that the registry surfaces ErrBrokerConfigNotFound so the
// daemon handler can return a clean codes.FailedPrecondition instead
// of looping.
func TestRegistry_NoConfigRowReturnsNotProvisioned(t *testing.T) {
	getter := newFakeConfigGetter()
	reg := buildTestRegistry(t, getter, nil)

	_, err := reg.For(context.Background(), regTenantA)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrBrokerConfigNotFound)
	assert.Contains(t, err.Error(), "has no broker config row")
	assert.Contains(t, err.Error(), "gibson#101")
}

func TestRegistry_UnknownProviderReturnsError(t *testing.T) {
	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "not-a-real-provider", ConfigBlob: []byte(`{}`)})
	reg := buildTestRegistry(t, getter, nil)

	_, err := reg.For(context.Background(), regTenantA)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestRegistry_ConstructorFailureReturnsError(t *testing.T) {
	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{"bad":"config"}`)})

	extras := map[string]ProviderConstructor{
		"vault": func(_ []byte) (sdksecrets.Broker, error) {
			return nil, errors.New("vault: invalid config")
		},
	}
	reg := buildTestRegistry(t, getter, extras)

	_, err := reg.For(context.Background(), regTenantA)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "vault: invalid config")
}

func TestRegistry_ConcurrentForSameTenant(t *testing.T) {
	vaultProv := newNamedProv("vault")
	getter := newFakeConfigGetter()
	getter.Set(regTenantA, BrokerConfig{Provider: "vault", ConfigBlob: []byte(`{}`)})
	extras := map[string]ProviderConstructor{
		"vault": func(_ []byte) (sdksecrets.Broker, error) { return vaultProv, nil },
	}
	reg := buildTestRegistry(t, getter, extras)

	const goroutines = 50
	results := make([]sdksecrets.Broker, goroutines)
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
