//go:build integration
// +build integration

// store_broker_integration_test.go exercises brokerBackedStore end-to-end against
// a real Postgres (via testcontainers) for the metadata table and an in-memory
// fake secrets broker for credentials. It is the coverage follow-up to #613
// (the old redis-direct provider_config_test.go was removed in #610).
//
// Tests are skipped gracefully when Docker is unavailable (testhelpers.StartPostgresTLS
// owns the skip).
package providerconfig_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	"github.com/zeroroot-ai/gibson/tests/testhelpers"

	sdksecrets "github.com/zeroroot-ai/gibson/internal/infra/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	intTenant = "acme"
)

// ---------------------------------------------------------------------------
// Fake secrets broker (in-memory). Tenant-agnostic — these tests use one tenant.
// ---------------------------------------------------------------------------

type fakeSecretsService struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newFakeSecretsService() *fakeSecretsService {
	return &fakeSecretsService{m: make(map[string][]byte)}
}

func (f *fakeSecretsService) Put(_ context.Context, name string, value []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	f.m[name] = cp
	return nil
}

func (f *fakeSecretsService) Resolve(_ context.Context, name string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[name]
	if !ok {
		return nil, sdksecrets.ErrNotFound
	}
	return v, nil
}

func (f *fakeSecretsService) Delete(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, name)
	return nil
}

func (f *fakeSecretsService) List(_ context.Context, filter sdksecrets.Filter) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for k := range f.m {
		if filter.Prefix == "" || strings.HasPrefix(k, filter.Prefix) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (f *fakeSecretsService) keysWithPrefix(prefix string) []string {
	out, _ := f.List(context.Background(), sdksecrets.Filter{Prefix: prefix})
	return out
}

// ---------------------------------------------------------------------------
// Fake datapool.Pool returning a Conn bound to the shared test Postgres pool.
// ---------------------------------------------------------------------------

type fakePool struct {
	pg  *pgxpool.Pool
	kek []byte
}

func (p *fakePool) For(_ context.Context, tenant auth.TenantID) (*datapool.Conn, error) {
	// Fresh KEK copy per call: Conn.Release() zeroes the KEK in place.
	kek := make([]byte, len(p.kek))
	copy(kek, p.kek)
	return &datapool.Conn{
		Tenant:   tenant,
		Postgres: p.pg,
		KEK:      kek,
	}, nil
}

func (p *fakePool) Admin(_ context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *fakePool) SetAdminPool(_ datapool.AdminAcquirer)                {}
func (p *fakePool) Close() error                                         { return nil }

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

// providerConfigsDDL mirrors pkg/platform/migrations/postgres/tenant/
// 007_provider_configs_split.up.sql (the schema the DAO targets).
const providerConfigsDDL = `
CREATE TABLE IF NOT EXISTS provider_configs (
    id            TEXT        NOT NULL DEFAULT gen_random_uuid()::TEXT,
    name          TEXT        PRIMARY KEY,
    type          TEXT        NOT NULL,
    default_model TEXT        NOT NULL DEFAULT '',
    is_default    BOOLEAN     NOT NULL DEFAULT FALSE,
    enabled       BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS provider_config_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- The lazy-migration scan (List/Get/Resolve) reads the legacy credential blobs
-- from tenant_secrets; the table must exist even when there is nothing to migrate.
CREATE TABLE IF NOT EXISTS tenant_secrets (
    name       TEXT        PRIMARY KEY,
    envelope   BYTEA       NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

func newBrokerStore(t *testing.T) (providerconfig.ProviderConfigStore, *fakeSecretsService) {
	t.Helper()
	ctx := context.Background()

	pgTLS := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{
		User:     "testuser",
		Password: "testpass",
		Database: "testdb",
	})

	var pool *pgxpool.Pool
	require.Eventually(t, func() bool {
		var err error
		pool, err = pgxpool.New(ctx, pgTLS.DSN)
		if err != nil {
			return false
		}
		return pool.Ping(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres not ready")
	t.Cleanup(pool.Close)

	_, err := pool.Exec(ctx, providerConfigsDDL)
	require.NoError(t, err, "apply provider_configs DDL")

	kek := make([]byte, 32)
	for i := range kek {
		kek[i] = byte(i + 1)
	}
	svc := newFakeSecretsService()
	store := providerconfig.NewBrokerBackedStore(&fakePool{pg: pool, kek: kek}, svc)
	return store, svc
}

func sampleInput(name string) *providerconfig.ProviderConfigInput {
	return &providerconfig.ProviderConfigInput{
		Name:         name,
		Type:         llm.ProviderOpenAI,
		DefaultModel: "gpt-4o",
		Credentials:  map[string]string{"api_key": "sk-supersecret-abcd1234"},
		Enabled:      true,
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestBrokerStore_CRUDLifecycle(t *testing.T) {
	store, _ := newBrokerStore(t)
	ctx := context.Background()

	// Create
	created, err := store.Create(ctx, intTenant, sampleInput("prod-openai"))
	require.NoError(t, err)
	assert.Equal(t, "prod-openai", created.Name)
	assert.Equal(t, llm.ProviderOpenAI, created.Type)

	// Duplicate create → ErrAlreadyExists
	_, err = store.Create(ctx, intTenant, sampleInput("prod-openai"))
	assert.ErrorIs(t, err, providerconfig.ErrAlreadyExists)

	// Get (masked credentials, never plaintext)
	got, err := store.Get(ctx, intTenant, "prod-openai")
	require.NoError(t, err)
	assert.Equal(t, "gpt-4o", got.DefaultModel)
	assert.Equal(t, "****1234", got.CredentialsMasked["api_key"])
	assert.NotContains(t, got.CredentialsMasked["api_key"], "supersecret")

	// List
	list, err := store.List(ctx, intTenant)
	require.NoError(t, err)
	assert.Len(t, list, 1)

	// Update
	upd := sampleInput("prod-openai")
	upd.DefaultModel = "gpt-4o-mini"
	upd.Credentials = map[string]string{"api_key": "sk-rotated-wxyz9999"}
	_, err = store.Update(ctx, intTenant, "prod-openai", upd)
	require.NoError(t, err)
	got, err = store.Get(ctx, intTenant, "prod-openai")
	require.NoError(t, err)
	assert.Equal(t, "gpt-4o-mini", got.DefaultModel)
	assert.Equal(t, "****9999", got.CredentialsMasked["api_key"])

	// Delete → subsequent Get is ErrNotFound
	require.NoError(t, store.Delete(ctx, intTenant, "prod-openai"))
	_, err = store.Get(ctx, intTenant, "prod-openai")
	assert.ErrorIs(t, err, providerconfig.ErrNotFound)
	_, err = store.Resolve(ctx, intTenant, "prod-openai")
	assert.ErrorIs(t, err, providerconfig.ErrNotFound)
}

func TestBrokerStore_CredentialsRoutedToBroker(t *testing.T) {
	store, svc := newBrokerStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, intTenant, sampleInput("p1"))
	require.NoError(t, err)

	// Credential lives in the broker under provider_cred:<name>:<field>.
	keys := svc.keysWithPrefix("provider_cred:p1:")
	require.Len(t, keys, 1)
	assert.Equal(t, "provider_cred:p1:api_key", keys[0])

	// Resolve returns plaintext for the execution path.
	dec, err := store.Resolve(ctx, intTenant, "p1")
	require.NoError(t, err)
	assert.Equal(t, "sk-supersecret-abcd1234", dec.Credentials["api_key"])

	// Delete also purges the broker keys.
	require.NoError(t, store.Delete(ctx, intTenant, "p1"))
	assert.Empty(t, svc.keysWithPrefix("provider_cred:p1:"))
}

func TestBrokerStore_Default(t *testing.T) {
	store, _ := newBrokerStore(t)
	ctx := context.Background()

	_, err := store.Create(ctx, intTenant, sampleInput("a"))
	require.NoError(t, err)
	_, err = store.Create(ctx, intTenant, sampleInput("b"))
	require.NoError(t, err)

	require.NoError(t, store.SetDefault(ctx, intTenant, "b"))
	def, err := store.GetDefault(ctx, intTenant)
	require.NoError(t, err)
	assert.Equal(t, "b", def.Name)
	assert.True(t, def.IsDefault)
}

func TestBrokerStore_UnsupportedType(t *testing.T) {
	store, _ := newBrokerStore(t)
	ctx := context.Background()

	in := sampleInput("weird")
	in.Type = llm.ProviderType("not-a-real-provider")
	_, err := store.Create(ctx, intTenant, in)
	assert.ErrorIs(t, err, providerconfig.ErrUnsupportedType)
}
