package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/secrets"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Stubs satisfying the secrets.Service interface dependencies.
// ---------------------------------------------------------------------------

// credStoreTestBroker is a configurable fake SecretsBroker for credential store tests.
type credStoreTestBroker struct {
	getVal []byte
	getErr error
}

func (b *credStoreTestBroker) Get(_ context.Context, _ auth.TenantID, _ string) ([]byte, error) {
	return b.getVal, b.getErr
}
func (b *credStoreTestBroker) Put(_ context.Context, _ auth.TenantID, _ string, _ []byte) error {
	return nil
}
func (b *credStoreTestBroker) Delete(_ context.Context, _ auth.TenantID, _ string) error { return nil }
func (b *credStoreTestBroker) List(_ context.Context, _ auth.TenantID, _ sdksecrets.Filter) ([]string, error) {
	return nil, nil
}
func (b *credStoreTestBroker) Health(_ context.Context) error { return nil }
func (b *credStoreTestBroker) Probe(_ context.Context) error  { return nil }
func (b *credStoreTestBroker) Capabilities() sdksecrets.Capabilities {
	return sdksecrets.Capabilities{CanPut: true, CanDelete: true, CanList: true, MaxValueBytes: 1 << 20}
}

var _ sdksecrets.Broker = (*credStoreTestBroker)(nil)

// credStoreTestRegistry implements secrets.ServiceRegistry, returning a fixed broker.
type credStoreTestRegistry struct {
	broker sdksecrets.Broker
	err    error
}

func (r *credStoreTestRegistry) For(_ context.Context, _ auth.TenantID) (sdksecrets.Broker, error) {
	return r.broker, r.err
}

// credStoreTestCircuit implements secrets.circuitExecutor, always allowing.
type credStoreTestCircuit struct{}

func (c *credStoreTestCircuit) Execute(_, _ string, fn func() error) error { return fn() }

// credStoreTestAuditor implements secrets.ServiceAuditWriter, discarding events.
type credStoreTestAuditor struct{}

func (a *credStoreTestAuditor) Audit(_ context.Context, _ secrets.AuditEvent) {}

// buildTestSecretsService constructs a *secrets.Service with a fake broker returning
// the given bytes/error from Get.
func buildTestSecretsService(t *testing.T, resolveBytes []byte, resolveErr error) *secrets.Service {
	t.Helper()
	broker := &credStoreTestBroker{getVal: resolveBytes, getErr: resolveErr}
	reg := &credStoreTestRegistry{broker: broker}
	circuit := &credStoreTestCircuit{}
	auditor := &credStoreTestAuditor{}
	svc, err := secrets.NewService(reg, circuit, auditor)
	require.NoError(t, err)
	return svc
}

// ctxWithTenantForCredStore returns a context with a tenant set.
func ctxWithTenantForCredStore() context.Context {
	return auth.WithTenant(context.Background(), auth.MustNewTenantID("test-tenant"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestNewDaemonCredentialStore_NilService verifies that a nil service is rejected.
func TestNewDaemonCredentialStore_NilService(t *testing.T) {
	store, err := NewDaemonCredentialStore(nil)
	assert.Error(t, err)
	assert.Nil(t, store)
	assert.Contains(t, err.Error(), "service must not be nil")
}

// TestDaemonCredentialStore_GetCredential_NotFound verifies the not-found path returns
// a user-facing "not found" error.
func TestDaemonCredentialStore_GetCredential_NotFound(t *testing.T) {
	svc := buildTestSecretsService(t, nil, status.Error(codes.NotFound, "secret not found"))
	store, err := NewDaemonCredentialStore(svc)
	require.NoError(t, err)

	ctx := ctxWithTenantForCredStore()
	_, _, err = store.GetCredential(ctx, "missing-cred")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestDaemonCredentialStore_GetCredential_Success verifies the happy path returns the
// correct Credential shape and the plaintext secret.
func TestDaemonCredentialStore_GetCredential_Success(t *testing.T) {
	secretVal := []byte("super-secret-key")
	svc := buildTestSecretsService(t, secretVal, nil)
	store, err := NewDaemonCredentialStore(svc)
	require.NoError(t, err)

	ctx := ctxWithTenantForCredStore()
	cred, secret, err := store.GetCredential(ctx, "my-cred")
	require.NoError(t, err)
	assert.Equal(t, "my-cred", cred.Name)
	assert.NotEmpty(t, cred.ID)
	assert.Equal(t, "super-secret-key", secret)
}

// TestDaemonCredentialStore_GetCredential_UnavailableError verifies that non-NotFound
// gRPC errors are passed through.
func TestDaemonCredentialStore_GetCredential_UnavailableError(t *testing.T) {
	svc := buildTestSecretsService(t, nil, status.Error(codes.Unavailable, "circuit open"))
	store, err := NewDaemonCredentialStore(svc)
	require.NoError(t, err)

	ctx := ctxWithTenantForCredStore()
	_, _, err = store.GetCredential(ctx, "my-cred")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Unavailable")
}

// TestDaemonCredentialStore_Health returns healthy.
func TestDaemonCredentialStore_Health(t *testing.T) {
	svc := buildTestSecretsService(t, nil, nil)
	store, err := NewDaemonCredentialStore(svc)
	require.NoError(t, err)

	health := store.Health(context.Background())
	assert.Equal(t, types.HealthStateHealthy, health.State)
}

// TestDaemonCredentialStore_Close is a no-op that returns nil.
func TestDaemonCredentialStore_Close(t *testing.T) {
	svc := buildTestSecretsService(t, nil, nil)
	store, err := NewDaemonCredentialStore(svc)
	require.NoError(t, err)

	assert.NoError(t, store.Close())
}

// TestDaemonCredentialStore_ImplementsInterface is a compile-time check via assertion.
func TestDaemonCredentialStore_ImplementsInterface(t *testing.T) {
	svc := buildTestSecretsService(t, nil, nil)
	store, err := NewDaemonCredentialStore(svc)
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.Implements(t, (*interface {
		GetCredential(ctx context.Context, name string) (*types.Credential, string, error)
		Health(ctx context.Context) types.HealthStatus
		Close() error
	})(nil), store)
}

// ---------------------------------------------------------------------------
// User-prefix (Vault "user/" namespace) tests — gibson#404
// ---------------------------------------------------------------------------

// trackingBroker is a fake SecretsBroker that records the last name passed to
// Get so tests can assert the stored-form key was used.
type trackingBroker struct {
	credStoreTestBroker
	lastGetName string
}

func (b *trackingBroker) Get(_ context.Context, _ auth.TenantID, name string) ([]byte, error) {
	b.lastGetName = name
	return b.getVal, b.getErr
}

type trackingRegistry struct{ broker *trackingBroker }

func (r *trackingRegistry) For(_ context.Context, _ auth.TenantID) (sdksecrets.Broker, error) {
	return r.broker, nil
}

func buildTrackingStore(t *testing.T, val []byte) (*DaemonCredentialStore, *trackingBroker) {
	t.Helper()
	broker := &trackingBroker{credStoreTestBroker: credStoreTestBroker{getVal: val}}
	reg := &trackingRegistry{broker: broker}
	circuit := &credStoreTestCircuit{}
	auditor := &credStoreTestAuditor{}
	svc, err := secrets.NewService(reg, circuit, auditor)
	require.NoError(t, err)
	store, err := NewDaemonCredentialStore(svc)
	require.NoError(t, err)
	return store, broker
}

// TestGetCredential_PrependUserPrefix verifies that GetCredential translates
// "cred:<name>" → "user/cred:<name>" before calling Resolve, so plugins
// resolve from the correct Vault sub-path.
func TestGetCredential_PrependUserPrefix(t *testing.T) {
	store, broker := buildTrackingStore(t, []byte("secret-value"))
	ctx := ctxWithTenantForCredStore()

	cred, secret, err := store.GetCredential(ctx, "cred:openai-prod")
	require.NoError(t, err)

	// The broker should have been queried with the stored form.
	assert.Equal(t, "user/cred:openai-prod", broker.lastGetName,
		"GetCredential should prepend user/ before calling Resolve")

	// The returned credential carries the caller-facing name (no user/).
	assert.Equal(t, "cred:openai-prod", cred.Name)
	assert.Equal(t, "secret-value", secret)
}

// TestGetCredential_ProviderConfigPrefix verifies the same for provider_config names.
func TestGetCredential_ProviderConfigPrefix(t *testing.T) {
	store, broker := buildTrackingStore(t, []byte("pk"))
	ctx := ctxWithTenantForCredStore()

	_, _, err := store.GetCredential(ctx, "provider_config:openai:key")
	require.NoError(t, err)

	assert.Equal(t, "user/provider_config:openai:key", broker.lastGetName)
}

// TestGetCredential_InfraPathNotPrefixed verifies that infra/ paths (e.g.
// "infra/postgres") are NOT given the "user/" prefix — they go through
// unchanged so the broker reads from the correct mount root.
func TestGetCredential_InfraPathNotPrefixed(t *testing.T) {
	store, broker := buildTrackingStore(t, []byte("pg-dsn"))
	ctx := ctxWithTenantForCredStore()

	_, _, err := store.GetCredential(ctx, "infra/postgres")
	require.NoError(t, err)

	assert.Equal(t, "infra/postgres", broker.lastGetName,
		"infra/ paths must not get a user/ prefix")
}

// TestGetCredential_AlreadyPrefixed verifies idempotency: a name that already
// starts with "user/" is not double-prefixed.
func TestGetCredential_AlreadyPrefixed(t *testing.T) {
	store, broker := buildTrackingStore(t, []byte("val"))
	ctx := ctxWithTenantForCredStore()

	_, _, err := store.GetCredential(ctx, "user/cred:my-key")
	require.NoError(t, err)

	assert.Equal(t, "user/cred:my-key", broker.lastGetName,
		"already-prefixed names must not be double-prefixed")
}

// TestIsUserSecretName covers the name-classification helper.
func TestIsUserSecretName(t *testing.T) {
	assert.True(t, isUserSecretName("cred:openai"), "cred: is a user secret")
	assert.True(t, isUserSecretName("provider_config:openai:key"), "provider_config: is a user secret")
	assert.False(t, isUserSecretName("infra/postgres"), "infra/ is not a user secret")
	assert.False(t, isUserSecretName(""), "empty string is not a user secret")
	assert.False(t, isUserSecretName("cred"), "bare 'cred' (no colon) is not a user secret")
}
