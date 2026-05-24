package component

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/secrets"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Stubs for secrets.Service
// ---------------------------------------------------------------------------

type compTestBroker struct {
	getVal []byte
	getErr error
}

func (b *compTestBroker) Get(_ context.Context, _ auth.TenantID, _ string) ([]byte, error) {
	return b.getVal, b.getErr
}
func (b *compTestBroker) Put(_ context.Context, _ auth.TenantID, _ string, _ []byte) error {
	return nil
}
func (b *compTestBroker) Delete(_ context.Context, _ auth.TenantID, _ string) error { return nil }
func (b *compTestBroker) List(_ context.Context, _ auth.TenantID, _ sdksecrets.Filter) ([]string, error) {
	return nil, nil
}
func (b *compTestBroker) Health(_ context.Context) error { return nil }
func (b *compTestBroker) Probe(_ context.Context) error  { return nil }
func (b *compTestBroker) Capabilities() sdksecrets.Capabilities {
	return sdksecrets.Capabilities{CanPut: true, CanDelete: true, CanList: true, MaxValueBytes: 1 << 20}
}

var _ sdksecrets.Broker = (*compTestBroker)(nil)

type compTestRegistry struct {
	broker sdksecrets.Broker
	err    error
}

func (r *compTestRegistry) For(_ context.Context, _ auth.TenantID) (sdksecrets.Broker, error) {
	return r.broker, r.err
}

type compTestCircuit struct{}

func (c *compTestCircuit) Execute(_, _ string, fn func() error) error { return fn() }

type compTestAuditor struct{}

func (a *compTestAuditor) Audit(_ context.Context, _ secrets.AuditEvent) {}

func buildCompTestService(t *testing.T, val []byte, err error) *secrets.Service {
	t.Helper()
	broker := &compTestBroker{getVal: val, getErr: err}
	reg := &compTestRegistry{broker: broker}
	svc, svcErr := secrets.NewService(reg, &compTestCircuit{}, &compTestAuditor{})
	require.NoError(t, svcErr)
	return svc
}

func compCtx() context.Context {
	return auth.WithTenant(context.Background(), auth.MustNewTenantID("acme-tenant"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewSecretsCredentialStore_NilService(t *testing.T) {
	store, err := NewSecretsCredentialStore(nil)
	assert.Error(t, err)
	assert.Nil(t, store)
	assert.Contains(t, err.Error(), "service must not be nil")
}

func TestSecretsCredentialStore_GetCredential_Success(t *testing.T) {
	svc := buildCompTestService(t, []byte("my-api-key"), nil)
	store, err := NewSecretsCredentialStore(svc)
	require.NoError(t, err)

	credJSON, err := store.GetCredential(compCtx(), "acme-tenant", "cred:openai")
	require.NoError(t, err)
	require.NotEmpty(t, credJSON)

	// Verify the JSON envelope shape.
	var envelope credentialJSONEnvelope
	require.NoError(t, json.Unmarshal(credJSON, &envelope))
	assert.Equal(t, "cred:openai", envelope.Name)
	assert.Equal(t, "my-api-key", envelope.Value)
	assert.NotEmpty(t, envelope.ID)
}

func TestSecretsCredentialStore_GetCredential_NotFound(t *testing.T) {
	svc := buildCompTestService(t, nil, status.Error(codes.NotFound, "not found"))
	store, err := NewSecretsCredentialStore(svc)
	require.NoError(t, err)

	_, err = store.GetCredential(compCtx(), "acme-tenant", "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestSecretsCredentialStore_GetCredential_Unavailable(t *testing.T) {
	svc := buildCompTestService(t, nil, status.Error(codes.Unavailable, "circuit open"))
	store, err := NewSecretsCredentialStore(svc)
	require.NoError(t, err)

	_, err = store.GetCredential(compCtx(), "acme-tenant", "some-cred")
	require.Error(t, err)
}

func TestSecretsCredentialStore_ImplementsInterface(t *testing.T) {
	svc := buildCompTestService(t, nil, nil)
	store, err := NewSecretsCredentialStore(svc)
	require.NoError(t, err)
	assert.Implements(t, (*CredentialStore)(nil), store)
}
