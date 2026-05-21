package api

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/secrets"
	"github.com/zero-day-ai/gibson/internal/types"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"

	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Stubs for secrets.Service
// ---------------------------------------------------------------------------

type apiTestBroker struct {
	getVal []byte
	getErr error
	putErr error
	delErr error
	lstVal []string
	lstErr error
}

func (b *apiTestBroker) Get(_ context.Context, _ auth.TenantID, _ string) ([]byte, error) {
	return b.getVal, b.getErr
}
func (b *apiTestBroker) Put(_ context.Context, _ auth.TenantID, _ string, _ []byte) error {
	return b.putErr
}
func (b *apiTestBroker) Delete(_ context.Context, _ auth.TenantID, _ string) error {
	return b.delErr
}
func (b *apiTestBroker) List(_ context.Context, _ auth.TenantID, _ sdksecrets.Filter) ([]string, error) {
	return b.lstVal, b.lstErr
}
func (b *apiTestBroker) Health(_ context.Context) error { return nil }
func (b *apiTestBroker) Probe(_ context.Context) error  { return nil }
func (b *apiTestBroker) Capabilities() sdksecrets.Capabilities {
	return sdksecrets.Capabilities{CanPut: true, CanDelete: true, CanList: true, MaxValueBytes: 1 << 20}
}

var _ sdksecrets.Broker = (*apiTestBroker)(nil)

type apiTestRegistry struct {
	broker sdksecrets.Broker
	err    error
}

func (r *apiTestRegistry) For(_ context.Context, _ auth.TenantID) (sdksecrets.Broker, error) {
	return r.broker, r.err
}

type apiTestCircuit struct{}

func (c *apiTestCircuit) Allow(_, _ string) error   { return nil }
func (c *apiTestCircuit) RecordSuccess(_, _ string) {}
func (c *apiTestCircuit) RecordFailure(_, _ string) {}

type apiTestAuditor struct{}

func (a *apiTestAuditor) Audit(_ context.Context, _ secrets.AuditEvent) {}

func buildAPITestService(t *testing.T, broker *apiTestBroker) *secrets.Service {
	t.Helper()
	reg := &apiTestRegistry{broker: broker}
	svc, err := secrets.NewService(reg, &apiTestCircuit{}, &apiTestAuditor{})
	require.NoError(t, err)
	return svc
}

func apiCtx() context.Context {
	return auth.WithTenant(context.Background(), auth.MustNewTenantID("dashboard-tenant"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewCredentialHandler(t *testing.T) {
	broker := &apiTestBroker{}
	svc := buildAPITestService(t, broker)

	t.Run("success", func(t *testing.T) {
		handler, err := NewCredentialHandler(svc)
		require.NoError(t, err)
		assert.NotNil(t, handler)
	})

	t.Run("nil service", func(t *testing.T) {
		_, err := NewCredentialHandler(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "service must not be nil")
	})
}

func TestCredentialHandler_Create_Success(t *testing.T) {
	broker := &apiTestBroker{}
	svc := buildAPITestService(t, broker)
	handler, err := NewCredentialHandler(svc)
	require.NoError(t, err)

	resp, err := handler.Create(apiCtx(), CredentialCreateRequest{
		Name:   "my-cred",
		Type:   types.CredentialTypeAPIKey,
		APIKey: "sk-test-1234",
	})
	require.NoError(t, err)
	assert.Equal(t, "my-cred", resp.Name)
	assert.NotEmpty(t, resp.MaskedKey)
	assert.NotContains(t, resp.MaskedKey, "sk-test-1234") // must not contain plaintext
}

func TestCredentialHandler_Create_EmptyName(t *testing.T) {
	broker := &apiTestBroker{}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	_, err := handler.Create(apiCtx(), CredentialCreateRequest{
		Name:   "",
		Type:   types.CredentialTypeAPIKey,
		APIKey: "sk-test",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name cannot be empty")
}

func TestCredentialHandler_Create_EmptyAPIKey(t *testing.T) {
	broker := &apiTestBroker{}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	_, err := handler.Create(apiCtx(), CredentialCreateRequest{
		Name:   "my-cred",
		Type:   types.CredentialTypeAPIKey,
		APIKey: "",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key cannot be empty")
}

func TestCredentialHandler_GetByName_Success(t *testing.T) {
	broker := &apiTestBroker{getVal: []byte("secret-value")}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	resp, err := handler.GetByName(apiCtx(), "my-cred")
	require.NoError(t, err)
	assert.Equal(t, "my-cred", resp.Name)
	assert.NotEmpty(t, resp.MaskedKey)
}

func TestCredentialHandler_GetByName_NotFound(t *testing.T) {
	// Return sdksecrets.ErrNotFound so secrets.Service maps it to codes.NotFound.
	broker := &apiTestBroker{getErr: fmt.Errorf("missing: %w", sdksecrets.ErrNotFound)}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	_, err := handler.GetByName(apiCtx(), "missing")
	require.Error(t, err)
}

func TestCredentialHandler_GetDecrypted_Success(t *testing.T) {
	broker := &apiTestBroker{getVal: []byte("plaintext-key")}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	cred, secret, err := handler.GetDecrypted(apiCtx(), "my-cred")
	require.NoError(t, err)
	assert.Equal(t, "my-cred", cred.Name)
	assert.Equal(t, "plaintext-key", secret)
}

func TestCredentialHandler_List_Success(t *testing.T) {
	broker := &apiTestBroker{lstVal: []string{"cred1", "cred2", "cred3"}}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	responses, err := handler.List(apiCtx(), nil)
	require.NoError(t, err)
	require.Len(t, responses, 3)
	assert.Equal(t, "cred1", responses[0].Name)
}

func TestCredentialHandler_List_WithFilter(t *testing.T) {
	broker := &apiTestBroker{lstVal: []string{"cred1"}}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	responses, err := handler.List(apiCtx(), &types.CredentialFilter{Limit: 10})
	require.NoError(t, err)
	require.Len(t, responses, 1)
}

func TestCredentialHandler_Update_Success(t *testing.T) {
	broker := &apiTestBroker{}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	name := "my-cred"
	key := "new-key-value"
	resp, err := handler.Update(apiCtx(), CredentialUpdateRequest{
		Name:   &name,
		APIKey: &key,
	})
	require.NoError(t, err)
	assert.Equal(t, "my-cred", resp.Name)
}

func TestCredentialHandler_Update_UnsupportedOnReadOnlyProvider(t *testing.T) {
	// Return sdksecrets.ErrUnsupported so secrets.Service maps it to codes.FailedPrecondition.
	broker := &apiTestBroker{putErr: fmt.Errorf("unsupported: %w", sdksecrets.ErrUnsupported)}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	name := "my-cred"
	key := "new-key"
	_, err := handler.Update(apiCtx(), CredentialUpdateRequest{
		Name:   &name,
		APIKey: &key,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported on read-only provider")
}

func TestCredentialHandler_Update_NilAPIKey(t *testing.T) {
	broker := &apiTestBroker{}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	_, err := handler.Update(apiCtx(), CredentialUpdateRequest{APIKey: nil})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "APIKey is required")
}

func TestCredentialHandler_DeleteByName_Success(t *testing.T) {
	broker := &apiTestBroker{}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	err := handler.DeleteByName(apiCtx(), "my-cred")
	assert.NoError(t, err)
}

func TestCredentialHandler_Exists_True(t *testing.T) {
	broker := &apiTestBroker{getVal: []byte("value")}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	exists, err := handler.Exists(apiCtx(), "my-cred")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestCredentialHandler_Exists_False(t *testing.T) {
	// Return sdksecrets.ErrNotFound so secrets.Service maps it to codes.NotFound.
	broker := &apiTestBroker{getErr: fmt.Errorf("missing: %w", sdksecrets.ErrNotFound)}
	svc := buildAPITestService(t, broker)
	handler, _ := NewCredentialHandler(svc)

	exists, err := handler.Exists(apiCtx(), "my-cred")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestMaskAPIKey exercises the masking helper.
func TestMaskAPIKey(t *testing.T) {
	assert.Equal(t, "", maskAPIKey(""))
	assert.Equal(t, "***", maskAPIKey("abc"))
	assert.Equal(t, "sk-a****5678", maskAPIKey("sk-ant-api03-12345678"))
}
