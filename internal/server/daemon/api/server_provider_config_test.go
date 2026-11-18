// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// server_provider_config_test.go — unit tests for the 11 provider CRUD handlers
// added by spec 25-daemon-driven-provider-config (task 3).
//
// Test strategy:
//   - All tests are pure in-process; no Redis, no real LLM API, no network.
//   - mockProviderStore injects deterministic responses.
//   - auditedServer wires an audit logger over audittest.Recorder.
//   - auth.ContextWithTenant injects a tenant without spinning up the interceptor.
//   - TestProvider uses a factory-injected mock provider to avoid any network calls.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
)

// ---------------------------------------------------------------------------
// mockProviderStore
// ---------------------------------------------------------------------------

// mockProviderStore satisfies providerConfigStoreIface for tests.
// All return values are configurable via exported fields.
type mockProviderStore struct {
	listOut    []*providerconfig.ProviderConfig
	listErr    error
	getOut     *providerconfig.ProviderConfig
	getErr     error
	createOut  *providerconfig.ProviderConfig
	createErr  error
	updateOut  *providerconfig.ProviderConfig
	updateErr  error
	deleteErr  error
	defaultOut *providerconfig.ProviderConfig
	defaultErr error
	setDefErr  error
	resolveOut *providerconfig.DecryptedConfig
	resolveErr error

	// captured inputs for mutation verification
	capturedCreateInput *providerconfig.ProviderConfigInput
	capturedUpdateName  string
	capturedUpdateInput *providerconfig.ProviderConfigInput
	capturedDeleteName  string
	capturedDefaultName string
}

func (m *mockProviderStore) List(_ context.Context, _ string) ([]*providerconfig.ProviderConfig, error) {
	return m.listOut, m.listErr
}

func (m *mockProviderStore) Get(_ context.Context, _ string, _ string) (*providerconfig.ProviderConfig, error) {
	return m.getOut, m.getErr
}

func (m *mockProviderStore) Create(_ context.Context, _ string, input *providerconfig.ProviderConfigInput) (*providerconfig.ProviderConfig, error) {
	m.capturedCreateInput = input
	return m.createOut, m.createErr
}

func (m *mockProviderStore) Update(_ context.Context, _, name string, input *providerconfig.ProviderConfigInput) (*providerconfig.ProviderConfig, error) {
	m.capturedUpdateName = name
	m.capturedUpdateInput = input
	return m.updateOut, m.updateErr
}

func (m *mockProviderStore) Delete(_ context.Context, _ string, name string) error {
	m.capturedDeleteName = name
	return m.deleteErr
}

func (m *mockProviderStore) GetDefault(_ context.Context, _ string) (*providerconfig.ProviderConfig, error) {
	return m.defaultOut, m.defaultErr
}

func (m *mockProviderStore) SetDefault(_ context.Context, _ string, name string) error {
	m.capturedDefaultName = name
	return m.setDefErr
}

func (m *mockProviderStore) Resolve(_ context.Context, _ string, _ string) (*providerconfig.DecryptedConfig, error) {
	return m.resolveOut, m.resolveErr
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// fakeProviderRecord returns a minimal ProviderConfig for use in mock returns.
func fakeProviderRecord(name string) *providerconfig.ProviderConfig {
	return &providerconfig.ProviderConfig{
		ID:                types.NewID(),
		TenantID:          "acme",
		Name:              name,
		Type:              llm.ProviderOpenAI,
		DefaultModel:      "gpt-4o-mini",
		IsDefault:         false,
		Enabled:           true,
		CredentialsMasked: map[string]string{"api_key": "****abcd"},
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
}

// serverWithStore returns a DaemonServer with the given store and optional
// audit logger wired in.
// auditedServer is a blankServer with an audit logger. The audit logger is
// required: the daemon wires it at start.
func auditedServer(t *testing.T) *DaemonServer {
	t.Helper()
	s := blankServer()
	s.auditLogger = auditLoggerOver(t, &audittest.Recorder{})
	return s
}

func serverWithStore(t *testing.T, store providerConfigStoreIface) *DaemonServer {
	t.Helper()
	s := auditedServer(t)
	s.providerConfig = store
	return s
}

// ---------------------------------------------------------------------------
// ListProviders
// ---------------------------------------------------------------------------

// Note: auth.TenantFromContext always returns at least "_system" (SystemTenant)
// for any non-nil context, so the tenantID == "" guard in handlers is
// exercised only by the FGA interceptor in production. Unit tests covering
// the nil-store and store-error paths are sufficient here.

func TestListProviders_NilStore_FailedPrecondition(t *testing.T) {
	s := auditedServer(t)
	_, err := s.ListProviders(tenantCtx("acme"), &tenantv1.ListProvidersRequest{})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
}

func TestListProviders_StoreError_Internal(t *testing.T) {
	store := &mockProviderStore{listErr: assert.AnError}
	s := serverWithStore(t, store)
	_, err := s.ListProviders(tenantCtx("acme"), &tenantv1.ListProvidersRequest{})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestListProviders_Empty_OK(t *testing.T) {
	store := &mockProviderStore{listOut: nil}
	s := serverWithStore(t, store)
	resp, err := s.ListProviders(tenantCtx("acme"), &tenantv1.ListProvidersRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Providers)
}

func TestListProviders_Multiple_ReturnedInOrder(t *testing.T) {
	store := &mockProviderStore{
		listOut: []*providerconfig.ProviderConfig{
			fakeProviderRecord("openai-primary"),
			fakeProviderRecord("anthropic-secondary"),
		},
	}
	s := serverWithStore(t, store)
	resp, err := s.ListProviders(tenantCtx("acme"), &tenantv1.ListProvidersRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Providers, 2)
	assert.Equal(t, "openai-primary", resp.Providers[0].Name)
	assert.Equal(t, "anthropic-secondary", resp.Providers[1].Name)
	// Credentials must be masked, not empty or plaintext.
	assert.Equal(t, "****abcd", resp.Providers[0].CredentialsMasked["api_key"])
}

// ---------------------------------------------------------------------------
// GetProvider
// ---------------------------------------------------------------------------

func TestGetProvider_NilStore_FailedPrecondition(t *testing.T) {
	s := auditedServer(t)
	_, err := s.GetProvider(tenantCtx("acme"), &tenantv1.GetProviderRequest{Name: "x"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
}

func TestGetProvider_NotFound_NotFound(t *testing.T) {
	store := &mockProviderStore{getErr: providerconfig.ErrNotFound}
	s := serverWithStore(t, store)
	_, err := s.GetProvider(tenantCtx("acme"), &tenantv1.GetProviderRequest{Name: "missing"})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestGetProvider_StoreError_Internal(t *testing.T) {
	store := &mockProviderStore{getErr: assert.AnError}
	s := serverWithStore(t, store)
	_, err := s.GetProvider(tenantCtx("acme"), &tenantv1.GetProviderRequest{Name: "x"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestGetProvider_Success_ReturnsRecord(t *testing.T) {
	cfg := fakeProviderRecord("openai-primary")
	store := &mockProviderStore{getOut: cfg}
	s := serverWithStore(t, store)
	resp, err := s.GetProvider(tenantCtx("acme"), &tenantv1.GetProviderRequest{Name: "openai-primary"})
	require.NoError(t, err)
	require.NotNil(t, resp.Provider)
	assert.Equal(t, "openai-primary", resp.Provider.Name)
	assert.Equal(t, "openai", resp.Provider.Type)
	assert.Equal(t, "gpt-4o-mini", resp.Provider.DefaultModel)
}

// ---------------------------------------------------------------------------
// CreateProvider
// ---------------------------------------------------------------------------

func TestCreateProvider_NilStore_FailedPrecondition(t *testing.T) {
	s := auditedServer(t)
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{Name: "p", Type: "openai"},
	})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
}

func TestCreateProvider_InvalidType_InvalidArgument(t *testing.T) {
	s := serverWithStore(t, &mockProviderStore{})
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{Name: "p", Type: "made-up-provider"},
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestCreateProvider_CustomType_InvalidArgument(t *testing.T) {
	s := serverWithStore(t, &mockProviderStore{})
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{Name: "p", Type: "custom"},
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestCreateProvider_AlreadyExists_AlreadyExists(t *testing.T) {
	store := &mockProviderStore{createErr: providerconfig.ErrAlreadyExists}
	s := serverWithStore(t, store)
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{Name: "dup", Type: "openai"},
	})
	assert.Equal(t, codes.AlreadyExists, grpcCode(err))
}

func TestCreateProvider_StoreError_Internal(t *testing.T) {
	store := &mockProviderStore{createErr: assert.AnError}
	s := serverWithStore(t, store)
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{Name: "p", Type: "openai"},
	})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestCreateProvider_Success_ReturnsRecordAndEmitsAudit(t *testing.T) {
	cfg := fakeProviderRecord("openai-new")
	store := &mockProviderStore{createOut: cfg}
	s := serverWithStore(t, store)
	// auditLogger is nil → emitProviderAudit is a no-op; no panic.
	resp, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:         "openai-new",
			Type:         "openai",
			DefaultModel: "gpt-4o-mini", DefaultModelContextWindow: 128000,
			Credentials: map[string]string{"api_key": "sk-test-key"},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.Provider)
	assert.Equal(t, "openai-new", resp.Provider.Name)
	// Verify the store was called with the correct type conversion.
	require.NotNil(t, store.capturedCreateInput)
	assert.Equal(t, llm.ProviderOpenAI, store.capturedCreateInput.Type)
}

func TestCreateProvider_CredentialsNotInResponse(t *testing.T) {
	cfg := fakeProviderRecord("p")
	store := &mockProviderStore{createOut: cfg}
	s := serverWithStore(t, store)
	resp, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{
		Input: &tenantv1.ProviderConfigInput{
			Name:        "p",
			Type:        "openai",
			Credentials: map[string]string{"api_key": "sk-super-secret-key-plaintext"},
		},
	})
	require.NoError(t, err)
	// The masked value from the store is "****abcd" (from fakeProviderRecord);
	// it must never equal the plaintext that was sent in.
	for _, v := range resp.Provider.CredentialsMasked {
		assert.NotContains(t, v, "sk-super-secret-key-plaintext",
			"plaintext credentials must not appear in the response")
	}
}

// ---------------------------------------------------------------------------
// UpdateProvider
// ---------------------------------------------------------------------------

func TestUpdateProvider_NilStore_FailedPrecondition(t *testing.T) {
	s := auditedServer(t)
	_, err := s.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{
		Name:  "p",
		Input: &tenantv1.ProviderConfigInput{Type: "openai"},
	})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
}

func TestUpdateProvider_NotFound_NotFound(t *testing.T) {
	store := &mockProviderStore{updateErr: providerconfig.ErrNotFound}
	s := serverWithStore(t, store)
	_, err := s.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{
		Name:  "missing",
		Input: &tenantv1.ProviderConfigInput{Type: "openai"},
	})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestUpdateProvider_Success_PassesNameToStore(t *testing.T) {
	cfg := fakeProviderRecord("openai-updated")
	store := &mockProviderStore{updateOut: cfg}
	s := serverWithStore(t, store)
	resp, err := s.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{
		Name:  "openai-updated",
		Input: &tenantv1.ProviderConfigInput{Type: "openai", DefaultModel: "gpt-4o", DefaultModelContextWindow: 128000},
	})
	require.NoError(t, err)
	assert.Equal(t, "openai-updated", store.capturedUpdateName)
	assert.Equal(t, "openai-updated", resp.Provider.Name)
}

// ---------------------------------------------------------------------------
// DeleteProvider
// ---------------------------------------------------------------------------

func TestDeleteProvider_NilStore_FailedPrecondition(t *testing.T) {
	s := auditedServer(t)
	_, err := s.DeleteProvider(tenantCtx("acme"), &tenantv1.DeleteProviderRequest{Name: "p"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
}

func TestDeleteProvider_NotFound_NotFound(t *testing.T) {
	store := &mockProviderStore{deleteErr: providerconfig.ErrNotFound}
	s := serverWithStore(t, store)
	_, err := s.DeleteProvider(tenantCtx("acme"), &tenantv1.DeleteProviderRequest{Name: "gone"})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestDeleteProvider_Success_PassesNameToStore(t *testing.T) {
	store := &mockProviderStore{}
	s := serverWithStore(t, store)
	_, err := s.DeleteProvider(tenantCtx("acme"), &tenantv1.DeleteProviderRequest{Name: "old-provider"})
	require.NoError(t, err)
	assert.Equal(t, "old-provider", store.capturedDeleteName)
}

// ---------------------------------------------------------------------------
// GetDefaultProvider
// ---------------------------------------------------------------------------

func TestGetDefaultProvider_NilStore_FailedPrecondition(t *testing.T) {
	s := auditedServer(t)
	_, err := s.GetDefaultProvider(tenantCtx("acme"), &tenantv1.GetDefaultProviderRequest{})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
}

func TestGetDefaultProvider_NotFound_NotFound(t *testing.T) {
	store := &mockProviderStore{defaultErr: providerconfig.ErrNotFound}
	s := serverWithStore(t, store)
	_, err := s.GetDefaultProvider(tenantCtx("acme"), &tenantv1.GetDefaultProviderRequest{})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestGetDefaultProvider_Success(t *testing.T) {
	cfg := fakeProviderRecord("default-prov")
	cfg.IsDefault = true
	store := &mockProviderStore{defaultOut: cfg}
	s := serverWithStore(t, store)
	resp, err := s.GetDefaultProvider(tenantCtx("acme"), &tenantv1.GetDefaultProviderRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.Provider)
	assert.Equal(t, "default-prov", resp.Provider.Name)
	assert.True(t, resp.Provider.IsDefault)
}

// ---------------------------------------------------------------------------
// SetDefaultProvider
// ---------------------------------------------------------------------------

func TestSetDefaultProvider_NilStore_FailedPrecondition(t *testing.T) {
	s := auditedServer(t)
	_, err := s.SetDefaultProvider(tenantCtx("acme"), &tenantv1.SetDefaultProviderRequest{Name: "p"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
}

func TestSetDefaultProvider_StoreError_Internal(t *testing.T) {
	store := &mockProviderStore{setDefErr: assert.AnError}
	s := serverWithStore(t, store)
	_, err := s.SetDefaultProvider(tenantCtx("acme"), &tenantv1.SetDefaultProviderRequest{Name: "p"})
	assert.Equal(t, codes.Internal, grpcCode(err))
}

func TestSetDefaultProvider_Success_PassesNameAndEmitsAudit(t *testing.T) {
	cfg := fakeProviderRecord("primary")
	cfg.IsDefault = true
	store := &mockProviderStore{getOut: cfg}
	s := serverWithStore(t, store)
	resp, err := s.SetDefaultProvider(tenantCtx("acme"), &tenantv1.SetDefaultProviderRequest{Name: "primary"})
	require.NoError(t, err)
	assert.Equal(t, "primary", store.capturedDefaultName)
	// Response should contain the updated record from the follow-up Get.
	require.NotNil(t, resp.Provider)
	assert.Equal(t, "primary", resp.Provider.Name)
}

func TestSetDefaultProvider_GetFailureAfterSet_ReturnsEmpty(t *testing.T) {
	// setDefault succeeds but the follow-up Get fails → return empty response
	// rather than propagating the read error.
	store := &mockProviderStore{getErr: assert.AnError}
	s := serverWithStore(t, store)
	resp, err := s.SetDefaultProvider(tenantCtx("acme"), &tenantv1.SetDefaultProviderRequest{Name: "p"})
	require.NoError(t, err) // no gRPC-level error
	assert.Nil(t, resp.Provider)
}

// ---------------------------------------------------------------------------
// GetProviderHealth
// ---------------------------------------------------------------------------

func TestGetProviderHealth_NilStore_FailedPrecondition(t *testing.T) {
	s := auditedServer(t)
	_, err := s.GetProviderHealth(tenantCtx("acme"), &tenantv1.GetProviderHealthRequest{Name: "p"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err))
}

func savedProviderStore() *mockProviderStore {
	return &mockProviderStore{getOut: &providerconfig.ProviderConfig{Name: "p", Type: llm.ProviderOpenAI, DefaultModel: "gpt-x", Enabled: true}}
}

func TestGetProviderHealth_NotFound_NotFound(t *testing.T) {
	s := serverWithStore(t, &mockProviderStore{getErr: providerconfig.ErrNotFound})
	s.modelLister = &fakeLister{}
	_, err := s.GetProviderHealth(tenantCtx("acme"), &tenantv1.GetProviderHealthRequest{Name: "missing"})
	assert.Equal(t, codes.NotFound, grpcCode(err))
}

func TestGetProviderHealth_ReportsTheListCall(t *testing.T) {
	s := serverWithStore(t, savedProviderStore())
	s.modelLister = &fakeLister{models: map[string][]modelclient.ModelEntry{"p": {{ID: "m"}}}}
	resp, err := s.GetProviderHealth(tenantCtx("acme"), &tenantv1.GetProviderHealthRequest{Name: "p"})
	require.NoError(t, err)
	assert.True(t, resp.Healthy)

	s.modelLister = &fakeLister{errs: map[string]error{"p": &modelclient.APIError{Status: 404}}}
	resp, err = s.GetProviderHealth(tenantCtx("acme"), &tenantv1.GetProviderHealthRequest{Name: "p"})
	require.NoError(t, err)
	assert.False(t, resp.Healthy)
	assert.Contains(t, resp.Error, "not ready")
}

// ---------------------------------------------------------------------------
// TestProvider and ListProviderModels: one GET of the model list of a saved
// provider through the gateway (gibson#1394).
// ---------------------------------------------------------------------------

type recordingLister struct {
	callers []modelclient.Caller
	targets []modelclient.Target
	models  []modelclient.ModelEntry
	err     error
	calls   int
}

func (r *recordingLister) Models(_ context.Context, c modelclient.Caller, t modelclient.Target) ([]modelclient.ModelEntry, error) {
	r.calls++
	r.callers, r.targets = append(r.callers, c), append(r.targets, t)
	return r.models, r.err
}

func TestTestProvider_NeedsASavedProvider(t *testing.T) {
	rec := &recordingLister{}
	s := serverWithStore(t, &mockProviderStore{getErr: providerconfig.ErrNotFound})
	s.modelLister = rec
	_, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{Name: "not-saved"})
	assert.Equal(t, codes.NotFound, grpcCode(err))
	assert.Zero(t, rec.calls, "no call tests a provider that is not saved")

	_, err = s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestTestProvider_SendsOneListCallWithTheProbePurpose(t *testing.T) {
	rec := &recordingLister{models: []modelclient.ModelEntry{{ID: "b", ContextWindow: 100}, {ID: "a"}}}
	s := serverWithStore(t, savedProviderStore())
	s.modelLister = rec
	resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{Name: "p"})
	require.NoError(t, err)
	assert.True(t, resp.Ok)
	assert.Equal(t, "gpt-x", resp.Model)
	require.Len(t, resp.Models, 2)
	assert.Equal(t, "a", resp.Models[0].Name, "the models are sorted")
	require.Equal(t, 1, rec.calls)
	assert.Equal(t, "provider_probe", rec.callers[0].Purpose)
	assert.Equal(t, "user:user-test", rec.callers[0].Initiator)
	assert.Equal(t, modelclient.Target{Tenant: "acme", Provider: "p"}, rec.targets[0])
}

func TestTestProvider_AFailedCallIsAnAnswerAndNotAnError(t *testing.T) {
	cases := map[int]string{
		http.StatusNotFound:  "not ready",
		http.StatusForbidden: "refused",
	}
	for status, want := range cases {
		rec := &recordingLister{err: &modelclient.APIError{Status: status, Body: "x"}}
		s := serverWithStore(t, savedProviderStore())
		s.modelLister = rec
		resp, err := s.TestProvider(tenantCtx("acme"), &tenantv1.TestProviderRequest{Name: "p"})
		require.NoError(t, err)
		assert.False(t, resp.Ok)
		assert.Contains(t, resp.Error, want)
	}
}

func TestListProviderModels_CachesAGoodListAndDropsItOnUpdate(t *testing.T) {
	rec := &recordingLister{models: []modelclient.ModelEntry{{ID: "m1"}}}
	store := savedProviderStore()
	store.updateOut = fakeProviderRecord("p")
	store.getOut.DefaultModel = "m1"
	store.getOut.DefaultModelContextWindow = 1000
	s := serverWithStore(t, store)
	s.modelLister = rec
	ctx := tenantCtx("acme")

	for range 2 {
		resp, err := s.ListProviderModels(ctx, &tenantv1.ListProviderModelsRequest{Name: "p"})
		require.NoError(t, err)
		assert.True(t, resp.Ok)
	}
	assert.Equal(t, 1, rec.calls, "the second call is served from the cache")
	assert.Equal(t, "model_list", rec.callers[0].Purpose)

	_, err := s.UpdateProvider(ctx, &tenantv1.UpdateProviderRequest{Name: "p", Input: anthropicSaveInput("m1", 1000)})
	require.NoError(t, err)
	_, err = s.ListProviderModels(ctx, &tenantv1.ListProviderModelsRequest{Name: "p"})
	require.NoError(t, err)
	assert.Equal(t, 2, rec.calls, "an update drops the cache")
}

func TestListProviderModels_AFailedCallIsNotCached(t *testing.T) {
	rec := &recordingLister{err: &modelclient.APIError{Status: http.StatusTooManyRequests}}
	s := serverWithStore(t, savedProviderStore())
	s.modelLister = rec
	resp, err := s.ListProviderModels(tenantCtx("acme"), &tenantv1.ListProviderModelsRequest{Name: "p"})
	require.NoError(t, err)
	assert.False(t, resp.Ok)
	assert.Equal(t, "rate_limited", resp.ErrorClass)
	rec.err = nil
	rec.models = []modelclient.ModelEntry{{ID: "m"}}
	resp, err = s.ListProviderModels(tenantCtx("acme"), &tenantv1.ListProviderModelsRequest{Name: "p"})
	require.NoError(t, err)
	assert.True(t, resp.Ok, "the failure left no entry")
}

func TestProviderModelHandlers_NeedTheClientAndTheStore(t *testing.T) {
	s := serverWithStore(t, savedProviderStore())
	_, err := s.ListProviderModels(tenantCtx("acme"), &tenantv1.ListProviderModelsRequest{Name: "p"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err), "no model client")
	_, err = auditedServer(t).ListProviderModels(tenantCtx("acme"), &tenantv1.ListProviderModelsRequest{Name: "p"})
	assert.Equal(t, codes.FailedPrecondition, grpcCode(err), "no store")
	_, err = s.ListProviderModels(context.Background(), &tenantv1.ListProviderModelsRequest{Name: "p"})
	assert.Equal(t, codes.Unauthenticated, grpcCode(err))
}

// ---------------------------------------------------------------------------
// Error translation coverage — toGRPCProviderError
// ---------------------------------------------------------------------------

func TestErrorTranslation_AllSentinels(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{"ErrNotFound", providerconfig.ErrNotFound, codes.NotFound},
		{"ErrAlreadyExists", providerconfig.ErrAlreadyExists, codes.AlreadyExists},
		{"ErrUnsupportedType", providerconfig.ErrUnsupportedType, codes.InvalidArgument},
		{"ErrKeyProviderUnset", providerconfig.ErrKeyProviderUnset, codes.FailedPrecondition},
		{"unknown error", assert.AnError, codes.Internal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toGRPCProviderError("op", tc.err)
			assert.Equal(t, tc.wantCode, grpcCode(got))
		})
	}
}

// ---------------------------------------------------------------------------
// toProtoProviderRecord
// ---------------------------------------------------------------------------

func TestToProtoProviderRecord_NilInput_ReturnsNil(t *testing.T) {
	assert.Nil(t, toProtoProviderRecord(nil))
}

func TestToProtoProviderRecord_FieldMapping(t *testing.T) {
	cfg := fakeProviderRecord("prov")
	cfg.IsDefault = true
	cfg.Enabled = false
	rec := toProtoProviderRecord(cfg)
	require.NotNil(t, rec)
	assert.Equal(t, cfg.ID.String(), rec.Id)
	assert.Equal(t, "prov", rec.Name)
	assert.Equal(t, "openai", rec.Type)
	assert.Equal(t, "gpt-4o-mini", rec.DefaultModel)
	assert.True(t, rec.IsDefault)
	assert.False(t, rec.Enabled)
	assert.Equal(t, map[string]string{"api_key": "****abcd"}, rec.CredentialsMasked)
	assert.NotEmpty(t, rec.CreatedAt)
	assert.NotEmpty(t, rec.UpdatedAt)
}

// ---------------------------------------------------------------------------
// fromProtoInput
// ---------------------------------------------------------------------------

func TestFromProtoInput_NilReturnsEmpty(t *testing.T) {
	out := fromProtoInput(nil)
	require.NotNil(t, out)
	assert.Equal(t, llm.ProviderType(""), out.Type)
	assert.Empty(t, out.Name)
}

func TestFromProtoInput_CredentialsCopied(t *testing.T) {
	in := &tenantv1.ProviderConfigInput{
		Name:         "p",
		Type:         "anthropic",
		DefaultModel: "claude-3-5-sonnet-20241022",
		Credentials:  map[string]string{"api_key": "sk-ant-test", "region": "us-east-1"},
		SetAsDefault: true,
	}
	out := fromProtoInput(in)
	assert.Equal(t, llm.ProviderAnthropic, out.Type)
	assert.Equal(t, "sk-ant-test", out.Credentials["api_key"])
	assert.Equal(t, "us-east-1", out.Credentials["region"])
	assert.True(t, out.SetAsDefault)
	assert.True(t, out.Enabled, "new providers should default to enabled")
}

// ---------------------------------------------------------------------------
// validateProviderInput
// ---------------------------------------------------------------------------

func TestValidateProviderInput_NilInput_Error(t *testing.T) {
	err := validateProviderInput(nil)
	require.Error(t, err)
}

func TestValidateProviderInput_CustomType_Error(t *testing.T) {
	err := validateProviderInput(&tenantv1.ProviderConfigInput{Type: "custom"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "operator-only")
}

func TestValidateProviderInput_UnknownType_Error(t *testing.T) {
	err := validateProviderInput(&tenantv1.ProviderConfigInput{Type: "notreal"})
	require.Error(t, err)
}

func TestValidateProviderInput_KnownTypes_NoError(t *testing.T) {
	for _, typ := range llm.SupportedProviderTypes() {
		if typ == llm.ProviderCustom {
			continue
		}
		t.Run(string(typ), func(t *testing.T) {
			// Embedding-only providers (voyage, openai-compatible, tei) must
			// declare CAPABILITY_EMBEDDING and a known default_embedding_model.
			isEmbeddingOnly := typ == llm.ProviderVoyage ||
				typ == llm.ProviderOpenAICompatible ||
				typ == llm.ProviderTEI
			input := &tenantv1.ProviderConfigInput{Type: string(typ)}
			if isEmbeddingOnly {
				input.Capabilities = []tenantv1.Capability{tenantv1.Capability_CAPABILITY_EMBEDDING}
				input.DefaultEmbeddingModel = "text-embedding-3-small"
			}
			err := validateProviderInput(input)
			assert.NoError(t, err, "supported type %q must validate successfully", typ)
		})
	}
}

// ---------------------------------------------------------------------------
// Audit emission — nil logger is a no-op
// ---------------------------------------------------------------------------

func TestEmitProviderAudit_WritesTheRecord(t *testing.T) {
	rec := &audittest.Recorder{}
	s := auditedServer(t)
	s.auditLogger = auditLoggerOver(t, rec)
	s.emitProviderAudit(tenantCtx("acme"), "acme", auditProviderTested, "my-provider")
	require.Eventually(t, func() bool { return len(rec.Events()) == 1 }, 2*time.Second, 10*time.Millisecond)
	assert.Equal(t, "my-provider", rec.Events()[0].TargetID)
}
