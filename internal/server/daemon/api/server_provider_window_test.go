// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// server_provider_window_test.go — gibson#1193, gibson#1394. The context window
// of the saved model is stored with the provider config at save time. The caller
// states it. The save path calls no provider, so it never asks a model list.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/platform/providerconfig"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

func anthropicSaveInput(model string, window int32) *tenantv1.ProviderConfigInput {
	return &tenantv1.ProviderConfigInput{
		Name: "anthropic-prod", Type: "anthropic", DefaultModel: model,
		DefaultModelContextWindow: window,
		Credentials:               map[string]string{"api_key": "sk-good"},
	}
}

func TestCreateProvider_StoresTheStatedWindowAndCallsNoProvider(t *testing.T) {
	rec := &recordingLister{}
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := serverWithStore(t, store)
	s.modelLister = rec

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-x", 64000)})
	require.NoError(t, err)
	assert.Equal(t, 64000, store.capturedCreateInput.DefaultModelContextWindow)
	assert.Zero(t, rec.calls, "the save path asks no model list")
}

func TestCreateProvider_RefusesAChatModelWithNoStatedWindow(t *testing.T) {
	rec := &recordingLister{models: []modelclient.ModelEntry{{ID: "claude-a", ContextWindow: 200000}}}
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := serverWithStore(t, store)
	s.modelLister = rec

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", 0)})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
	assert.Contains(t, err.Error(), "default_model_context_window")
	assert.Contains(t, err.Error(), "claude-a")
	assert.Nil(t, store.capturedCreateInput, "nothing is saved")
	assert.Zero(t, rec.calls, "the refusal comes with no provider call")
}

func TestCreateProvider_NoWindowIsNeededWithoutAChatModel(t *testing.T) {
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := serverWithStore(t, store)
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("", 0)})
	require.NoError(t, err)

	s2 := serverWithStore(t, &mockProviderStore{createOut: fakeProviderRecord("v")})
	_, err = s2.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: &tenantv1.ProviderConfigInput{
		Name: "v", Type: "openai-compatible", DefaultModel: "m", DefaultEmbeddingModel: "text-embedding-3-small",
		Capabilities: []tenantv1.Capability{tenantv1.Capability_CAPABILITY_EMBEDDING},
		Credentials:  map[string]string{"api_key": "k", "base_url": "https://x.example"},
	}})
	require.NoError(t, err)
}

func TestUpdateProvider_StoresTheStatedWindow(t *testing.T) {
	store := &mockProviderStore{updateOut: fakeProviderRecord("p")}
	s := serverWithStore(t, store)
	_, err := s.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{Name: "anthropic-prod", Input: anthropicSaveInput("claude-a", 123456)})
	require.NoError(t, err)
	assert.Equal(t, 123456, store.capturedUpdateInput.DefaultModelContextWindow)

	// A refusal on update saves nothing.
	store2 := &mockProviderStore{updateOut: fakeProviderRecord("p")}
	_, err = serverWithStore(t, store2).UpdateProvider(tenantCtx("acme"),
		&tenantv1.UpdateProviderRequest{Name: "anthropic-prod", Input: anthropicSaveInput("claude-a", 0)})
	require.Error(t, err)
	assert.Nil(t, store2.capturedUpdateInput)
}

func TestFromProtoInput_CarriesTheStatedWindow(t *testing.T) {
	in := fromProtoInput(&tenantv1.ProviderConfigInput{DefaultModelContextWindow: 654})
	assert.Equal(t, 654, in.DefaultModelContextWindow)
}

func TestSave_AStatedWindowMustBeInRange(t *testing.T) {
	for name, window := range map[string]int32{"negative": -1, "above the bound": maxContextWindow + 1} {
		t.Run(name, func(t *testing.T) {
			store := &mockProviderStore{createOut: fakeProviderRecord("p")}
			_, err := serverWithStore(t, store).CreateProvider(tenantCtx("acme"),
				&tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", window)})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, grpcCode(err))
			assert.Contains(t, err.Error(), "out of range")
			assert.Nil(t, store.capturedCreateInput)
		})
	}
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	_, err := serverWithStore(t, store).CreateProvider(tenantCtx("acme"),
		&tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", maxContextWindow)})
	require.NoError(t, err, "the bound itself is allowed")
}

func updateReq(model string, window int32) *tenantv1.UpdateProviderRequest {
	return &tenantv1.UpdateProviderRequest{Name: "anthropic-prod", Input: anthropicSaveInput(model, window)}
}

func storedProvider(model string, window int) *providerconfig.ProviderConfig {
	rec := fakeProviderRecord("anthropic-prod")
	rec.Type = providerconfig.ProviderAnthropic
	rec.DefaultModel = model
	rec.DefaultModelContextWindow = window
	return rec
}

func TestUpdateProvider_KeepsTheStoredWindowWhenTheModelIsUnchanged(t *testing.T) {
	store := &mockProviderStore{getOut: storedProvider("claude-a", 200000), updateOut: fakeProviderRecord("p")}
	_, err := serverWithStore(t, store).UpdateProvider(tenantCtx("acme"), updateReq("claude-a", 0))
	require.NoError(t, err)
	assert.Equal(t, 200000, store.capturedUpdateInput.DefaultModelContextWindow, "the stored window is kept")
}

func TestUpdateProvider_AModelChangeNeedsTheWindowStated(t *testing.T) {
	store := &mockProviderStore{getOut: storedProvider("claude-a", 200000), updateOut: fakeProviderRecord("p")}
	s := serverWithStore(t, store)
	_, err := s.UpdateProvider(tenantCtx("acme"), updateReq("claude-b", 0))
	require.Error(t, err, "a new model gets no window from the old one")
	assert.Contains(t, err.Error(), "default_model_context_window")
	assert.Nil(t, store.capturedUpdateInput)

	_, err = s.UpdateProvider(tenantCtx("acme"), updateReq("claude-b", 1000000))
	require.NoError(t, err)
	assert.Equal(t, 1000000, store.capturedUpdateInput.DefaultModelContextWindow)
}

func TestUpdateProvider_ALegacyProviderIsSavedAgainWithoutAWindow(t *testing.T) {
	store := &mockProviderStore{getOut: storedProvider("claude-a", 0), updateOut: fakeProviderRecord("p")}
	_, err := serverWithStore(t, store).UpdateProvider(tenantCtx("acme"), updateReq("claude-a", 0))
	require.NoError(t, err, "an edit that does not touch the model is never refused")
	assert.Zero(t, store.capturedUpdateInput.DefaultModelContextWindow)
}

func TestUpdateProvider_UnknownNameIsNotFound(t *testing.T) {
	store := &mockProviderStore{getErr: providerconfig.ErrNotFound}
	_, err := serverWithStore(t, store).UpdateProvider(tenantCtx("acme"), updateReq("claude-a", 1000))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, grpcCode(err))
}
