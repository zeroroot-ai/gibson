// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// server_provider_window_test.go — gibson#1193. The context window of the saved
// model is stored with the provider config at save time: from the caller, else
// from the live model list, else the save is refused.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
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

func TestCreateProvider_StoresTheWindowTheListReports(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK,
		`{"data":[{"id":"claude-a","max_input_tokens":200000},{"id":"claude-b"}],"has_more":false}`)
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", 0)})
	require.NoError(t, err)
	require.NotNil(t, store.capturedCreateInput)
	assert.Equal(t, 200000, store.capturedCreateInput.DefaultModelContextWindow, "the window comes from the live list")
	assert.Zero(t, fake.otherCalls.Load(), "no completion is sent")
}

func TestCreateProvider_AWindowTheCallerStatesIsUsedWhenTheListDoesNotNameTheModel(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK, `{"data":[],"has_more":false}`)
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-x", 64000)})
	require.NoError(t, err)
	assert.Equal(t, 64000, store.capturedCreateInput.DefaultModelContextWindow)
	assert.EqualValues(t, 1, fake.listCalls.Load(), "the list is asked only to check the stated window")
}

func TestCreateProvider_RefusesWhenTheProviderReportsNoWindowAndNoneIsStated(t *testing.T) {
	cases := map[string]string{
		"model has no window": `{"data":[{"id":"claude-a"}],"has_more":false}`,
		"model is not listed": `{"data":[{"id":"other","max_input_tokens":1000}],"has_more":false}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			fake := newFakeAnthropic(t, http.StatusOK, body)
			store := &mockProviderStore{createOut: fakeProviderRecord("p")}
			s := withFakeAnthropic(serverWithStore(t, store), fake)

			_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", 0)})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, grpcCode(err))
			assert.Contains(t, err.Error(), "default_model_context_window")
			assert.Contains(t, err.Error(), "claude-a")
			assert.Nil(t, store.capturedCreateInput, "nothing is saved")
		})
	}
}

func TestCreateProvider_RefusesWhenTheListFailsAndNoWindowIsStated(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusUnauthorized, `{"error":{"message":"invalid x-api-key"}}`)
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", 0)})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
	assert.Contains(t, err.Error(), "invalid x-api-key", "the provider's own text stays in the message")
	assert.Nil(t, store.capturedCreateInput)
}

func TestCreateProvider_FoundryNeedsTheWindowStated(t *testing.T) {
	foundry := newFoundryFake(t, http.StatusOK, `{}`)
	in := func(window int32) *tenantv1.CreateProviderRequest {
		i := foundryTestInput("my-deployment")
		i.DefaultModelContextWindow = window
		return &tenantv1.CreateProviderRequest{Input: i}
	}

	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := withFakeFoundry(serverWithStore(t, store), foundry)
	_, err := s.CreateProvider(tenantCtx("acme"), in(0))
	require.Error(t, err, "Foundry has no list call, so the caller must state the window")
	assert.Contains(t, err.Error(), "default_model_context_window")

	_, err = s.CreateProvider(tenantCtx("acme"), in(200000))
	require.NoError(t, err)
	assert.Equal(t, 200000, store.capturedCreateInput.DefaultModelContextWindow)
}

func TestCreateProvider_NoWindowIsNeededWithoutAChatModel(t *testing.T) {
	// No default model: nothing to measure. Embedding-only: no chat model.
	fake := newFakeAnthropic(t, http.StatusInternalServerError, `{}`)
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)

	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("", 0)})
	require.NoError(t, err)

	s2 := serverWithStore(t, &mockProviderStore{createOut: fakeProviderRecord("v")})
	_, err = s2.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: &tenantv1.ProviderConfigInput{
		Name: "v", Type: "voyage", DefaultModel: "voyage-3", DefaultEmbeddingModel: "voyage-3",
		Capabilities: []tenantv1.Capability{tenantv1.Capability_CAPABILITY_EMBEDDING},
		Credentials:  map[string]string{"api_key": "k"},
	}})
	require.NoError(t, err)
	assert.Zero(t, fake.listCalls.Load())
}

func TestUpdateProvider_StoresTheWindowToo(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK, `{"data":[{"id":"claude-a","max_input_tokens":123456}],"has_more":false}`)
	store := &mockProviderStore{updateOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)

	_, err := s.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{Name: "anthropic-prod", Input: anthropicSaveInput("claude-a", 0)})
	require.NoError(t, err)
	require.NotNil(t, store.capturedUpdateInput)
	assert.Equal(t, 123456, store.capturedUpdateInput.DefaultModelContextWindow)

	// A refusal on update saves nothing.
	store2 := &mockProviderStore{updateOut: fakeProviderRecord("p")}
	s2 := withFakeAnthropic(serverWithStore(t, store2), newFakeAnthropic(t, http.StatusOK, `{"data":[],"has_more":false}`))
	_, err = s2.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{Name: "anthropic-prod", Input: anthropicSaveInput("claude-a", 0)})
	require.Error(t, err)
	assert.Nil(t, store2.capturedUpdateInput)
}

func TestFromProtoInput_CarriesTheStatedWindow(t *testing.T) {
	in := fromProtoInput(&tenantv1.ProviderConfigInput{DefaultModelContextWindow: 654})
	assert.Equal(t, 654, in.DefaultModelContextWindow)
}

func TestProbeProvider_FoundryNeedsTheModelInTheRequest(t *testing.T) {
	ok := newFoundryFake(t, http.StatusOK,
		`{"id":"m","type":"message","role":"assistant","model":"x","content":[{"type":"text","text":"p"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`)
	s := withFakeFoundry(auditedServer(t), ok)
	creds := map[string]string{"api_key": "k", "foundry_resource": "r"}

	resp, err := s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{Type: "foundry", Credentials: creds})
	require.NoError(t, err)
	assert.False(t, resp.Ok)
	assert.Contains(t, resp.ErrorMessage, "Enter a model name")

	resp, err = s.ProbeProvider(tenantCtx("acme"), &tenantv1.ProbeProviderRequest{Type: "foundry", Credentials: creds, DefaultModel: "dep"})
	require.NoError(t, err)
	assert.True(t, resp.Ok, resp.ErrorMessage)
}

func TestSave_AStatedWindowMustBeInRange(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK, `{"data":[],"has_more":false}`)
	for name, window := range map[string]int32{"negative": -1, "above the bound": maxContextWindow + 1} {
		t.Run(name, func(t *testing.T) {
			store := &mockProviderStore{createOut: fakeProviderRecord("p")}
			s := withFakeAnthropic(serverWithStore(t, store), fake)
			_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", window)})
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, grpcCode(err))
			assert.Contains(t, err.Error(), "out of range")
			assert.Nil(t, store.capturedCreateInput)
		})
	}
	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", maxContextWindow)})
	require.NoError(t, err, "the bound itself is allowed")
}

func TestSave_AStatedWindowMustMatchWhatTheListReports(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK, `{"data":[{"id":"claude-a","max_input_tokens":200000},{"id":"claude-b"}],"has_more":false}`)

	store := &mockProviderStore{createOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)
	_, err := s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", 9000000)})
	require.Error(t, err, "a caller cannot state a bigger window than the provider reports")
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
	assert.Contains(t, err.Error(), "9000000")
	assert.Contains(t, err.Error(), "200000")
	assert.Nil(t, store.capturedCreateInput)

	_, err = s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", 200000)})
	require.NoError(t, err, "the same value passes")

	_, err = s.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-b", 64000)})
	require.NoError(t, err, "the list reports no window for the model, so the stated one is used")
	assert.Equal(t, 64000, store.capturedCreateInput.DefaultModelContextWindow)

	down := newFakeAnthropic(t, http.StatusInternalServerError, `{}`)
	s2 := withFakeAnthropic(serverWithStore(t, &mockProviderStore{createOut: fakeProviderRecord("p")}), down)
	_, err = s2.CreateProvider(tenantCtx("acme"), &tenantv1.CreateProviderRequest{Input: anthropicSaveInput("claude-a", 64000)})
	require.NoError(t, err, "a list outage cannot block a stated window")
}

func updateReq(model string, window int32) *tenantv1.UpdateProviderRequest {
	return &tenantv1.UpdateProviderRequest{Name: "anthropic-prod", Input: anthropicSaveInput(model, window)}
}

func storedProvider(model string, window int) *providerconfig.ProviderConfig {
	rec := fakeProviderRecord("anthropic-prod")
	rec.Type = llm.ProviderAnthropic
	rec.DefaultModel = model
	rec.DefaultModelContextWindow = window
	return rec
}

func TestUpdateProvider_KeepsTheStoredWindowAndMakesNoListCallWhenTheModelIsUnchanged(t *testing.T) {
	down := newFakeAnthropic(t, http.StatusInternalServerError, `{"error":{"message":"list is down"}}`)
	store := &mockProviderStore{getOut: storedProvider("claude-a", 200000), updateOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), down)

	// A rename, a key rotation or a default toggle: same model, no window stated.
	_, err := s.UpdateProvider(tenantCtx("acme"), &tenantv1.UpdateProviderRequest{
		Name: "anthropic-prod", Input: anthropicSaveInput("claude-a", 0)})
	require.NoError(t, err, "an edit that does not touch the model works during a list outage")
	assert.Equal(t, 200000, store.capturedUpdateInput.DefaultModelContextWindow, "the stored window is kept")
	assert.Zero(t, down.listCalls.Load(), "no list call")
}

func TestUpdateProvider_AModelChangeFillsTheWindowFromTheList(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK, `{"data":[{"id":"claude-b","max_input_tokens":1000000},{"id":"claude-c"}],"has_more":false}`)
	store := &mockProviderStore{getOut: storedProvider("claude-a", 200000), updateOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)

	_, err := s.UpdateProvider(tenantCtx("acme"), updateReq("claude-b", 0))
	require.NoError(t, err)
	assert.Equal(t, 1000000, store.capturedUpdateInput.DefaultModelContextWindow, "the new model gets the window of its list entry, not the old one")

	store.capturedUpdateInput = nil
	_, err = s.UpdateProvider(tenantCtx("acme"), updateReq("claude-c", 0))
	require.Error(t, err, "a new model with no reported window needs one stated")
	assert.Contains(t, err.Error(), "default_model_context_window")
	assert.Nil(t, store.capturedUpdateInput)
}

func TestUpdateProvider_AStatedWindowReplacesTheStoredOne(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK, `{"data":[{"id":"claude-a"}],"has_more":false}`)
	store := &mockProviderStore{getOut: storedProvider("claude-a", 200000), updateOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)

	_, err := s.UpdateProvider(tenantCtx("acme"), updateReq("claude-a", 64000))
	require.NoError(t, err)
	assert.Equal(t, 64000, store.capturedUpdateInput.DefaultModelContextWindow)
}

func TestUpdateProvider_ALegacyProviderIsFilledWhenTheListCanAndSavedWhenItCannot(t *testing.T) {
	fake := newFakeAnthropic(t, http.StatusOK, `{"data":[{"id":"claude-a","max_input_tokens":200000}],"has_more":false}`)
	store := &mockProviderStore{getOut: storedProvider("claude-a", 0), updateOut: fakeProviderRecord("p")}
	s := withFakeAnthropic(serverWithStore(t, store), fake)
	_, err := s.UpdateProvider(tenantCtx("acme"), updateReq("claude-a", 0))
	require.NoError(t, err)
	assert.Equal(t, 200000, store.capturedUpdateInput.DefaultModelContextWindow, "saving again stores the window")

	down := newFakeAnthropic(t, http.StatusInternalServerError, `{}`)
	store2 := &mockProviderStore{getOut: storedProvider("claude-a", 0), updateOut: fakeProviderRecord("p")}
	s2 := withFakeAnthropic(serverWithStore(t, store2), down)
	_, err = s2.UpdateProvider(tenantCtx("acme"), updateReq("claude-a", 0))
	require.NoError(t, err, "an edit that does not touch the model is never refused")
	assert.Zero(t, store2.capturedUpdateInput.DefaultModelContextWindow)
}

func TestUpdateProvider_UnknownNameIsNotFound(t *testing.T) {
	store := &mockProviderStore{getErr: providerconfig.ErrNotFound}
	s := serverWithStore(t, store)
	_, err := s.UpdateProvider(tenantCtx("acme"), updateReq("claude-a", 1000))
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, grpcCode(err))
}
