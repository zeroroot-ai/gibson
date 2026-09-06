// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// llm_adapter_test.go contains unit tests for LLMRegistryAdapter.
//
// Strategy:
//   - All external dependencies (LLMRegistry, SlotManager, LLMProvider) are
//     replaced with lightweight in-package mocks so no network or external
//     process is needed.
//   - Each test targets one public method: Complete, Stream, CompleteWithTools,
//     and CompleteStructured.
//   - Failure paths (no providers, provider not found, bad messages JSON) are
//     also exercised.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ---------------------------------------------------------------------------
// Test helpers / shared values
// ---------------------------------------------------------------------------

var adapterTestLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

// validMessagesJSON is a minimal valid messages payload the adapter can unmarshal.
func validMessagesJSON() string {
	msgs := []llm.Message{
		{Role: "user", Content: "hello"},
	}
	b, _ := json.Marshal(msgs)
	return string(b)
}

// ---------------------------------------------------------------------------
// mockLLMProvider implements llm.LLMProvider for unit tests.
// ---------------------------------------------------------------------------

type mockLLMProvider struct {
	name             string
	models           []llm.ModelInfo
	modelsErr        error
	completeResp     *llm.CompletionResponse
	completeErr      error
	streamChunks     []llm.StreamChunk
	streamErr        error
	toolCompleteResp *llm.CompletionResponse
	toolCompleteErr  error

	// calls counts every completion this provider actually served. A provider
	// standing in for one tenant's credential must never record a call made
	// on behalf of another tenant.
	calls int
}

func (m *mockLLMProvider) Name() string { return m.name }

func (m *mockLLMProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	if m.modelsErr != nil {
		return nil, m.modelsErr
	}
	return m.models, nil
}

func (m *mockLLMProvider) Complete(_ context.Context, _ llm.CompletionRequest) (*llm.CompletionResponse, error) {
	m.calls++
	return m.completeResp, m.completeErr
}

func (m *mockLLMProvider) CompleteWithTools(_ context.Context, _ llm.CompletionRequest, _ []llm.ToolDef) (*llm.CompletionResponse, error) {
	m.calls++
	return m.toolCompleteResp, m.toolCompleteErr
}

func (m *mockLLMProvider) Stream(_ context.Context, _ llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	m.calls++
	if m.streamErr != nil {
		return nil, m.streamErr
	}
	ch := make(chan llm.StreamChunk, len(m.streamChunks))
	for _, c := range m.streamChunks {
		ch <- c
	}
	close(ch)
	return ch, nil
}

func (m *mockLLMProvider) Health(_ context.Context) types.HealthStatus {
	return types.Healthy("mock healthy")
}

// ---------------------------------------------------------------------------
// mockStructuredProvider additionally implements llm.StructuredOutputProvider,
// standing in for the providers with native JSON-schema enforcement (OpenAI,
// Anthropic). It records the request so a test can assert the caller's schema
// actually reached the provider.
// ---------------------------------------------------------------------------

type mockStructuredProvider struct {
	mockLLMProvider
	structuredResp *llm.CompletionResponse
	structuredErr  error
	gotRequest     *llm.CompletionRequest
}

func (m *mockStructuredProvider) SupportsStructuredOutput(format types.ResponseFormatType) bool {
	return format == types.ResponseFormatJSONObject || format == types.ResponseFormatJSONSchema
}

func (m *mockStructuredProvider) CompleteStructured(_ context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	m.calls++
	reqCopy := req
	m.gotRequest = &reqCopy
	return m.structuredResp, m.structuredErr
}

// ---------------------------------------------------------------------------
// mockLLMRegistry implements llm.LLMRegistry backed by a map of providers.
// ---------------------------------------------------------------------------

type mockLLMRegistry struct {
	providers map[string]llm.LLMProvider
}

func newMockRegistry(providers ...llm.LLMProvider) *mockLLMRegistry {
	m := &mockLLMRegistry{providers: make(map[string]llm.LLMProvider)}
	for _, p := range providers {
		m.providers[p.Name()] = p
	}
	return m
}

func (r *mockLLMRegistry) RegisterProvider(p llm.LLMProvider) error {
	r.providers[p.Name()] = p
	return nil
}
func (r *mockLLMRegistry) UnregisterProvider(name string) error {
	delete(r.providers, name)
	return nil
}
func (r *mockLLMRegistry) GetProvider(name string) (llm.LLMProvider, error) {
	p, ok := r.providers[name]
	if !ok {
		return nil, errors.New("provider not found: " + name)
	}
	return p, nil
}
func (r *mockLLMRegistry) ListProviders() []string {
	names := make([]string, 0, len(r.providers))
	for n := range r.providers {
		names = append(names, n)
	}
	return names
}
func (r *mockLLMRegistry) GetEmbeddingProvider() (llm.EmbeddingProvider, error) {
	return nil, errors.New("no embedding provider")
}
func (r *mockLLMRegistry) Health(_ context.Context) types.HealthStatus {
	return types.Healthy("mock registry healthy")
}

// ---------------------------------------------------------------------------
// mockSlotManager implements llm.SlotManager over a registry.
//
// It deliberately HONOURS the SlotDefinition it is handed instead of
// discarding it: an explicit provider pin is looked up in the registry, and an
// unpinned slot falls to the configured default provider. A stub that ignored
// the slot definition could not tell correct provider selection from the
// "whatever is first" behaviour this file is here to pin down.
// ---------------------------------------------------------------------------

type mockSlotManager struct {
	registry        *mockLLMRegistry
	defaultProvider string
	resolveErr      error
}

func (m *mockSlotManager) ResolveSlot(ctx context.Context, slot agent.SlotDefinition, override *agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	if m.resolveErr != nil {
		return nil, llm.ModelInfo{}, m.resolveErr
	}

	name := slot.Default.Provider
	if override != nil && override.Provider != "" {
		name = override.Provider
	}
	if name == "" {
		name = m.defaultProvider
	}
	if name == "" {
		return nil, llm.ModelInfo{}, errors.New("no provider pinned and no default configured")
	}

	provider, err := m.registry.GetProvider(name)
	if err != nil {
		return nil, llm.ModelInfo{}, err
	}
	models, err := provider.Models(ctx)
	if err != nil {
		return nil, llm.ModelInfo{}, fmt.Errorf("listing models for %q: %w", name, err)
	}
	if len(models) == 0 {
		return nil, llm.ModelInfo{}, errors.New("provider has no models: " + name)
	}
	return provider, models[0], nil
}

func (m *mockSlotManager) ValidateSlot(_ context.Context, _ agent.SlotDefinition) error {
	return nil
}

// ---------------------------------------------------------------------------
// Tenant fixtures
// ---------------------------------------------------------------------------

// tenantSet is one tenant's own provider set: the registry built from that
// tenant's stored provider configuration and that tenant's credentials.
type tenantSet struct {
	registry *mockLLMRegistry
	slots    *mockSlotManager
}

func newTenantSet(defaultProvider string, providers ...llm.LLMProvider) *tenantSet {
	reg := newMockRegistry(providers...)
	return &tenantSet{
		registry: reg,
		slots:    &mockSlotManager{registry: reg, defaultProvider: defaultProvider},
	}
}

// tenantResolverFor builds a TenantLLMResolver over a fixed tenant → set map.
// An unknown tenant is an error, never a shared fallback.
func tenantResolverFor(sets map[string]*tenantSet) TenantLLMResolver {
	return func(_ context.Context, tenantID string) (llm.SlotManager, llm.LLMRegistry, error) {
		set, ok := sets[tenantID]
		if !ok {
			return nil, nil, errors.New("no provider set for tenant " + tenantID)
		}
		return set.slots, set.registry, nil
	}
}

// ---------------------------------------------------------------------------
// newTestAdapter wires a single mock provider as the sole provider of
// adapterTestTenant.
// ---------------------------------------------------------------------------

const adapterTestTenant = "tenant-under-test"

func newTestAdapter(provider *mockLLMProvider) *LLMRegistryAdapter {
	set := newTenantSet(provider.Name(), provider)
	return NewLLMRegistryAdapter(nil, nil, adapterTestLogger).
		WithTenantResolver(tenantResolverFor(map[string]*tenantSet{adapterTestTenant: set}))
}

// newTestAdapterForProvider wires any llm.LLMProvider (not just the base mock)
// as the sole provider of adapterTestTenant, under the given name.
func newTestAdapterForProvider(name string, provider llm.LLMProvider) *LLMRegistryAdapter {
	set := newTenantSet(name, provider)
	return NewLLMRegistryAdapter(nil, nil, adapterTestLogger).
		WithTenantResolver(tenantResolverFor(map[string]*tenantSet{adapterTestTenant: set}))
}

// newEmptyTenantAdapter wires a tenant whose provider set is empty.
func newEmptyTenantAdapter() *LLMRegistryAdapter {
	return NewLLMRegistryAdapter(nil, nil, adapterTestLogger).
		WithTenantResolver(tenantResolverFor(map[string]*tenantSet{adapterTestTenant: newTenantSet("")}))
}

// ---------------------------------------------------------------------------
// Complete tests
// ---------------------------------------------------------------------------

func TestComplete_ReturnsContentAndTokenCounts(t *testing.T) {
	provider := &mockLLMProvider{
		name:   "mock-provider",
		models: []llm.ModelInfo{{Name: "mock-model", ContextWindow: 8192}},
		completeResp: &llm.CompletionResponse{
			Model:        "mock-model",
			Message:      llm.Message{Role: "assistant", Content: "hello world"},
			FinishReason: llm.FinishReasonStop,
			Usage: llm.CompletionTokenUsage{
				PromptTokens:     10,
				CompletionTokens: 5,
			},
		},
	}

	adapter := newTestAdapter(provider)
	content, finishReason, modelUsed, promptToks, completionToks, err := adapter.Complete(
		context.Background(),
		adapterTestTenant, "mission-1", "mock-provider",
		validMessagesJSON(),
		1024, 0.5,
	)

	require.NoError(t, err)
	assert.Equal(t, "hello world", content)
	assert.Equal(t, "stop", finishReason)
	assert.Equal(t, "mock-model", modelUsed)
	assert.Equal(t, int32(10), promptToks)
	assert.Equal(t, int32(5), completionToks)
}

func TestComplete_NoProviders_ReturnsUnavailable(t *testing.T) {
	adapter := newEmptyTenantAdapter()

	_, _, _, _, _, err := adapter.Complete(
		context.Background(),
		adapterTestTenant, "m", "any-slot", validMessagesJSON(), 100, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, s.Code())
}

func TestComplete_InvalidMessagesJSON_ReturnsInvalidArgument(t *testing.T) {
	provider := &mockLLMProvider{
		name:   "p",
		models: []llm.ModelInfo{{Name: "m"}},
	}
	adapter := newTestAdapter(provider)

	_, _, _, _, _, err := adapter.Complete(
		context.Background(),
		adapterTestTenant, "m", "p", `not-valid-json`, 100, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, s.Code())
}

func TestComplete_ProviderError_ReturnsInternal(t *testing.T) {
	provider := &mockLLMProvider{
		name:        "p",
		models:      []llm.ModelInfo{{Name: "m"}},
		completeErr: errors.New("provider exploded"),
	}
	adapter := newTestAdapter(provider)

	_, _, _, _, _, err := adapter.Complete(
		context.Background(),
		adapterTestTenant, "m", "p", validMessagesJSON(), 100, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, s.Code())
}

// ---------------------------------------------------------------------------
// Stream tests
// ---------------------------------------------------------------------------

func TestStream_SendsAllChunks(t *testing.T) {
	provider := &mockLLMProvider{
		name:   "p",
		models: []llm.ModelInfo{{Name: "m"}},
		streamChunks: []llm.StreamChunk{
			{Delta: llm.StreamDelta{Content: "foo"}},
			{Delta: llm.StreamDelta{Content: "bar"}, FinishReason: llm.FinishReasonStop},
		},
	}
	adapter := newTestAdapter(provider)

	var collected []string
	err := adapter.Stream(
		context.Background(),
		adapterTestTenant, "m", "p", validMessagesJSON(), 100, 0.5,
		func(delta, _ string) error {
			collected = append(collected, delta)
			return nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, []string{"foo", "bar"}, collected)
}

func TestStream_NoProviders_ReturnsUnavailable(t *testing.T) {
	adapter := newEmptyTenantAdapter()

	err := adapter.Stream(
		context.Background(),
		adapterTestTenant, "m", "slot", validMessagesJSON(), 100, 0.5,
		func(_, _ string) error { return nil },
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, s.Code())
}

func TestStream_ProviderStreamError_ReturnsInternal(t *testing.T) {
	provider := &mockLLMProvider{
		name:      "p",
		models:    []llm.ModelInfo{{Name: "m"}},
		streamErr: errors.New("stream failed"),
	}
	adapter := newTestAdapter(provider)

	err := adapter.Stream(
		context.Background(),
		adapterTestTenant, "m", "p", validMessagesJSON(), 100, 0.5,
		func(_, _ string) error { return nil },
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, s.Code())
}

// ---------------------------------------------------------------------------
// CompleteWithTools tests
// ---------------------------------------------------------------------------

func TestCompleteWithTools_ReturnsContentAndToolCalls(t *testing.T) {
	toolCallsJSON := `[{"id":"c1","name":"nmap","arguments":"{}"}]`
	provider := &mockLLMProvider{
		name:   "p",
		models: []llm.ModelInfo{{Name: "m"}},
		toolCompleteResp: &llm.CompletionResponse{
			Model: "m",
			Message: llm.Message{
				Role:    "assistant",
				Content: "running nmap",
				ToolCalls: []llm.ToolCall{
					{ID: "c1", Name: "nmap", Arguments: "{}"},
				},
			},
			FinishReason: llm.FinishReasonToolCalls,
			Usage: llm.CompletionTokenUsage{
				PromptTokens: 20, CompletionTokens: 15,
			},
		},
	}
	adapter := newTestAdapter(provider)

	content, finishReason, modelUsed, prompt, completion, tcJSON, err := adapter.CompleteWithTools(
		context.Background(),
		adapterTestTenant, "m", "p", validMessagesJSON(), toolCallsJSON, 1024, 0.7,
	)

	require.NoError(t, err)
	assert.Equal(t, "running nmap", content)
	assert.Equal(t, "tool_calls", finishReason)
	assert.Equal(t, "m", modelUsed)
	assert.Equal(t, int32(20), prompt)
	assert.Equal(t, int32(15), completion)
	assert.NotEmpty(t, tcJSON, "tool calls JSON should be populated")
}

func TestCompleteWithTools_NoToolCalls_EmptyToolCallsJSON(t *testing.T) {
	provider := &mockLLMProvider{
		name:   "p",
		models: []llm.ModelInfo{{Name: "m"}},
		toolCompleteResp: &llm.CompletionResponse{
			Model:        "m",
			Message:      llm.Message{Role: "assistant", Content: "no tools needed"},
			FinishReason: llm.FinishReasonStop,
		},
	}
	adapter := newTestAdapter(provider)

	_, _, _, _, _, tcJSON, err := adapter.CompleteWithTools(
		context.Background(),
		adapterTestTenant, "m", "p", validMessagesJSON(), "", 512, 0.5,
	)

	require.NoError(t, err)
	assert.Empty(t, tcJSON)
}

func TestCompleteWithTools_NoProviders_ReturnsUnavailable(t *testing.T) {
	adapter := newEmptyTenantAdapter()

	_, _, _, _, _, _, err := adapter.CompleteWithTools(
		context.Background(),
		adapterTestTenant, "m", "slot", validMessagesJSON(), "", 100, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, s.Code())
}

// ---------------------------------------------------------------------------
// CompleteStructured tests
// ---------------------------------------------------------------------------

func TestCompleteStructured_ReturnsJSONResult(t *testing.T) {
	provider := &mockStructuredProvider{
		mockLLMProvider: mockLLMProvider{
			name:   "p",
			models: []llm.ModelInfo{{Name: "m"}},
		},
		structuredResp: &llm.CompletionResponse{
			Model:        "m",
			Message:      llm.Message{Role: "assistant", Content: `{"key":"value"}`},
			FinishReason: llm.FinishReasonStop,
			Usage: llm.CompletionTokenUsage{
				PromptTokens: 8, CompletionTokens: 6,
			},
		},
	}
	adapter := newTestAdapterForProvider("p", provider)

	resultJSON, prompt, completion, err := adapter.CompleteStructured(
		context.Background(),
		adapterTestTenant, "m", "p", validMessagesJSON(), `{"type":"object"}`, 512, 0.3,
	)

	require.NoError(t, err)
	assert.Equal(t, `{"key":"value"}`, resultJSON)
	assert.Equal(t, int32(8), prompt)
	assert.Equal(t, int32(6), completion)
}

func TestCompleteStructured_NoProviders_ReturnsUnavailable(t *testing.T) {
	adapter := newEmptyTenantAdapter()

	_, _, _, err := adapter.CompleteStructured(
		context.Background(),
		adapterTestTenant, "m", "slot", validMessagesJSON(), "{}", 100, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, s.Code())
}

// ---------------------------------------------------------------------------
// NewLLMRegistryAdapter constructor tests
// ---------------------------------------------------------------------------

func TestNewLLMRegistryAdapter_NilLogger_UsesDefault(t *testing.T) {
	assert.NotPanics(t, func() {
		a := NewLLMRegistryAdapter(nil, nil, nil)
		assert.NotNil(t, a)
	})
}

// ---------------------------------------------------------------------------
// Tenant scoping
//
// Component prompts must travel on the calling tenant's own credential. These
// tests treat each mock provider as one tenant's credential and assert on
// which provider actually served the call.
// ---------------------------------------------------------------------------

func newTenantProvider(name, reply string) *mockStructuredProvider {
	return &mockStructuredProvider{
		mockLLMProvider: mockLLMProvider{
			name:   name,
			models: []llm.ModelInfo{{Name: name + "-model", ContextWindow: 8192}},
			completeResp: &llm.CompletionResponse{
				Model:        name + "-model",
				Message:      llm.Message{Role: "assistant", Content: reply},
				FinishReason: llm.FinishReasonStop,
			},
			toolCompleteResp: &llm.CompletionResponse{
				Model:        name + "-model",
				Message:      llm.Message{Role: "assistant", Content: reply},
				FinishReason: llm.FinishReasonStop,
			},
			streamChunks: []llm.StreamChunk{
				{Delta: llm.StreamDelta{Content: reply}, FinishReason: llm.FinishReasonStop},
			},
		},
		structuredResp: &llm.CompletionResponse{
			Model:        name + "-model",
			Message:      llm.Message{Role: "assistant", Content: reply},
			FinishReason: llm.FinishReasonStop,
		},
	}
}

// twoTenantAdapter wires tenant "tenant-a" and tenant "tenant-b", each with a
// provider set of its own, plus a third provider standing in for the daemon's
// process-global startup registry (the operator's credential) that belongs to
// no tenant at all.
func twoTenantAdapter() (adapter *LLMRegistryAdapter, a, b, operator *mockStructuredProvider) {
	a = newTenantProvider("provider-a", "answer from tenant a")
	b = newTenantProvider("provider-b", "answer from tenant b")
	operator = newTenantProvider("operator-shared", "answer on the operator credential")

	sets := map[string]*tenantSet{
		"tenant-a": newTenantSet("provider-a", a),
		"tenant-b": newTenantSet("provider-b", b),
	}

	adapter = NewLLMRegistryAdapter(newMockRegistry(operator), &mockSlotManager{
		registry:        newMockRegistry(operator),
		defaultProvider: "operator-shared",
	}, adapterTestLogger).WithTenantResolver(tenantResolverFor(sets))
	return adapter, a, b, operator
}

func TestComplete_UsesTheCallingTenantsProvider(t *testing.T) {
	adapter, a, b, operator := twoTenantAdapter()

	content, _, model, _, _, err := adapter.Complete(
		context.Background(),
		"tenant-a", "mission-1", "primary", validMessagesJSON(), 512, 0.5,
	)

	require.NoError(t, err)
	assert.Equal(t, "answer from tenant a", content)
	assert.Equal(t, "provider-a-model", model)
	assert.Equal(t, 1, a.calls, "tenant a's own provider must serve tenant a")
	assert.Zero(t, b.calls, "another tenant's provider must never be reached")
	assert.Zero(t, operator.calls, "the operator's shared credential must never serve tenant traffic")
}

func TestComplete_SecondTenantGetsItsOwnProvider(t *testing.T) {
	adapter, a, b, operator := twoTenantAdapter()

	content, _, _, _, _, err := adapter.Complete(
		context.Background(),
		"tenant-b", "mission-1", "primary", validMessagesJSON(), 512, 0.5,
	)

	require.NoError(t, err)
	assert.Equal(t, "answer from tenant b", content)
	assert.Equal(t, 1, b.calls)
	assert.Zero(t, a.calls)
	assert.Zero(t, operator.calls)
}

func TestComplete_UnknownTenant_IsRefusedNotServedByTheOperator(t *testing.T) {
	adapter, a, b, operator := twoTenantAdapter()

	_, _, _, _, _, err := adapter.Complete(
		context.Background(),
		"tenant-with-no-providers", "mission-1", "primary", validMessagesJSON(), 512, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, s.Code())
	assert.Zero(t, operator.calls, "an unresolvable tenant must not fall back to a shared credential")
	assert.Zero(t, a.calls)
	assert.Zero(t, b.calls)
}

func TestComplete_EmptyTenant_IsRefused(t *testing.T) {
	adapter, _, _, operator := twoTenantAdapter()

	_, _, _, _, _, err := adapter.Complete(
		context.Background(),
		"", "mission-1", "primary", validMessagesJSON(), 512, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, s.Code())
	assert.Zero(t, operator.calls)
}

// TestAdapter_NoTenantResolver_FailsClosed is the load-bearing regression
// guard: an adapter built from the daemon's process-global startup registry
// but with no per-tenant resolver installed must serve NOTHING. Serving that
// registry would put every tenant's prompts on the operator's credential.
func TestAdapter_NoTenantResolver_FailsClosed(t *testing.T) {
	operator := newTenantProvider("operator-shared", "answer on the operator credential")
	globalRegistry := newMockRegistry(operator)
	globalSlots := &mockSlotManager{registry: globalRegistry, defaultProvider: "operator-shared"}

	adapter := NewLLMRegistryAdapter(globalRegistry, globalSlots, adapterTestLogger)

	t.Run("Complete", func(t *testing.T) {
		_, _, _, _, _, err := adapter.Complete(
			context.Background(),
			"tenant-a", "mission-1", "primary", validMessagesJSON(), 512, 0.5,
		)
		require.Error(t, err)
		s, _ := status.FromError(err)
		assert.Equal(t, codes.FailedPrecondition, s.Code())
	})

	t.Run("Stream", func(t *testing.T) {
		err := adapter.Stream(
			context.Background(),
			"tenant-a", "mission-1", "primary", validMessagesJSON(), 512, 0.5,
			func(_, _ string) error { return nil },
		)
		require.Error(t, err)
		s, _ := status.FromError(err)
		assert.Equal(t, codes.FailedPrecondition, s.Code())
	})

	t.Run("CompleteWithTools", func(t *testing.T) {
		_, _, _, _, _, _, err := adapter.CompleteWithTools(
			context.Background(),
			"tenant-a", "mission-1", "primary", validMessagesJSON(), "", 512, 0.5,
		)
		require.Error(t, err)
		s, _ := status.FromError(err)
		assert.Equal(t, codes.FailedPrecondition, s.Code())
	})

	t.Run("CompleteStructured", func(t *testing.T) {
		_, _, _, err := adapter.CompleteStructured(
			context.Background(),
			"tenant-a", "mission-1", "primary", validMessagesJSON(), "{}", 512, 0.5,
		)
		require.Error(t, err)
		s, _ := status.FromError(err)
		assert.Equal(t, codes.FailedPrecondition, s.Code())
	})

	assert.Zero(t, operator.calls, "the process-global registry must never serve a component completion")
}

func TestStream_UsesTheCallingTenantsProvider(t *testing.T) {
	adapter, a, b, operator := twoTenantAdapter()

	var collected []string
	err := adapter.Stream(
		context.Background(),
		"tenant-a", "mission-1", "primary", validMessagesJSON(), 512, 0.5,
		func(delta, _ string) error {
			collected = append(collected, delta)
			return nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, []string{"answer from tenant a"}, collected)
	assert.Equal(t, 1, a.calls)
	assert.Zero(t, b.calls)
	assert.Zero(t, operator.calls)
}

func TestCompleteWithTools_UsesTheCallingTenantsProvider(t *testing.T) {
	adapter, a, b, operator := twoTenantAdapter()

	content, _, _, _, _, _, err := adapter.CompleteWithTools(
		context.Background(),
		"tenant-b", "mission-1", "primary", validMessagesJSON(), "", 512, 0.5,
	)

	require.NoError(t, err)
	assert.Equal(t, "answer from tenant b", content)
	assert.Equal(t, 1, b.calls)
	assert.Zero(t, a.calls)
	assert.Zero(t, operator.calls)
}

func TestCompleteStructured_UsesTheCallingTenantsProvider(t *testing.T) {
	adapter, a, b, operator := twoTenantAdapter()

	result, _, _, err := adapter.CompleteStructured(
		context.Background(),
		"tenant-b", "mission-1", "primary", validMessagesJSON(), "{}", 512, 0.5,
	)

	require.NoError(t, err)
	assert.Equal(t, "answer from tenant b", result)
	assert.Equal(t, 1, b.calls)
	assert.Zero(t, a.calls)
	assert.Zero(t, operator.calls)
}

// TestComplete_UnpinnedSlot_UsesTheTenantsDefaultNotAnArbitraryProvider pins
// provider selection: a slot name that is not a provider name resolves through
// the tenant's configured default, not through whichever provider happens to
// come first out of the registry map.
func TestComplete_UnpinnedSlot_UsesTheTenantsDefaultNotAnArbitraryProvider(t *testing.T) {
	preferred := newTenantProvider("preferred", "from the tenant default")
	other := newTenantProvider("other", "from some other provider")

	sets := map[string]*tenantSet{
		"tenant-a": newTenantSet("preferred", preferred, other),
	}
	adapter := NewLLMRegistryAdapter(nil, nil, adapterTestLogger).
		WithTenantResolver(tenantResolverFor(sets))

	// Run repeatedly: Go randomises map iteration, so a "first provider in the
	// map" selection would be flaky rather than consistently wrong.
	for range 20 {
		preferred.calls = 0
		other.calls = 0

		content, _, _, _, _, err := adapter.Complete(
			context.Background(),
			"tenant-a", "mission-1", "reasoning", validMessagesJSON(), 512, 0.5,
		)

		require.NoError(t, err)
		assert.Equal(t, "from the tenant default", content)
		assert.Equal(t, 1, preferred.calls)
		assert.Zero(t, other.calls)
	}
}

// TestComplete_SlotNamingAProvider_PinsThatProvider covers the other selection
// branch: when the slot name IS one of the tenant's providers it is pinned.
func TestComplete_SlotNamingAProvider_PinsThatProvider(t *testing.T) {
	preferred := newTenantProvider("preferred", "from the tenant default")
	other := newTenantProvider("other", "from some other provider")

	sets := map[string]*tenantSet{
		"tenant-a": newTenantSet("preferred", preferred, other),
	}
	adapter := NewLLMRegistryAdapter(nil, nil, adapterTestLogger).
		WithTenantResolver(tenantResolverFor(sets))

	content, _, _, _, _, err := adapter.Complete(
		context.Background(),
		"tenant-a", "mission-1", "other", validMessagesJSON(), 512, 0.5,
	)

	require.NoError(t, err)
	assert.Equal(t, "from some other provider", content)
	assert.Equal(t, 1, other.calls)
	assert.Zero(t, preferred.calls)
}

// TestComplete_SlotResolutionFailure_IsNotPaperedOver ensures a slot-manager
// failure surfaces instead of quietly falling through to a provider the slot
// manager rejected.
func TestComplete_SlotResolutionFailure_IsNotPaperedOver(t *testing.T) {
	provider := newTenantProvider("provider-a", "should not be reached")
	set := newTenantSet("provider-a", provider)
	set.slots.resolveErr = errors.New("model not permitted for this principal")

	adapter := NewLLMRegistryAdapter(nil, nil, adapterTestLogger).
		WithTenantResolver(tenantResolverFor(map[string]*tenantSet{"tenant-a": set}))

	_, _, _, _, _, err := adapter.Complete(
		context.Background(),
		"tenant-a", "mission-1", "primary", validMessagesJSON(), 512, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, s.Code())
	assert.Zero(t, provider.calls, "a rejected slot must not fall through to the provider anyway")
}

// A component completion carries no client max-tokens field; the ceiling is
// server-side and a slot that omits it resolves to 0. Zero must mean "use the
// default", never "generate nothing" — a 0 ceiling made the provider return an
// empty completion (completion_tokens=0), which the calling agent SDK choked
// on. Found live on kind-vanilla.
func TestEffectiveMaxTokens_ZeroBecomesDefault(t *testing.T) {
	if got := effectiveMaxTokens(0); got != defaultComponentMaxTokens {
		t.Errorf("effectiveMaxTokens(0) = %d, want %d", got, defaultComponentMaxTokens)
	}
	if got := effectiveMaxTokens(-5); got != defaultComponentMaxTokens {
		t.Errorf("effectiveMaxTokens(-5) = %d, want the default", got)
	}
	if got := effectiveMaxTokens(256); got != 256 {
		t.Errorf("effectiveMaxTokens(256) = %d, want 256 preserved", got)
	}
}
