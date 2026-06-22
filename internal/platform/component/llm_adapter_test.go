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
}

func (m *mockLLMProvider) Name() string { return m.name }

func (m *mockLLMProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	if m.modelsErr != nil {
		return nil, m.modelsErr
	}
	return m.models, nil
}

func (m *mockLLMProvider) Complete(_ context.Context, _ llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return m.completeResp, m.completeErr
}

func (m *mockLLMProvider) CompleteWithTools(_ context.Context, _ llm.CompletionRequest, _ []llm.ToolDef) (*llm.CompletionResponse, error) {
	return m.toolCompleteResp, m.toolCompleteErr
}

func (m *mockLLMProvider) Stream(_ context.Context, _ llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
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
// mockSlotManager implements llm.SlotManager — always delegates to the
// registry directly so resolveProvider's fallback path is exercised.
// ---------------------------------------------------------------------------

type mockSlotManager struct {
	provider   llm.LLMProvider
	model      llm.ModelInfo
	resolveErr error
}

func (m *mockSlotManager) ResolveSlot(_ context.Context, _ agent.SlotDefinition, _ *agent.SlotConfig) (llm.LLMProvider, llm.ModelInfo, error) {
	if m.resolveErr != nil {
		return nil, llm.ModelInfo{}, m.resolveErr
	}
	return m.provider, m.model, nil
}
func (m *mockSlotManager) ValidateSlot(_ context.Context, _ agent.SlotDefinition) error {
	return nil
}

// ---------------------------------------------------------------------------
// newTestAdapter is a convenience constructor wiring a single mock provider.
// ---------------------------------------------------------------------------

func newTestAdapter(provider *mockLLMProvider) *LLMRegistryAdapter {
	reg := newMockRegistry(provider)
	slots := &mockSlotManager{
		provider: provider,
		model:    provider.models[0],
	}
	return NewLLMRegistryAdapter(reg, slots, adapterTestLogger)
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
		"tenant-1", "mission-1", "mock-provider",
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
	reg := newMockRegistry() // empty registry
	slots := &mockSlotManager{}
	adapter := NewLLMRegistryAdapter(reg, slots, adapterTestLogger)

	_, _, _, _, _, err := adapter.Complete(
		context.Background(),
		"t", "m", "any-slot", validMessagesJSON(), 100, 0.5,
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
		"t", "m", "p", `not-valid-json`, 100, 0.5,
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
		"t", "m", "p", validMessagesJSON(), 100, 0.5,
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
		"t", "m", "p", validMessagesJSON(), 100, 0.5,
		func(delta, _ string) error {
			collected = append(collected, delta)
			return nil
		},
	)

	require.NoError(t, err)
	assert.Equal(t, []string{"foo", "bar"}, collected)
}

func TestStream_NoProviders_ReturnsUnavailable(t *testing.T) {
	reg := newMockRegistry()
	slots := &mockSlotManager{}
	adapter := NewLLMRegistryAdapter(reg, slots, adapterTestLogger)

	err := adapter.Stream(
		context.Background(),
		"t", "m", "slot", validMessagesJSON(), 100, 0.5,
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
		"t", "m", "p", validMessagesJSON(), 100, 0.5,
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
		"t", "m", "p", validMessagesJSON(), toolCallsJSON, 1024, 0.7,
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
		"t", "m", "p", validMessagesJSON(), "", 512, 0.5,
	)

	require.NoError(t, err)
	assert.Empty(t, tcJSON)
}

func TestCompleteWithTools_NoProviders_ReturnsUnavailable(t *testing.T) {
	reg := newMockRegistry()
	slots := &mockSlotManager{}
	adapter := NewLLMRegistryAdapter(reg, slots, adapterTestLogger)

	_, _, _, _, _, _, err := adapter.CompleteWithTools(
		context.Background(),
		"t", "m", "slot", validMessagesJSON(), "", 100, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, s.Code())
}

// ---------------------------------------------------------------------------
// CompleteStructured tests
// ---------------------------------------------------------------------------

func TestCompleteStructured_ReturnsJSONResult(t *testing.T) {
	provider := &mockLLMProvider{
		name:   "p",
		models: []llm.ModelInfo{{Name: "m"}},
		completeResp: &llm.CompletionResponse{
			Model:        "m",
			Message:      llm.Message{Role: "assistant", Content: `{"key":"value"}`},
			FinishReason: llm.FinishReasonStop,
			Usage: llm.CompletionTokenUsage{
				PromptTokens: 8, CompletionTokens: 6,
			},
		},
	}
	adapter := newTestAdapter(provider)

	resultJSON, prompt, completion, err := adapter.CompleteStructured(
		context.Background(),
		"t", "m", "p", validMessagesJSON(), `{"type":"object"}`, 512, 0.3,
	)

	require.NoError(t, err)
	assert.Equal(t, `{"key":"value"}`, resultJSON)
	assert.Equal(t, int32(8), prompt)
	assert.Equal(t, int32(6), completion)
}

func TestCompleteStructured_NoProviders_ReturnsUnavailable(t *testing.T) {
	reg := newMockRegistry()
	slots := &mockSlotManager{}
	adapter := NewLLMRegistryAdapter(reg, slots, adapterTestLogger)

	_, _, _, err := adapter.CompleteStructured(
		context.Background(),
		"t", "m", "slot", validMessagesJSON(), "{}", 100, 0.5,
	)

	require.Error(t, err)
	s, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, s.Code())
}

// ---------------------------------------------------------------------------
// NewLLMRegistryAdapter constructor tests
// ---------------------------------------------------------------------------

func TestNewLLMRegistryAdapter_NilRegistry_Panics(t *testing.T) {
	slots := &mockSlotManager{}
	assert.Panics(t, func() {
		NewLLMRegistryAdapter(nil, slots, adapterTestLogger)
	})
}

func TestNewLLMRegistryAdapter_NilSlots_Panics(t *testing.T) {
	reg := newMockRegistry()
	assert.Panics(t, func() {
		NewLLMRegistryAdapter(reg, nil, adapterTestLogger)
	})
}

func TestNewLLMRegistryAdapter_NilLogger_UsesDefault(t *testing.T) {
	reg := newMockRegistry()
	slots := &mockSlotManager{}
	assert.NotPanics(t, func() {
		a := NewLLMRegistryAdapter(reg, slots, nil)
		assert.NotNil(t, a)
	})
}
