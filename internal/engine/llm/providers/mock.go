package providers

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MockCall represents a recorded call to the mock provider
type MockCall struct {
	Request llm.CompletionRequest
}

// MockProvider implements LLMProvider for testing
type MockProvider struct {
	mu               sync.RWMutex
	responses        []string
	responseIndex    int
	calls            []MockCall
	streamingEnabled bool
}

// NewMockProvider creates a new mock provider
func NewMockProvider(responses []string) *MockProvider {
	return &MockProvider{
		responses:        responses,
		responseIndex:    0,
		calls:            make([]MockCall, 0),
		streamingEnabled: true,
	}
}

// Name returns the provider name
func (p *MockProvider) Name() string {
	return "mock"
}

// Models returns mock model information
func (p *MockProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	return []llm.ModelInfo{
		{
			Name:          "mock-model",
			ContextWindow: 200000,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tool_use"},
		},
	}, nil
}

// Complete generates a completion
func (p *MockProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	p.mu.Lock()
	p.calls = append(p.calls, MockCall{Request: req})

	if len(p.responses) == 0 {
		p.mu.Unlock()
		return nil, llm.NewProviderError("mock", fmt.Errorf("no responses configured"))
	}

	response := p.responses[p.responseIndex%len(p.responses)]
	p.responseIndex++
	p.mu.Unlock()

	return &llm.CompletionResponse{
		ID:    uuid.New().String(),
		Model: req.Model,
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: response,
		},
		FinishReason: llm.FinishReasonStop,
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     10,
			CompletionTokens: len(response) / 4,
			TotalTokens:      10 + len(response)/4,
		},
	}, nil
}

// CompleteWithTools generates a completion with tools
func (p *MockProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req)
}

// Stream generates a streaming completion
func (p *MockProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	p.mu.RLock()
	if !p.streamingEnabled {
		p.mu.RUnlock()
		return nil, llm.NewProviderError("mock", fmt.Errorf("streaming not supported"))
	}

	p.calls = append(p.calls, MockCall{Request: req})

	if len(p.responses) == 0 {
		p.mu.RUnlock()
		return nil, llm.NewProviderError("mock", fmt.Errorf("no responses configured"))
	}

	response := p.responses[p.responseIndex%len(p.responses)]
	p.responseIndex++
	p.mu.RUnlock()

	chunkChan := make(chan llm.StreamChunk, 10)

	go func() {
		defer close(chunkChan)

		// Stream in chunks
		chunkSize := 5
		for i := 0; i < len(response); i += chunkSize {
			end := i + chunkSize
			if end > len(response) {
				end = len(response)
			}

			select {
			case <-ctx.Done():
				return
			case chunkChan <- llm.StreamChunk{
				Delta: llm.StreamDelta{
					Content: response[i:end],
				},
			}:
			}
		}

		// Send final chunk carrying model + aggregated usage so streaming
		// completions surface token metadata to the harness World capture path
		// (gibson#1085), mirroring the unary Complete usage above.
		select {
		case <-ctx.Done():
		case chunkChan <- llm.StreamChunk{
			FinishReason: llm.FinishReasonStop,
			Model:        req.Model,
			Usage: &llm.CompletionTokenUsage{
				PromptTokens:     10,
				CompletionTokens: len(response) / 4,
				TotalTokens:      10 + len(response)/4,
			},
		}:
		}
	}()

	return chunkChan, nil
}

// Health checks the provider health
func (p *MockProvider) Health(ctx context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

// GetCalls returns all recorded calls (thread-safe)
func (p *MockProvider) GetCalls() []MockCall {
	p.mu.RLock()
	defer p.mu.RUnlock()

	calls := make([]MockCall, len(p.calls))
	copy(calls, p.calls)
	return calls
}

// Reset resets the mock provider state
func (p *MockProvider) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.calls = make([]MockCall, 0)
	p.responseIndex = 0
}

// SetResponses replaces all responses
func (p *MockProvider) SetResponses(responses []string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.responses = responses
	p.responseIndex = 0
}
