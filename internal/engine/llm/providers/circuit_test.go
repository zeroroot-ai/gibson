package providers

import (
	"context"
	"errors"
	"testing"

	"github.com/sony/gobreaker"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// alwaysErrProvider is a minimal LLMProvider that returns a configurable error
// from Complete and a configurable response on success (when err is nil).
type alwaysErrProvider struct {
	name string
	err  error
	resp *llm.CompletionResponse
}

func (p *alwaysErrProvider) Name() string { return p.name }

func (p *alwaysErrProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	return nil, nil
}

func (p *alwaysErrProvider) Complete(_ context.Context, _ llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.resp, nil
}

func (p *alwaysErrProvider) CompleteWithTools(_ context.Context, _ llm.CompletionRequest, _ []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(context.Background(), llm.CompletionRequest{})
}

func (p *alwaysErrProvider) Stream(_ context.Context, _ llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	ch := make(chan llm.StreamChunk)
	close(ch)
	return ch, nil
}

func (p *alwaysErrProvider) Health(_ context.Context) types.HealthStatus {
	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

// TestCircuitLLMProvider_OpensAfter10Failures verifies that after 10 consecutive
// failures the circuit trips to the open state and subsequent calls return
// gobreaker.ErrOpenState immediately without delegating to the inner provider.
func TestCircuitLLMProvider_OpensAfter10Failures(t *testing.T) {
	t.Parallel()

	providerErr := errors.New("provider unavailable")
	inner := &alwaysErrProvider{name: "test-failing", err: providerErr}
	wrapped := newCircuitLLMProvider(inner, "test-failing")

	ctx := context.Background()
	req := llm.CompletionRequest{Model: "test-model"}

	// Drive exactly 10 consecutive failures to trip the circuit.
	for i := 0; i < 10; i++ {
		_, err := wrapped.Complete(ctx, req)
		if err == nil {
			t.Fatalf("call %d: expected error, got nil", i+1)
		}
		if errors.Is(err, gobreaker.ErrOpenState) {
			t.Fatalf("call %d: circuit opened too early (after %d failures, expected 10)", i+1, i+1)
		}
	}

	// The 11th call must be rejected by the open circuit immediately.
	_, err := wrapped.Complete(ctx, req)
	if !errors.Is(err, gobreaker.ErrOpenState) {
		t.Fatalf("11th call: expected gobreaker.ErrOpenState, got %v", err)
	}
}

// TestCircuitLLMProvider_PassthroughOnSuccess verifies that a healthy provider
// passes completions through without interference from the circuit breaker.
func TestCircuitLLMProvider_PassthroughOnSuccess(t *testing.T) {
	t.Parallel()

	want := &llm.CompletionResponse{
		ID:    "test-id",
		Model: "test-model",
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: "hello",
		},
		FinishReason: llm.FinishReasonStop,
	}

	inner := &alwaysErrProvider{name: "test-ok", resp: want}
	wrapped := newCircuitLLMProvider(inner, "test-ok")

	ctx := context.Background()
	req := llm.CompletionRequest{Model: "test-model"}

	got, err := wrapped.Complete(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil response")
	}
	if got.ID != want.ID {
		t.Errorf("response ID: got %q, want %q", got.ID, want.ID)
	}
	if got.Message.Content != want.Message.Content {
		t.Errorf("content: got %q, want %q", got.Message.Content, want.Message.Content)
	}
}
