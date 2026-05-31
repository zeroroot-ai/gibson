package daemon

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/llm/modelgate"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// gateFakeProvider is a minimal llm.LLMProvider for gate tests.
type gateFakeProvider struct{ name string }

func (p *gateFakeProvider) Name() string                                    { return p.name }
func (p *gateFakeProvider) Models(context.Context) ([]llm.ModelInfo, error) { return nil, nil }
func (p *gateFakeProvider) Complete(context.Context, llm.CompletionRequest) (*llm.CompletionResponse, error) {
	return nil, nil
}
func (p *gateFakeProvider) CompleteWithTools(context.Context, llm.CompletionRequest, []llm.ToolDef) (*llm.CompletionResponse, error) {
	return nil, nil
}
func (p *gateFakeProvider) Stream(context.Context, llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	return nil, nil
}
func (p *gateFakeProvider) Health(context.Context) types.HealthStatus { return types.HealthStatus{} }

// gateFakeFilter is a modelgate.Filter whose decision is fixed per test.
type gateFakeFilter struct {
	permit bool
	err    error
}

func (f *gateFakeFilter) Permitted(_ context.Context, cands []modelgate.Candidate) ([]modelgate.Candidate, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.permit {
		return cands, nil
	}
	return nil, nil
}
func (f *gateFakeFilter) InvalidateCache() {}

func gateManager(filter modelgate.Filter) *DaemonSlotManager {
	m := NewDaemonSlotManager(llm.NewLLMRegistry(), slog.Default())
	m.WithModelFilter(filter)
	return m
}

func TestApplyModelGate(t *testing.T) {
	slot := agent.SlotDefinition{Name: "primary"}
	prov := &gateFakeProvider{name: "anthropic"}
	model := llm.ModelInfo{Name: "claude-sonnet-4-5"}

	t.Run("permitted resolves", func(t *testing.T) {
		err := gateManager(&gateFakeFilter{permit: true}).applyModelGate(context.Background(), slot, prov, model)
		if err != nil {
			t.Fatalf("permitted principal should resolve, got %v", err)
		}
	})

	t.Run("not permitted is denied", func(t *testing.T) {
		err := gateManager(&gateFakeFilter{permit: false}).applyModelGate(context.Background(), slot, prov, model)
		if err == nil || !strings.Contains(err.Error(), "model_access_denied") {
			t.Fatalf("unpermitted must be model_access_denied, got %v", err)
		}
	})

	t.Run("authorizer error fails closed", func(t *testing.T) {
		err := gateManager(&gateFakeFilter{err: errors.New("fga unavailable")}).applyModelGate(context.Background(), slot, prov, model)
		if err == nil || !strings.Contains(err.Error(), "model_access_denied") {
			t.Fatalf("FGA error must fail closed (denied), got %v", err)
		}
	})

	t.Run("no filter allows (gate not wired)", func(t *testing.T) {
		m := NewDaemonSlotManager(llm.NewLLMRegistry(), slog.Default())
		if err := m.applyModelGate(context.Background(), slot, prov, model); err != nil {
			t.Fatalf("no filter should allow, got %v", err)
		}
	})
}
