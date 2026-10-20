// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/llm/modelgate"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
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
		if errors.Is(err, modelgate.ErrUnavailable) {
			t.Fatalf("an unclassified error is not an outage, got %v", err)
		}
	})

	t.Run("an outage marks the gate as unable to decide", func(t *testing.T) {
		for name, cause := range map[string]error{
			"fga unavailable":   authz.ErrFgaUnavailable,
			"fga timeout":       authz.ErrFgaTimeout,
			"context canceled":  context.Canceled,
			"deadline exceeded": context.DeadlineExceeded,
		} {
			err := gateManager(&gateFakeFilter{err: fmt.Errorf("modelgate: authorization check failed: %w", cause)}).
				applyModelGate(context.Background(), slot, prov, model)
			if !errors.Is(err, modelgate.ErrUnavailable) {
				t.Errorf("%s: want ErrUnavailable, got %v", name, err)
			}
		}
	})

	t.Run("a permanent authorizer error is not marked retryable", func(t *testing.T) {
		for name, cause := range map[string]error{
			"no authorizer":   errors.New("modelgate: no authorizer is configured, so no model can be permitted"),
			"invalid":         fmt.Errorf("modelgate: authorization check failed: %w", authz.ErrInvalidArgument),
			"short answer":    errors.New("modelgate: authorizer answered 1 of 2 checks"),
			"model not found": authz.ErrModelNotFound,
		} {
			err := gateManager(&gateFakeFilter{err: cause}).applyModelGate(context.Background(), slot, prov, model)
			if err == nil || !strings.Contains(err.Error(), "model_access_denied") {
				t.Errorf("%s: must still deny, got %v", name, err)
			}
			if errors.Is(err, modelgate.ErrUnavailable) {
				t.Errorf("%s: a permanent error must not carry ErrUnavailable", name)
			}
		}
	})

	t.Run("a pinned decider stops on a permanent error and retries an outage", func(t *testing.T) {
		pin := brain.DeciderSlot{Provider: "anthropic"}
		ctx := context.Background()
		permanent := gateManager(&gateFakeFilter{err: authz.ErrInvalidArgument}).applyModelGate(ctx, slot, prov, model)
		if !pinnedDeciderUnservable(pin, permanent) {
			t.Error("a permanent gate error must end a pinned mission")
		}
		outage := gateManager(&gateFakeFilter{err: authz.ErrFgaUnavailable}).applyModelGate(ctx, slot, prov, model)
		if pinnedDeciderUnservable(pin, outage) {
			t.Error("an outage must keep the retry")
		}
	})

	t.Run("no filter allows (gate not wired)", func(t *testing.T) {
		m := NewDaemonSlotManager(llm.NewLLMRegistry(), slog.Default())
		if err := m.applyModelGate(context.Background(), slot, prov, model); err != nil {
			t.Fatalf("no filter should allow, got %v", err)
		}
	})
}
