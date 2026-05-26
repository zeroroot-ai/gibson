//go:build test_fixtures

// Package mockllm implements a deterministic LLM provider for e2e testing.
//
// PRODUCTION SAFETY CONTRACT:
//   - This file is ONLY compiled when the binary is built with -tags=test_fixtures.
//   - Production `make bin` never uses that tag: the mock is absent from the production binary.
//   - Even if accidentally included, Register() is a hard no-op when
//     GIBSON_TEST_FIXTURES_ENABLED != "true".
//   - CI lint (cmd/fixtures-lint) asserts that GIBSON_TEST_FIXTURES_ENABLED is
//     NEVER set in any production overlay's values.yaml or ConfigMap.
//
// Requirements: R3.1, R3.2, R3.3, NFR Security.
package mockllm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// DeterministicResponse is the canonical canned response the probe agent
// asserts against.  Changing this value is a breaking change; update
// tests/e2e/fixtures/agents/probe/main.go in the same commit.
const DeterministicResponse = "MOCK_LLM_DETERMINISTIC_RESPONSE_v1"

// ProviderName is the registry key used when the mock is registered.
// This must match MockProviderName in tests/e2e/helpers/mock_llm_client.go.
const ProviderName = "mock-llm-e2e-test"

// errorMode values for InjectErrorMode / ResetMockProvider.
const (
	errorModeNone  = "none"
	errorModeError = "error" // R4.3 — returns a provider error on every Complete
	errorModeSlow  = "slow"  // R4.4 — deliberate hang; the caller's context deadline fires
)

// Register adds the e2e mock provider to the daemon LLM registry.
// It is a no-op when GIBSON_TEST_FIXTURES_ENABLED != "true" (defense in depth).
// Logs at INFO on success; WARN on already-registered (idempotent).
func Register(registry llm.LLMRegistry) error {
	if os.Getenv("GIBSON_TEST_FIXTURES_ENABLED") != "true" {
		slog.Info("mock-llm: GIBSON_TEST_FIXTURES_ENABLED not set — skipping registration (production safety gate)")
		return nil
	}
	slog.Warn("mock-llm: registering e2e test provider — NEVER run in production")
	p := newE2EMockProvider()
	if err := registry.RegisterProvider(p); err != nil {
		// Already registered is not an error — idempotent for daemon restarts.
		slog.Warn("mock-llm: RegisterProvider returned non-nil (may be duplicate)", "err", err)
	}
	return nil
}

// e2EMockProvider is the in-process deterministic provider.
// All state mutations are protected by mu; errorMode is an atomic string for
// fast-path read in Complete without holding the lock.
type e2EMockProvider struct {
	mu        sync.RWMutex
	callCount atomic.Int64
	errorMode string // protected by mu
}

func newE2EMockProvider() *e2EMockProvider {
	p := &e2EMockProvider{}
	p.errorMode = errorModeNone
	return p
}

// Name returns the registry key. Matches ProviderName.
func (p *e2EMockProvider) Name() string { return ProviderName }

// Models returns the single mock model understood by the probe agent.
func (p *e2EMockProvider) Models(_ context.Context) ([]llm.ModelInfo, error) {
	return []llm.ModelInfo{
		{
			Name:          "mock-model",
			ContextWindow: 200_000,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming"},
		},
	}, nil
}

// Complete returns DeterministicResponse for any prompt, or the configured error mode.
//
// Negative-test modes:
//   - errorModeError: returns a ProviderError so the probe's callLLM returns an error (R4.3).
//   - errorModeSlow:  blocks until ctx is cancelled so deadline-exceeded path fires (R4.4).
func (p *e2EMockProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	p.callCount.Add(1)

	p.mu.RLock()
	mode := p.errorMode
	p.mu.RUnlock()

	switch mode {
	case errorModeError:
		return nil, llm.NewProviderError(ProviderName, fmt.Errorf("injected e2e error for negative test R4.3"))
	case errorModeSlow:
		// Block until the caller's context deadline fires.  The test uses a
		// real 5 s context deadline — this path exercises R4.4.
		<-ctx.Done()
		return nil, llm.NewProviderError(ProviderName, fmt.Errorf("injected slow response: context deadline exceeded (R4.4)"))
	}

	// Happy path — deterministic response.
	return &llm.CompletionResponse{
		ID:    uuid.New().String(),
		Model: req.Model,
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: DeterministicResponse,
		},
		FinishReason: llm.FinishReasonStop,
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     len(req.Messages) * 10,
			CompletionTokens: len(DeterministicResponse) / 4,
			TotalTokens:      len(req.Messages)*10 + len(DeterministicResponse)/4,
		},
	}, nil
}

// CompleteWithTools delegates to Complete (mock ignores tool definitions).
func (p *e2EMockProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, _ []llm.ToolDef) (*llm.CompletionResponse, error) {
	return p.Complete(ctx, req)
}

// Stream returns a single-chunk stream with DeterministicResponse.
func (p *e2EMockProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	resp, err := p.Complete(ctx, req)
	if err != nil {
		return nil, err
	}

	ch := make(chan llm.StreamChunk, 2)
	go func() {
		defer close(ch)
		select {
		case <-ctx.Done():
			return
		case ch <- llm.StreamChunk{Delta: llm.StreamDelta{Content: resp.Message.Content}}:
		}
		select {
		case <-ctx.Done():
		case ch <- llm.StreamChunk{FinishReason: llm.FinishReasonStop}:
		}
	}()
	return ch, nil
}

// Health always reports healthy when in normal mode; degraded in error/slow mode.
func (p *e2EMockProvider) Health(_ context.Context) types.HealthStatus {
	p.mu.RLock()
	mode := p.errorMode
	p.mu.RUnlock()
	if mode != errorModeNone {
		return types.Degraded(fmt.Sprintf("mock-llm: error mode %q active (e2e test)", mode))
	}
	return types.NewHealthStatus(types.HealthStateHealthy, "mock-llm: ready (e2e test fixture)")
}

// SetErrorMode switches the error injection mode.  Called by the test helper
// (tests/e2e/helpers/mock_llm_client.go) via the daemon's provider state — in
// practice for e2e tests, the mock is stateful in-process and the test helper
// updates it directly through the registry.  External callers use the
// InjectErrorMode / ResetMockProvider helpers in mock_llm_client.go which
// reach the provider via InjectableProvider (below).
func (p *e2EMockProvider) SetErrorMode(mode string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.errorMode = mode
}

// CallCount returns the number of Complete/Stream calls received.
func (p *e2EMockProvider) CallCount() int64 {
	return p.callCount.Load()
}

// InjectableProvider is the interface the test helper uses to inject modes
// without importing the concrete type.  It is satisfied by *e2EMockProvider.
type InjectableProvider interface {
	llm.LLMProvider
	SetErrorMode(mode string)
	CallCount() int64
}

// LookupFromRegistry retrieves the mock provider from the daemon's LLM registry
// and returns it as InjectableProvider, so test helpers can inject error modes.
// Returns (nil, error) if not found or not the correct type.
func LookupFromRegistry(registry llm.LLMRegistry) (InjectableProvider, error) {
	raw, err := registry.GetProvider(ProviderName)
	if err != nil {
		return nil, fmt.Errorf("mock-llm: provider %q not found in registry: %w", ProviderName, err)
	}
	p, ok := raw.(InjectableProvider)
	if !ok {
		return nil, fmt.Errorf("mock-llm: provider %q is not InjectableProvider (unexpected type %T)", ProviderName, raw)
	}
	return p, nil
}
