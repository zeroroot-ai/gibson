//go:build test_fixtures

// fixture_mock_llm_register.go — daemon-side hook for the e2e mock LLM provider.
//
// This file is ONLY compiled when -tags=test_fixtures is passed.
// Production `make bin` never uses that flag, so the mock is absent from
// production binaries regardless of GIBSON_TEST_FIXTURES_ENABLED.
//
// PRODUCTION SAFETY: two independent gates:
//  1. Build tag test_fixtures (absent from `make bin`) — compile-time gate.
//  2. GIBSON_TEST_FIXTURES_ENABLED=true env var — runtime gate checked inside Register().
//
// Neither gate alone is sufficient; both must be true for mock registration.
//
// Requirements: R3.1, NFR Security.
package daemon

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/llm"
	mockllm "github.com/zeroroot-ai/gibson/tests/e2e/fixtures/providers/mock-llm"
)

// maybeRegisterMockLLMProvider registers the e2e mock LLM provider into the
// registry when:
//  1. The binary was built with -tags=test_fixtures (compile-time gate, this
//     file only exists in that build), AND
//  2. GIBSON_TEST_FIXTURES_ENABLED=true (runtime gate inside mockllm.Register).
//
// Called at the end of registerLLMProviders in infrastructure.go.
func maybeRegisterMockLLMProvider(_ context.Context, registry llm.LLMRegistry) {
	// Error is non-fatal; mockllm.Register logs internally via slog.
	_ = mockllm.Register(registry)
}
