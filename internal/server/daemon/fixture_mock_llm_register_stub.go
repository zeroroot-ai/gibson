//go:build !test_fixtures

// fixture_mock_llm_register_stub.go — no-op stub for production builds.
//
// When the binary is built WITHOUT -tags=test_fixtures (i.e., `make bin`),
// this file is compiled instead of fixture_mock_llm_register.go.
// maybeRegisterMockLLMProvider does nothing, so no test fixture code path
// exists in the production binary.
//
// Requirements: NFR Security (production safety).
package daemon

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

// maybeRegisterMockLLMProvider is a compile-time no-op in production builds.
// The mock LLM provider is not compiled in when -tags=test_fixtures is absent.
func maybeRegisterMockLLMProvider(_ context.Context, _ llm.LLMRegistry) {}
