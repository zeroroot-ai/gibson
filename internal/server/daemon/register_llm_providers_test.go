// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

func testDaemonForRegistry(t *testing.T) *daemonImpl {
	t.Helper()
	return &daemonImpl{
		logger: observability.NewLogger(observability.Config{
			Component: "test", Level: slog.LevelError, Output: os.Stderr,
		}),
	}
}

// TestRegisterLLMProviders_EmptyByDesign: the daemon-wide registry holds no
// platform provider. Nothing in the daemon's environment or configuration
// registers one, so a production start leaves the registry empty and returns
// no error.
func TestRegisterLLMProviders_EmptyByDesign(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "a-key-the-daemon-must-ignore")
	t.Setenv("OPENAI_API_KEY", "another-key-the-daemon-must-ignore")

	registry := llm.NewLLMRegistry()
	require.NoError(t, testDaemonForRegistry(t).registerLLMProviders(context.Background(), registry))
	require.Empty(t, registry.ListProviders(), "the platform holds no LLM credential; the registry must stay empty")
}

// TestRegisterLLMProviders_KeepsWhatIsAlreadyThere: a registry that already
// carries a provider (the e2e mock fixture is the one production caller)
// is left as is.
func TestRegisterLLMProviders_KeepsWhatIsAlreadyThere(t *testing.T) {
	registry := llm.NewLLMRegistry()
	require.NoError(t, registry.RegisterProvider(createMockAnthropicProvider()))

	require.NoError(t, testDaemonForRegistry(t).registerLLMProviders(context.Background(), registry))
	require.Len(t, registry.ListProviders(), 1)
}
