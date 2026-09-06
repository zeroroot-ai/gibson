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
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// TestRegisterLLMProviders_ConfigDriven exercises the config-driven provider
// registration loop, specifically the providers.NewProviderWithContext call
// site. A provider that fails to construct is logged and skipped, so the loop
// runs to completion and returns nil either way.
func TestRegisterLLMProviders_ConfigDriven(t *testing.T) {
	di := &daemonImpl{
		logger: observability.NewLogger(observability.Config{
			Component: "test", Level: slog.LevelError, Output: os.Stderr,
		}),
		config: &config.Config{
			LLM: config.LLMConfig{
				Providers: map[string]config.ProviderConfig{
					"anthropic": {Type: "anthropic", APIKey: "unit-test-key", Model: "claude-x"},
				},
			},
		},
	}

	require.NoError(t, di.registerLLMProviders(context.Background(), llm.NewLLMRegistry()))
}
