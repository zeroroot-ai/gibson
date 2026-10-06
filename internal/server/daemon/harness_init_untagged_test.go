// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !setec_integration

package daemon

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// The tests in this file pin the un-tagged build, which compiles no setec
// client. A published image builds with -tags=setec_integration.

// TestNewSetecAgentLauncher_DisabledBuild pins the default (un-tagged) build's
// fail-closed behavior: no setec client is compiled in, so the constructor
// returns (nil, nil) and an untrusted agent is denied rather than run.
func TestNewSetecAgentLauncher_DisabledBuild(t *testing.T) {
	l, err := NewSetecAgentLauncher(config.SandboxConfig{}, nil, nil, nil, nil, "")
	if l != nil || err != nil {
		t.Fatalf("disabled build: got (%v, %v), want (nil, nil)", l, err)
	}
}

// With a setec address set, the un-tagged build has no setec executor, so
// the factory builds and logs the build-tag warning.
func TestNewHarnessFactory_UntaggedBuildWithAnAddress(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Sandbox.Setec.Address = "setec:50051"
	d := &daemonImpl{
		config: cfg,
		logger: observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr}),
		infrastructure: &Infrastructure{
			llmRegistry: llm.NewLLMRegistry(),
			slotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		},
	}
	factory, err := d.newHarnessFactory(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, factory)
}
