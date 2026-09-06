// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
)

func TestNewHarnessFactory(t *testing.T) {
	// This test requires Redis + Neo4j infrastructure
	if os.Getenv("GIBSON_INTEGRATION_TESTS") == "" {
		t.Skip("skipping integration test (set GIBSON_INTEGRATION_TESTS=1 to run)")
	}

	// Create test daemon with minimal config
	cfg := &config.Config{
		Registry: config.RegistryConfig{},
	}

	logger := observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr})

	// Create StateClient via miniredis
	sc := setupTestStateClient(t)

	// Create a mock Redis-backed component registry adapter using a nil registry
	// (acceptable for this test since we only check harness factory initialization)
	var registryAdapter component.ComponentDiscovery

	// Create daemon instance
	d := &daemonImpl{
		config:          cfg,
		logger:          logger,
		stateClient:     sc,
		registryAdapter: registryAdapter,
	}

	// Create infrastructure
	ctx := context.Background()

	// Initialize infrastructure
	infra, err := d.newInfrastructure(ctx)
	require.NoError(t, err)
	require.NotNil(t, infra)

	// Verify infrastructure components
	assert.NotNil(t, infra.llmRegistry, "LLM registry should be initialized")
	assert.NotNil(t, infra.slotManager, "Slot manager should be initialized")
	assert.NotNil(t, infra.harnessFactory, "Harness factory should be initialized")
	assert.NotNil(t, infra.findingStore, "Finding store should be initialized")

	// Test harness factory directly
	factory, err := d.newHarnessFactory(ctx)
	require.NoError(t, err)
	assert.NotNil(t, factory, "Harness factory should not be nil")
}

func TestNewHarnessFactory_WithoutRegistryAdapter(t *testing.T) {
	logger := observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr})

	// Create daemon with minimal infrastructure (no registry adapter)
	d := &daemonImpl{
		logger:          logger,
		registryAdapter: nil, // No registry adapter
	}

	// Create minimal infrastructure manually
	d.infrastructure = &Infrastructure{
		llmRegistry: llm.NewLLMRegistry(),
		slotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	// Create harness factory - should still work even without registry adapter
	ctx := context.Background()
	factory, err := d.newHarnessFactory(ctx)
	require.NoError(t, err)
	assert.NotNil(t, factory, "Harness factory should be created even without registry adapter")
}

func TestNewHarnessFactory_ConfigValidation(t *testing.T) {
	logger := observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr})

	// Create daemon with nil slot manager (should fail validation)
	d := &daemonImpl{
		logger: logger,
		infrastructure: &Infrastructure{
			llmRegistry: llm.NewLLMRegistry(),
			slotManager: nil, // Missing required slot manager
		},
	}

	ctx := context.Background()
	factory, err := d.newHarnessFactory(ctx)

	// Should fail because SlotManager is required
	assert.Error(t, err, "Should return error when SlotManager is nil")
	assert.Nil(t, factory, "Factory should be nil when validation fails")
	assert.Contains(t, err.Error(), "SlotManager", "Error should mention SlotManager")
}

// TestTaskGrantVerifier_RefusesUntilTheKeyExists: the callback listener always
// gets a verifier, and until the daemon has a signing key that verifier answers
// ErrNoSigningKey. A presented grant is refused, never trusted (gibson#1605).
func TestTaskGrantVerifier_RefusesUntilTheKeyExists(t *testing.T) {
	d := &daemonImpl{}
	v := d.taskGrantVerifier()
	if v == nil {
		t.Fatal("the listener must always get a verifier, or a nil check becomes the gate")
	}
	if _, err := v.Verify(context.Background(), "x.y.z"); !errors.Is(err, capabilitygrant.ErrNoSigningKey) {
		t.Fatalf("err = %v, want ErrNoSigningKey", err)
	}
}

// TestTaskGrantVerifier_ReadsTheMinterPerCall: the Minter is built during
// Start, after the callback options are assembled, so the verifier has to read
// it per call rather than capture it.
func TestTaskGrantVerifier_ReadsTheMinterPerCall(t *testing.T) {
	d := &daemonImpl{}
	v := d.taskGrantVerifier()
	if _, err := v.Verify(context.Background(), "x.y.z"); !errors.Is(err, capabilitygrant.ErrNoSigningKey) {
		t.Fatalf("before the key: err = %v, want ErrNoSigningKey", err)
	}
	d.cgMinter = testCGMinter(t)
	if _, err := v.Verify(context.Background(), "x.y.z"); errors.Is(err, capabilitygrant.ErrNoSigningKey) {
		t.Fatal("after the key exists the same verifier must reach it")
	}
}

// testCGMinter builds a Minter over a fixed master key.
func testCGMinter(t *testing.T) *capabilitygrant.Minter {
	t.Helper()
	m, err := capabilitygrant.NewMinter(context.Background(), capabilitygrant.Config{
		Issuer: "https://test.daemon", Audience: "test-daemon",
		KeyProvider: fixedKeyProvider{key: []byte("kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk")},
		KeyID:       "k1",
	})
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return m
}

// fixedKeyProvider hands out one master key.
type fixedKeyProvider struct{ key []byte }

func (f fixedKeyProvider) GetEncryptionKey(context.Context) ([]byte, error) { return f.key, nil }
func (f fixedKeyProvider) Name() string                                     { return "test" }
func (f fixedKeyProvider) Health(context.Context) types.HealthStatus {
	return types.HealthStatus{State: types.HealthStateHealthy}
}
func (f fixedKeyProvider) Close() error { return nil }
