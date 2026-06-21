package daemon

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/config"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/observability"
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
		activeMissions:  make(map[string]context.CancelFunc),
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
