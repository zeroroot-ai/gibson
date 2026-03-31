package daemon

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/observability"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/state"
)

func TestNewHarnessFactory(t *testing.T) {
	// Create test daemon with minimal config
	cfg := &config.Config{
		Registry: config.RegistryConfig{
			Type: "embedded",
		},
	}

	logger := observability.NewLogger(observability.Config{Component: "test", Level: slog.LevelError, Output: os.Stderr})

	// Create StateClient via miniredis
	sc := setupTestStateClient(t)

	// Create daemon instance
	d := &daemonImpl{
		config:         cfg,
		logger:         logger,
		stateClient:    sc,
		registry:       registry.NewManager(cfg.Registry),
		activeMissions: make(map[string]context.CancelFunc),
	}

	// Create infrastructure (which includes registry adapter)
	ctx := context.Background()

	// Start registry to create the adapter
	err := d.registry.Start(ctx)
	require.NoError(t, err)
	defer d.registry.Stop(ctx)

	// Create registry adapter
	d.registryAdapter = registry.NewRegistryAdapter(d.registry.Registry())

	// Initialize infrastructure
	infra, err := d.newInfrastructure(ctx)
	require.NoError(t, err)
	require.NotNil(t, infra)

	// Verify infrastructure components
	assert.NotNil(t, infra.llmRegistry, "LLM registry should be initialized")
	assert.NotNil(t, infra.slotManager, "Slot manager should be initialized")
	assert.NotNil(t, infra.harnessFactory, "Harness factory should be initialized")
	assert.NotNil(t, infra.findingStore, "Finding store should be initialized")
	assert.NotNil(t, infra.planExecutor, "Plan executor should be initialized")

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
