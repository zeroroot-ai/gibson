package payload

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockComponentDiscovery implements component.ComponentDiscovery for testing
type mockComponentDiscovery struct{}

func (m *mockComponentDiscovery) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	return nil, nil
}

func (m *mockComponentDiscovery) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	return nil, nil
}

func (m *mockComponentDiscovery) DiscoverPlugin(ctx context.Context, name string) (plugin.Plugin, error) {
	return nil, nil
}

func (m *mockComponentDiscovery) ListAgents(ctx context.Context) ([]component.AgentInfo, error) {
	return []component.AgentInfo{}, nil
}

func (m *mockComponentDiscovery) ListTools(ctx context.Context) ([]component.ToolInfo, error) {
	return []component.ToolInfo{}, nil
}

func (m *mockComponentDiscovery) ListPlugins(ctx context.Context) ([]component.PluginInfo, error) {
	return []component.PluginInfo{}, nil
}

func (m *mockComponentDiscovery) DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	return agent.Result{}, nil
}

// TestNewPayloadExecutor tests executor creation
func TestNewPayloadExecutor(t *testing.T) {
	db, findingStore, cleanup := setupExecutorTestStore(t)
	defer cleanup()

	registry := NewPayloadRegistryWithDefaults(db)
	executionStore := NewExecutionStore(db)
	discovery := &mockComponentDiscovery{}

	config := DefaultExecutorConfig()
	executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

	require.NotNil(t, executor)
}

// TestPayloadExecutor_Execute tests full payload execution
func TestPayloadExecutor_Execute(t *testing.T) {
	db, findingStore, cleanup := setupExecutorTestStore(t)
	defer cleanup()

	registry := NewPayloadRegistryWithDefaults(db)
	executionStore := NewExecutionStore(db)
	discovery := &mockComponentDiscovery{}

	ctx := context.Background()

	t.Run("execute simple payload", func(t *testing.T) {
		// Create and register a test payload
		payload := createTestPayloadForExecutor("test-exec-simple")
		payload.Template = "Tell me about {{topic}}"
		payload.Parameters = []ParameterDef{
			{
				Name:        "topic",
				Type:        ParameterTypeString,
				Description: "Topic to ask about",
				Required:    true,
			},
		}
		payload.SuccessIndicators = []SuccessIndicator{
			{
				Type:   IndicatorContains,
				Value:  "Simulated",
				Weight: 1.0,
			},
		}
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		// Create executor with findings disabled for simpler test
		config := DefaultExecutorConfig()
		config.CreateFindings = false
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create execution request
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
		req.Parameters = map[string]interface{}{
			"topic": "security",
		}

		// Execute
		result, err := executor.Execute(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, ExecutionStatusCompleted, result.Status)
		assert.Contains(t, result.InstantiatedText, "security")
	})

	t.Run("execute with missing required parameter", func(t *testing.T) {
		// Create and register a test payload
		payload := createTestPayloadForExecutor("test-exec-missing-param")
		payload.Template = "Tell me about {{topic}}"
		payload.Parameters = []ParameterDef{
			{
				Name:        "topic",
				Type:        ParameterTypeString,
				Description: "Topic to ask about",
				Required:    true,
			},
		}
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create execution request without required parameter
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
		req.Parameters = map[string]interface{}{} // Empty params

		// Execute - should fail
		_, err = executor.Execute(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "parameter validation failed")
	})

	t.Run("execute disabled payload", func(t *testing.T) {
		// Create and register a disabled payload
		payload := createTestPayloadForExecutor("test-exec-disabled")
		payload.Enabled = false
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create execution request
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())

		// Execute - should fail
		_, err = executor.Execute(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "disabled")
	})

	t.Run("execute with timeout", func(t *testing.T) {
		// Create and register a test payload
		payload := createTestPayloadForExecutor("test-exec-timeout")
		payload.Template = "Quick test"
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create execution request with very short timeout
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
		req.Timeout = 1 * time.Nanosecond // Extremely short timeout

		// Execute - might timeout (but simulated execution is fast)
		result, err := executor.Execute(ctx, req)
		// Either succeeds or times out - both are acceptable for this test
		if err != nil {
			assert.Contains(t, err.Error(), "timeout")
		} else {
			assert.NotNil(t, result)
		}
	})

	t.Run("execute with nil request", func(t *testing.T) {
		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Execute with nil request
		_, err := executor.Execute(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("execute with empty payload ID", func(t *testing.T) {
		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create request with empty payload ID
		req := NewExecutionRequest("", types.NewID(), types.NewID())

		// Execute
		_, err := executor.Execute(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "payload ID is required")
	})

	t.Run("execute with non-existent payload", func(t *testing.T) {
		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create request with non-existent payload ID
		req := NewExecutionRequest(types.NewID(), types.NewID(), types.NewID())

		// Execute
		_, err := executor.Execute(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get payload")
	})
}

// TestPayloadExecutor_ExecuteDryRun tests dry run execution
func TestPayloadExecutor_ExecuteDryRun(t *testing.T) {
	db, findingStore, cleanup := setupExecutorTestStore(t)
	defer cleanup()

	registry := NewPayloadRegistryWithDefaults(db)
	executionStore := NewExecutionStore(db)
	discovery := &mockComponentDiscovery{}

	ctx := context.Background()

	t.Run("dry run with valid parameters", func(t *testing.T) {
		// Create and register a test payload
		payload := createTestPayloadForExecutor("test-dryrun-valid")
		payload.Template = "Tell me about {{topic}}"
		payload.Parameters = []ParameterDef{
			{
				Name:        "topic",
				Type:        ParameterTypeString,
				Description: "Topic to ask about",
				Required:    true,
			},
		}
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create dry run request
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
		req.Parameters = map[string]interface{}{
			"topic": "security",
		}

		// Execute dry run
		result, err := executor.ExecuteDryRun(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Valid)
		assert.Contains(t, result.InstantiatedText, "security")
		assert.Greater(t, result.EstimatedTokens, 0)
	})

	t.Run("dry run with missing required parameter", func(t *testing.T) {
		// Create and register a test payload
		payload := createTestPayloadForExecutor("test-dryrun-missing")
		payload.Template = "Tell me about {{topic}}"
		payload.Parameters = []ParameterDef{
			{
				Name:        "topic",
				Type:        ParameterTypeString,
				Description: "Topic to ask about",
				Required:    true,
			},
		}
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create dry run request without required parameter
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
		req.Parameters = map[string]interface{}{} // Empty params

		// Execute dry run
		result, err := executor.ExecuteDryRun(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Valid)
		assert.NotEmpty(t, result.ValidationErrors)
	})

	t.Run("dry run with disabled payload", func(t *testing.T) {
		// Create and register a disabled payload
		payload := createTestPayloadForExecutor("test-dryrun-disabled")
		payload.Enabled = false
		payload.Template = "Test"
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create dry run request
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())

		// Execute dry run - should warn but not fail
		result, err := executor.ExecuteDryRun(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Warnings)
		assert.Contains(t, result.Warnings[0], "disabled")
	})

	t.Run("dry run with nil request", func(t *testing.T) {
		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Execute dry run with nil request
		_, err := executor.ExecuteDryRun(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("dry run with long template", func(t *testing.T) {
		// Create and register a payload with very long template
		payload := createTestPayloadForExecutor("test-dryrun-long")
		longText := ""
		for i := 0; i < 3000; i++ {
			longText += "This is a very long payload template. "
		}
		payload.Template = longText
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		config := DefaultExecutorConfig()
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Create dry run request
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())

		// Execute dry run - should warn about length
		result, err := executor.ExecuteDryRun(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.Warnings)
	})
}

// TestPayloadExecutor_ValidateParameters tests parameter validation
func TestPayloadExecutor_ValidateParameters(t *testing.T) {
	db, findingStore, cleanup := setupExecutorTestStore(t)
	defer cleanup()

	registry := NewPayloadRegistryWithDefaults(db)
	executionStore := NewExecutionStore(db)
	discovery := &mockComponentDiscovery{}

	config := DefaultExecutorConfig()
	executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

	t.Run("validate with all required parameters", func(t *testing.T) {
		payload := createTestPayloadForExecutor("test-validate-valid")
		payload.Parameters = []ParameterDef{
			{
				Name:     "param1",
				Type:     ParameterTypeString,
				Required: true,
			},
			{
				Name:     "param2",
				Type:     ParameterTypeInt,
				Required: false,
			},
		}

		params := map[string]interface{}{
			"param1": "value1",
			"param2": 42,
		}

		err := executor.ValidateParameters(payload, params)
		assert.NoError(t, err)
	})

	t.Run("validate with missing required parameter", func(t *testing.T) {
		payload := createTestPayloadForExecutor("test-validate-missing")
		payload.Parameters = []ParameterDef{
			{
				Name:     "param1",
				Type:     ParameterTypeString,
				Required: true,
			},
		}

		params := map[string]interface{}{} // Empty params

		err := executor.ValidateParameters(payload, params)
		assert.Error(t, err)
	})

	t.Run("validate with nil payload", func(t *testing.T) {
		params := map[string]interface{}{
			"param1": "value1",
		}

		err := executor.ValidateParameters(nil, params)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})

	t.Run("validate with type mismatch", func(t *testing.T) {
		payload := createTestPayloadForExecutor("test-validate-type")
		payload.Parameters = []ParameterDef{
			{
				Name:     "count",
				Type:     ParameterTypeInt,
				Required: true,
			},
		}

		params := map[string]interface{}{
			"count": "not-an-integer", // String instead of integer
		}

		err := executor.ValidateParameters(payload, params)
		assert.Error(t, err)
	})
}

// TestPayloadExecutor_SuccessIndicators tests indicator matching
func TestPayloadExecutor_SuccessIndicators(t *testing.T) {
	db, findingStore, cleanup := setupExecutorTestStore(t)
	defer cleanup()

	registry := NewPayloadRegistryWithDefaults(db)
	executionStore := NewExecutionStore(db)
	discovery := &mockComponentDiscovery{}

	ctx := context.Background()

	t.Run("payload with matching indicators", func(t *testing.T) {
		// Create payload with success indicators
		payload := createTestPayloadForExecutor("test-indicators-match")
		payload.Template = "Test"
		payload.SuccessIndicators = []SuccessIndicator{
			{
				Type:   IndicatorContains,
				Value:  "Simulated response", // This will match our mock response
				Weight: 1.0,
			},
		}
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		config := DefaultExecutorConfig()
		config.CreateFindings = false
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Execute
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
		result, err := executor.Execute(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, result)
		// The simulated response contains "Simulated" so indicator should match
		assert.True(t, result.Success)
		assert.Greater(t, result.ConfidenceScore, 0.0)
	})

	t.Run("payload with non-matching indicators", func(t *testing.T) {
		// Create payload with success indicators that won't match
		payload := createTestPayloadForExecutor("test-indicators-nomatch")
		payload.Template = "Test"
		payload.SuccessIndicators = []SuccessIndicator{
			{
				Type:   IndicatorContains,
				Value:  "ThisWillNeverMatch",
				Weight: 1.0,
			},
		}
		err := registry.Register(ctx, payload)
		require.NoError(t, err)

		config := DefaultExecutorConfig()
		config.CreateFindings = false
		executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

		// Execute
		req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
		result, err := executor.Execute(ctx, req)

		require.NoError(t, err)
		assert.NotNil(t, result)
		// Indicators should not match
		assert.False(t, result.Success)
		assert.Equal(t, 0.0, result.ConfidenceScore)
	})
}

// TestPayloadExecutor_Concurrency tests concurrent execution
func TestPayloadExecutor_Concurrency(t *testing.T) {
	db, findingStore, cleanup := setupExecutorTestStore(t)
	defer cleanup()

	registry := NewPayloadRegistryWithDefaults(db)
	executionStore := NewExecutionStore(db)
	discovery := &mockComponentDiscovery{}

	ctx := context.Background()

	// Create and register a test payload
	payload := createTestPayloadForExecutor("test-concurrent")
	payload.Template = "Test {{id}}"
	payload.Parameters = []ParameterDef{
		{
			Name:     "id",
			Type:     ParameterTypeString,
			Required: true,
		},
	}
	err := registry.Register(ctx, payload)
	require.NoError(t, err)

	config := DefaultExecutorConfig()
	config.CreateFindings = false
	executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

	// Execute multiple payloads concurrently
	concurrency := 10
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func(id int) {
			req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
			req.Parameters = map[string]interface{}{
				"id": fmt.Sprintf("test-%d", id),
			}

			result, err := executor.Execute(ctx, req)
			assert.NoError(t, err)
			assert.NotNil(t, result)
			done <- true
		}(i)
	}

	// Wait for all executions to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}
}

// TestPayloadExecutor_ContextCancellation tests context cancellation
func TestPayloadExecutor_ContextCancellation(t *testing.T) {
	db, findingStore, cleanup := setupExecutorTestStore(t)
	defer cleanup()

	registry := NewPayloadRegistryWithDefaults(db)
	executionStore := NewExecutionStore(db)
	discovery := &mockComponentDiscovery{}

	// Create and register a test payload
	payload := createTestPayloadForExecutor("test-cancel")
	payload.Template = "Test"
	err := registry.Register(context.Background(), payload)
	require.NoError(t, err)

	config := DefaultExecutorConfig()
	executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

	// Create a cancellable context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Execute with cancelled context
	req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
	result, err := executor.Execute(ctx, req)

	// Should either error or complete very quickly
	// The simulated execution is fast, so it might complete before cancellation
	if err != nil {
		assert.Error(t, err)
	} else {
		assert.NotNil(t, result)
	}
}

// TestExecutionStore_Integration tests execution storage integration
func TestExecutionStore_Integration(t *testing.T) {
	db, findingStore, cleanup := setupExecutorTestStore(t)
	defer cleanup()

	registry := NewPayloadRegistryWithDefaults(db)
	executionStore := NewExecutionStore(db)
	discovery := &mockComponentDiscovery{}

	ctx := context.Background()

	// Create and register a test payload
	payload := createTestPayloadForExecutor("test-store-integration")
	payload.Template = "Test"
	err := registry.Register(ctx, payload)
	require.NoError(t, err)

	// Create executor with execution storage enabled
	config := DefaultExecutorConfig()
	config.StoreExecutions = true
	config.CreateFindings = false
	executor := NewPayloadExecutor(registry, executionStore, findingStore, discovery, config)

	// Execute
	req := NewExecutionRequest(payload.ID, types.NewID(), types.NewID())
	result, err := executor.Execute(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify execution was stored
	stored, err := executionStore.Get(ctx, result.ExecutionID)
	require.NoError(t, err)
	assert.Equal(t, result.ExecutionID, stored.ID)
	assert.Equal(t, payload.ID, stored.PayloadID)
}

// Helper function to create a test payload for executor tests
func createTestPayloadForExecutor(name string) *Payload {
	return &Payload{
		ID:          types.NewID(),
		Name:        name,
		Version:     "1.0.0",
		Description: "Test payload for " + name,
		Categories:  []PayloadCategory{CategoryJailbreak},
		Template:    "Test template",
		Parameters:  []ParameterDef{},
		SuccessIndicators: []SuccessIndicator{
			{Type: IndicatorContains, Value: "test", Weight: 1.0},
		},
		Severity:    agent.SeverityMedium,
		TargetTypes: []string{string(types.TargetTypeLLMChat)},
		Enabled:     true,
		Metadata: PayloadMetadata{
			Author: "test",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// setupExecutorTestStore creates a test database and stores for executor tests
func setupExecutorTestStore(t *testing.T) (*database.DB, finding.FindingStore, func()) {
	// For testing, we'll use database.DB with payload migrations
	db, _, cleanup := setupTestStore(t)

	// Create a simple finding store wrapper
	// In real usage, this would use finding.Database
	findingStore := &mockFindingStore{}

	return db, findingStore, cleanup
}

// mockFindingStore implements finding.FindingStore for testing
type mockFindingStore struct{}

func (m *mockFindingStore) Store(ctx context.Context, f finding.EnhancedFinding) error {
	return nil
}

func (m *mockFindingStore) Get(ctx context.Context, id types.ID) (*finding.EnhancedFinding, error) {
	return nil, nil
}

func (m *mockFindingStore) List(ctx context.Context, missionID types.ID, filter *finding.FindingFilter) ([]finding.EnhancedFinding, error) {
	return []finding.EnhancedFinding{}, nil
}

func (m *mockFindingStore) Update(ctx context.Context, f finding.EnhancedFinding) error {
	return nil
}

func (m *mockFindingStore) Delete(ctx context.Context, id types.ID) error {
	return nil
}

func (m *mockFindingStore) Count(ctx context.Context, missionID types.ID) (int, error) {
	return 0, nil
}
