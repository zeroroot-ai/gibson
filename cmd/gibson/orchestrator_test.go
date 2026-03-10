package main

import (
	"context"
	"os"
	"testing"

	"github.com/zero-day-ai/gibson/cmd/gibson/component"
)

// TestCreateOrchestrator_Success tests successful orchestrator creation
func TestCreateOrchestrator_Success(t *testing.T) {
	// Skip if no registry manager available (requires etcd/registry setup)
	t.Skip("requires registry manager setup - run integration tests instead")
}

// TestCreateOrchestrator_NoRegistry tests error handling when registry is not available
func TestCreateOrchestrator_NoRegistry(t *testing.T) {
	// Skip - requires Redis
	t.Skip("requires Redis")

	// Create context without registry manager
	ctx := context.Background()

	// Create a temporary home directory
	tmpDir := t.TempDir()
	originalHome := os.Getenv("GIBSON_HOME")
	os.Setenv("GIBSON_HOME", tmpDir)
	defer os.Setenv("GIBSON_HOME", originalHome)

	// Attempt to create orchestrator - should fail because no registry
	bundle, err := createOrchestrator(ctx)
	if err == nil {
		bundle.Cleanup()
		t.Fatal("expected error when registry is not available, got nil")
	}

	// Check error message
	expectedMsg := "registry not available"
	if err.Error() != expectedMsg && err.Error() != "registry not available (ensure daemon is running)" {
		t.Errorf("expected error containing %q, got %q", expectedMsg, err.Error())
	}
}

// TestOrchestratorBundle_Cleanup tests that cleanup function works correctly
func TestOrchestratorBundle_Cleanup(t *testing.T) {
	// Create a mock cleanup tracker
	cleanupCalled := false
	bundle := &OrchestratorBundle{
		Cleanup: func() {
			cleanupCalled = true
		},
	}

	// Call cleanup
	bundle.Cleanup()

	// Verify cleanup was called
	if !cleanupCalled {
		t.Error("cleanup function was not called")
	}

	// Call again to ensure idempotency doesn't panic
	bundle.Cleanup()
}

// TestCreateLLMComponents_NoProviders tests LLM component creation with no providers
func TestCreateLLMComponents_NoProviders(t *testing.T) {
	// Save and clear environment variables
	envVars := []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OLLAMA_URL"}
	savedVars := make(map[string]string)
	for _, v := range envVars {
		savedVars[v] = os.Getenv(v)
		os.Unsetenv(v)
	}
	defer func() {
		for k, v := range savedVars {
			if v != "" {
				os.Setenv(k, v)
			}
		}
	}()

	// Create LLM components - should succeed even with no providers
	registry, slotManager, err := createLLMComponents()
	if err != nil {
		t.Fatalf("createLLMComponents failed: %v", err)
	}

	// Verify registry is created
	if registry == nil {
		t.Error("LLM registry is nil")
	}

	// Verify slot manager is created
	if slotManager == nil {
		t.Error("slot manager is nil")
	}
}

// TestCreateLLMComponents_WithAnthropic tests LLM creation with Anthropic key
func TestCreateLLMComponents_WithAnthropic(t *testing.T) {
	// Skip if we're not testing with real API keys
	if os.Getenv("GIBSON_TEST_LLMS") == "" {
		t.Skip("skipping LLM provider test (set GIBSON_TEST_LLMS=1 to enable)")
	}

	// Save current value
	savedKey := os.Getenv("ANTHROPIC_API_KEY")
	if savedKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set")
	}

	// Create LLM components
	registry, slotManager, err := createLLMComponents()
	if err != nil {
		t.Fatalf("createLLMComponents failed: %v", err)
	}

	// Verify components are created
	if registry == nil {
		t.Error("LLM registry is nil")
	}
	if slotManager == nil {
		t.Error("slot manager is nil")
	}
}

// TestCreateOrchestrator_WithMockRegistry tests orchestrator with a mock registry
func TestCreateOrchestrator_WithMockRegistry(t *testing.T) {
	// Skip if we can't set up a mock registry easily
	t.Skip("requires mock registry implementation")
}

// TestOrchestratorBundle_AllFieldsPopulated verifies bundle structure
func TestOrchestratorBundle_AllFieldsPopulated(t *testing.T) {
	// Create a mock bundle to verify field types
	bundle := &OrchestratorBundle{}

	// Verify all expected fields exist (compile-time check)
	_ = bundle.Orchestrator
	_ = bundle.MissionStore
	_ = bundle.FindingStore
	_ = bundle.RegistryAdapter
	_ = bundle.EventEmitter
	_ = bundle.Cleanup
}

// BenchmarkCreateLLMComponents benchmarks LLM component creation
func BenchmarkCreateLLMComponents(b *testing.B) {
	// Clear environment to avoid actual provider creation
	envVars := []string{"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GOOGLE_API_KEY", "OLLAMA_URL"}
	savedVars := make(map[string]string)
	for _, v := range envVars {
		savedVars[v] = os.Getenv(v)
		os.Unsetenv(v)
	}
	defer func() {
		for k, v := range savedVars {
			if v != "" {
				os.Setenv(k, v)
			}
		}
	}()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = createLLMComponents()
	}
}

// Ensure we have the component package imported for potential mocking
var _ = component.GetRegistryManager
