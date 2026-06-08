package harness

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/llm"
)

// TestHarnessConfig_Validate tests configuration validation
func TestHarnessConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    HarnessConfig
		expectErr bool
	}{
		{
			name: "valid config with SlotManager",
			config: HarnessConfig{
				SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
			},
			expectErr: false,
		},
		{
			name:      "invalid config without SlotManager",
			config:    HarnessConfig{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

// TestHarnessConfig_ApplyDefaults tests that defaults are applied correctly
func TestHarnessConfig_ApplyDefaults(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		// All other fields are nil
	}

	// Before applying defaults
	if config.LLMRegistry != nil {
		t.Error("expected LLMRegistry to be nil before defaults")
	}

	config.ApplyDefaults()

	// After applying defaults
	if config.LLMRegistry == nil {
		t.Error("expected LLMRegistry to be defaulted")
	}
	// ComponentInstallRegistry field was removed in plugin-runtime Spec 2 Phase 7;
	// plugin dispatch goes through ComponentRegistry + WorkQueue
	// (component/plugin_dispatch.go).
	if config.Logger == nil {
		t.Error("expected Logger to be defaulted")
	}
	if config.FindingStore == nil {
		t.Error("expected FindingStore to be defaulted")
	}
	if config.Metrics == nil {
		t.Error("expected Metrics to be defaulted")
	}
	if config.Tracer == nil {
		t.Error("expected Tracer to be defaulted")
	}

	// SlotManager should remain unchanged
	if config.SlotManager == nil {
		t.Error("expected SlotManager to remain set")
	}

	// MemoryManager should remain nil (not defaulted)
	if config.MemoryManager != nil {
		t.Error("expected MemoryManager to remain nil (not defaulted)")
	}
}

// TestHarnessConfig_ApplyDefaults_Idempotent tests that ApplyDefaults is idempotent
func TestHarnessConfig_ApplyDefaults_Idempotent(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	// Apply defaults first time
	config.ApplyDefaults()
	firstLogger := config.Logger
	firstRegistry := config.LLMRegistry

	// Apply defaults second time
	config.ApplyDefaults()
	secondLogger := config.Logger
	secondRegistry := config.LLMRegistry

	// Should be the same instances (idempotent)
	if firstLogger != secondLogger {
		t.Error("expected Logger to remain the same after second ApplyDefaults")
	}
	if firstRegistry != secondRegistry {
		t.Error("expected LLMRegistry to remain the same after second ApplyDefaults")
	}
}

// TestHarnessFactoryConfig_Alias tests that HarnessFactoryConfig type alias works
func TestHarnessFactoryConfig_Alias(t *testing.T) {
	// Test that HarnessFactoryConfig is an alias for HarnessConfig
	var factoryConfig HarnessFactoryConfig
	factoryConfig.SlotManager = llm.NewSlotManager(llm.NewLLMRegistry())

	// Should be assignable to HarnessConfig without conversion
	var harnessConfig HarnessConfig = factoryConfig

	if harnessConfig.SlotManager == nil {
		t.Error("expected SlotManager to be set via alias")
	}
}

// TestNewDefaultHarnessFactory_Alias tests that NewDefaultHarnessFactory function alias works
func TestNewDefaultHarnessFactory_Alias(t *testing.T) {
	config := HarnessFactoryConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	// Test that NewDefaultHarnessFactory works
	factory, err := NewDefaultHarnessFactory(config)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if factory == nil {
		t.Fatal("expected factory to be non-nil")
	}

	// Verify factory has correct config
	factoryConfig := factory.Config()
	if factoryConfig.SlotManager == nil {
		t.Error("expected factory to have SlotManager configured")
	}

	// Verify defaults were applied
	if factoryConfig.LLMRegistry == nil {
		t.Error("expected factory to have LLMRegistry defaulted")
	}
}
