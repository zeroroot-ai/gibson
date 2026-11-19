// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"testing"
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
				SlotManagerForTenant: fixedSlotManager(newStubSlotManager()),
				TargetFacts:          testTargetFacts,
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
		SlotManagerForTenant: fixedSlotManager(newStubSlotManager()),
		TargetFacts:          testTargetFacts,
		// All other fields are nil
	}

	config.ApplyDefaults()

	// After applying defaults
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
	if config.SlotManagerForTenant == nil {
		t.Error("expected SlotManager to remain set")
	}

}

// TestHarnessConfig_ApplyDefaults_Idempotent tests that ApplyDefaults is idempotent
func TestHarnessConfig_ApplyDefaults_Idempotent(t *testing.T) {
	config := HarnessConfig{
		SlotManagerForTenant: fixedSlotManager(newStubSlotManager()),
		TargetFacts:          testTargetFacts,
	}

	// Apply defaults first time
	config.ApplyDefaults()
	firstLogger := config.Logger

	// Apply defaults second time
	config.ApplyDefaults()
	secondLogger := config.Logger

	// Should be the same instances (idempotent)
	if firstLogger != secondLogger {
		t.Error("expected Logger to remain the same after second ApplyDefaults")
	}
}

// TestHarnessFactoryConfig_Alias tests that HarnessFactoryConfig type alias works
func TestHarnessFactoryConfig_Alias(t *testing.T) {
	// Test that HarnessFactoryConfig is an alias for HarnessConfig
	var factoryConfig HarnessFactoryConfig
	factoryConfig.SlotManagerForTenant = fixedSlotManager(newStubSlotManager())

	// Should be assignable to HarnessConfig without conversion
	var harnessConfig HarnessConfig = factoryConfig

	if harnessConfig.SlotManagerForTenant == nil {
		t.Error("expected SlotManager to be set via alias")
	}
}

// TestNewDefaultHarnessFactory_Alias tests that NewDefaultHarnessFactory function alias works
func TestNewDefaultHarnessFactory_Alias(t *testing.T) {
	config := HarnessFactoryConfig{
		SlotManagerForTenant: fixedSlotManager(newStubSlotManager()),
		TargetFacts:          testTargetFacts,
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
	if factoryConfig.SlotManagerForTenant == nil {
		t.Error("expected factory to have SlotManager configured")
	}

	// Verify defaults were applied
}

// A daemon builds the slot manager of each mission from the provider records of
// the tenant. It sets SlotManagerForTenant and no fixed SlotManager. The config
// must be valid then. The comment in DefaultHarnessFactory.Create says that the
// fixed SlotManager is only a unit test seam.
func TestHarnessConfig_Validate_AcceptsAPerTenantSlotManagerOnly(t *testing.T) {
	config := HarnessConfig{
		TargetFacts: testTargetFacts,
		SlotManagerForTenant: func(context.Context, string) (SlotManager, error) {
			return newStubSlotManager(), nil
		},
	}

	if err := config.Validate(); err != nil {
		t.Fatalf("a config with a per-tenant slot manager and no fixed one was refused: %v", err)
	}
}

// A config with no slot manager of any kind is still refused.
func TestHarnessConfig_Validate_RefusesNoSlotManagerAtAll(t *testing.T) {
	config := HarnessConfig{TargetFacts: testTargetFacts}

	if err := config.Validate(); err == nil {
		t.Fatal("a config with no slot manager was accepted")
	}
}
