package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestInfrastructureInitialization(t *testing.T) {
	// Create temporary directory for test data
	tmpDir := t.TempDir()

	// Create minimal test configuration using actual config types
	cfg := &config.Config{
		Registry: config.RegistryConfig{
			Type:      "embedded",
			Namespace: "gibson-test",
			DataDir:   filepath.Join(tmpDir, "etcd"),
			TTL:       "30s",
		},
		Callback: config.CallbackConfig{
			Enabled:          false,
			ListenAddress:    "localhost:0",
			AdvertiseAddress: "localhost:0",
		},
		LLM: config.LLMConfig{
			// LLMConfig only has DefaultProvider field
			DefaultProvider: "",
		},
	}

	// Create daemon instance
	homeDir := filepath.Join(tmpDir, ".gibson")
	if err := os.MkdirAll(homeDir, 0755); err != nil {
		t.Fatalf("failed to create home dir: %v", err)
	}

	daemon, err := New(cfg, homeDir)
	if err != nil {
		t.Fatalf("failed to create daemon: %v", err)
	}

	// Downcast to daemonImpl to access internal methods
	daemonImpl, ok := daemon.(*daemonImpl)
	if !ok {
		t.Fatal("daemon is not a *daemonImpl")
	}

	ctx := context.Background()

	// Initialize infrastructure
	infra, err := daemonImpl.newInfrastructure(ctx)
	if err != nil {
		t.Fatalf("failed to initialize infrastructure: %v", err)
	}

	// Verify infrastructure components are created
	if infra == nil {
		t.Fatal("infrastructure is nil")
	}

	if infra.findingStore == nil {
		t.Fatal("finding store is nil")
	}

	if infra.llmRegistry == nil {
		t.Fatal("LLM registry is nil")
	}

	if infra.planExecutor == nil {
		t.Fatal("plan executor is nil")
	}

	if infra.slotManager == nil {
		t.Fatal("slot manager is nil")
	}

	if infra.harnessFactory == nil {
		t.Fatal("harness factory is nil")
	}

	if infra.memoryManagerFactory == nil {
		t.Fatal("memory manager factory is nil")
	}

	// Test finding store basic operation
	t.Run("FindingStore", func(t *testing.T) {
		// Count should succeed even with empty database
		count, err := infra.findingStore.Count(ctx, types.NewID())
		if err != nil {
			t.Errorf("finding store count failed: %v", err)
		}
		if count != 0 {
			t.Errorf("expected count 0, got %d", count)
		}
	})

	// Test LLM registry exists
	t.Run("LLMRegistry", func(t *testing.T) {
		// No providers configured via env vars in test, so list should be empty or have env-based providers
		providers := infra.llmRegistry.ListProviders()
		// Just verify it doesn't panic and returns a slice
		if providers == nil {
			t.Error("ListProviders returned nil, expected empty slice")
		}
	})

	// Test plan executor exists
	t.Run("PlanExecutor", func(t *testing.T) {
		if infra.planExecutor == nil {
			t.Error("plan executor should not be nil")
		}
	})

	// Test slot manager exists
	t.Run("SlotManager", func(t *testing.T) {
		if infra.slotManager == nil {
			t.Error("slot manager should not be nil")
		}
	})

	// Test harness factory exists
	t.Run("HarnessFactory", func(t *testing.T) {
		if infra.harnessFactory == nil {
			t.Error("harness factory should not be nil")
		}
	})

	// Test memory manager factory exists and can create managers
	t.Run("MemoryManagerFactory", func(t *testing.T) {
		if infra.memoryManagerFactory == nil {
			t.Error("memory manager factory should not be nil")
		}

		// Try to create a memory manager for a mission
		missionID := types.NewID()
		memMgr, err := infra.memoryManagerFactory.CreateForMission(ctx, missionID)
		if err != nil {
			t.Errorf("failed to create memory manager: %v", err)
		}
		if memMgr == nil {
			t.Error("memory manager is nil")
		}
	})
}
