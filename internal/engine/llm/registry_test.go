package llm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// mockProvider implements the LLMProvider interface for testing
type mockProvider struct {
	name      string
	models    []ModelInfo
	healthy   bool
	callCount int
	mu        sync.Mutex
}

func newMockProvider(name string, healthy bool) *mockProvider {
	return &mockProvider{
		name:    name,
		healthy: healthy,
		models: []ModelInfo{
			{
				Name:          fmt.Sprintf("%s-model-1", name),
				ContextWindow: 8192,
				Features:      []string{"tool_use", "streaming"},
			},
			{
				Name:          fmt.Sprintf("%s-model-2", name),
				ContextWindow: 16384,
				Features:      []string{"tool_use", "vision", "streaming"},
			},
			{
				Name:          fmt.Sprintf("%s-model-3", name),
				ContextWindow: 16384,
				Features:      []string{"tool_use", "streaming", "json_mode"},
			},
		},
	}
}

func (m *mockProvider) Name() string {
	return m.name
}

func (m *mockProvider) Models(ctx context.Context) ([]ModelInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
	return m.models, nil
}

func (m *mockProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockProvider) CompleteWithTools(ctx context.Context, req CompletionRequest, tools []ToolDef) (*CompletionResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockProvider) Stream(ctx context.Context, req CompletionRequest) (<-chan StreamChunk, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockProvider) Health(ctx context.Context) types.HealthStatus {
	if m.healthy {
		return types.Healthy(fmt.Sprintf("%s is healthy", m.name))
	}
	return types.Unhealthy(fmt.Sprintf("%s is unhealthy", m.name))
}

func (m *mockProvider) SupportsStreaming() bool {
	return true
}

func TestNewLLMRegistry(t *testing.T) {
	registry := NewLLMRegistry()
	if registry == nil {
		t.Fatal("NewLLMRegistry returned nil")
	}

	if registry.providers == nil {
		t.Error("registry.providers map is nil")
	}

	if len(registry.providers) != 0 {
		t.Errorf("expected empty providers map, got %d entries", len(registry.providers))
	}
}

func TestRegisterProvider(t *testing.T) {
	tests := []struct {
		name      string
		provider  LLMProvider
		wantError types.ErrorCode
	}{
		{
			name:      "successful registration",
			provider:  newMockProvider("test-provider", true),
			wantError: "",
		},
		{
			name:      "nil provider",
			provider:  nil,
			wantError: ErrLLMProviderInvalidInput,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewLLMRegistry()
			err := registry.RegisterProvider(tt.provider)

			if tt.wantError != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantError)
				}
				var gibsonErr *types.GibsonError
				if !errors.As(err, &gibsonErr) {
					t.Fatalf("expected GibsonError, got %T", err)
				}
				if gibsonErr.Code != tt.wantError {
					t.Errorf("expected error code %q, got %q", tt.wantError, gibsonErr.Code)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				// Verify provider was registered
				provider, err := registry.GetProvider(tt.provider.Name())
				if err != nil {
					t.Fatalf("failed to get registered provider: %v", err)
				}
				if provider.Name() != tt.provider.Name() {
					t.Errorf("expected provider name %q, got %q", tt.provider.Name(), provider.Name())
				}
			}
		})
	}
}

func TestRegisterProviderDuplicate(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)

	// First registration should succeed
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Second registration should fail
	err := registry.RegisterProvider(provider)
	if err == nil {
		t.Fatal("expected error for duplicate registration, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrLLMProviderAlreadyExists {
		t.Errorf("expected error code %q, got %q", ErrLLMProviderAlreadyExists, gibsonErr.Code)
	}
}

func TestRegisterProviderEmptyName(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("", true)

	err := registry.RegisterProvider(provider)
	if err == nil {
		t.Fatal("expected error for empty provider name, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrLLMProviderInvalidInput {
		t.Errorf("expected error code %q, got %q", ErrLLMProviderInvalidInput, gibsonErr.Code)
	}
}

func TestUnregisterProvider(t *testing.T) {
	registry := NewLLMRegistry()
	provider := newMockProvider("test-provider", true)

	// Register provider
	if err := registry.RegisterProvider(provider); err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	// Unregister provider
	if err := registry.UnregisterProvider(provider.Name()); err != nil {
		t.Fatalf("unregistration failed: %v", err)
	}

	// Verify provider is gone
	_, err := registry.GetProvider(provider.Name())
	if err == nil {
		t.Fatal("expected error when getting unregistered provider, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrLLMProviderNotFound {
		t.Errorf("expected error code %q, got %q", ErrLLMProviderNotFound, gibsonErr.Code)
	}
}

func TestUnregisterProviderNotFound(t *testing.T) {
	registry := NewLLMRegistry()

	err := registry.UnregisterProvider("nonexistent")
	if err == nil {
		t.Fatal("expected error when unregistering nonexistent provider, got nil")
	}

	var gibsonErr *types.GibsonError
	if !errors.As(err, &gibsonErr) {
		t.Fatalf("expected GibsonError, got %T", err)
	}
	if gibsonErr.Code != ErrLLMProviderNotFound {
		t.Errorf("expected error code %q, got %q", ErrLLMProviderNotFound, gibsonErr.Code)
	}
}

func TestGetProvider(t *testing.T) {
	registry := NewLLMRegistry()
	provider1 := newMockProvider("provider1", true)
	provider2 := newMockProvider("provider2", true)

	// Register providers
	if err := registry.RegisterProvider(provider1); err != nil {
		t.Fatalf("failed to register provider1: %v", err)
	}
	if err := registry.RegisterProvider(provider2); err != nil {
		t.Fatalf("failed to register provider2: %v", err)
	}

	// Get provider1
	p, err := registry.GetProvider("provider1")
	if err != nil {
		t.Fatalf("failed to get provider1: %v", err)
	}
	if p.Name() != "provider1" {
		t.Errorf("expected provider name %q, got %q", "provider1", p.Name())
	}

	// Get provider2
	p, err = registry.GetProvider("provider2")
	if err != nil {
		t.Fatalf("failed to get provider2: %v", err)
	}
	if p.Name() != "provider2" {
		t.Errorf("expected provider name %q, got %q", "provider2", p.Name())
	}

	// Get nonexistent provider
	_, err = registry.GetProvider("nonexistent")
	if err == nil {
		t.Fatal("expected error when getting nonexistent provider, got nil")
	}
}

func TestListProviders(t *testing.T) {
	registry := NewLLMRegistry()

	// Initially empty
	providers := registry.ListProviders()
	if len(providers) != 0 {
		t.Errorf("expected 0 providers, got %d", len(providers))
	}

	// Register providers
	provider1 := newMockProvider("provider1", true)
	provider2 := newMockProvider("provider2", true)
	provider3 := newMockProvider("provider3", true)

	if err := registry.RegisterProvider(provider1); err != nil {
		t.Fatalf("failed to register provider1: %v", err)
	}
	if err := registry.RegisterProvider(provider2); err != nil {
		t.Fatalf("failed to register provider2: %v", err)
	}
	if err := registry.RegisterProvider(provider3); err != nil {
		t.Fatalf("failed to register provider3: %v", err)
	}

	// List providers
	providers = registry.ListProviders()
	if len(providers) != 3 {
		t.Errorf("expected 3 providers, got %d", len(providers))
	}

	// Verify all provider names are present
	names := make(map[string]bool)
	for _, name := range providers {
		names[name] = true
	}

	if !names["provider1"] || !names["provider2"] || !names["provider3"] {
		t.Errorf("missing expected provider names in list: %v", providers)
	}
}

func TestHealth(t *testing.T) {
	tests := []struct {
		name          string
		providers     []LLMProvider
		expectedState types.HealthState
		expectedInMsg string
	}{
		{
			name:          "no providers",
			providers:     []LLMProvider{},
			expectedState: types.HealthStateUnhealthy,
			expectedInMsg: "no providers",
		},
		{
			name: "all healthy",
			providers: []LLMProvider{
				newMockProvider("provider1", true),
				newMockProvider("provider2", true),
				newMockProvider("provider3", true),
			},
			expectedState: types.HealthStateHealthy,
			expectedInMsg: "all 3 providers healthy",
		},
		{
			name: "all unhealthy",
			providers: []LLMProvider{
				newMockProvider("provider1", false),
				newMockProvider("provider2", false),
			},
			expectedState: types.HealthStateUnhealthy,
			expectedInMsg: "all 2 providers unhealthy",
		},
		{
			name: "mixed health",
			providers: []LLMProvider{
				newMockProvider("provider1", true),
				newMockProvider("provider2", false),
				newMockProvider("provider3", true),
			},
			expectedState: types.HealthStateDegraded,
			expectedInMsg: "2/3 providers healthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewLLMRegistry()

			// Register providers
			for _, provider := range tt.providers {
				if err := registry.RegisterProvider(provider); err != nil {
					t.Fatalf("failed to register provider: %v", err)
				}
			}

			// Check health
			ctx := context.Background()
			status := registry.Health(ctx)

			if status.State != tt.expectedState {
				t.Errorf("expected health state %q, got %q", tt.expectedState, status.State)
			}

			if tt.expectedInMsg != "" && !contains(status.Message, tt.expectedInMsg) {
				t.Errorf("expected message to contain %q, got %q", tt.expectedInMsg, status.Message)
			}
		})
	}
}

func TestRegistryConcurrentAccess(t *testing.T) {
	registry := NewLLMRegistry()
	ctx := context.Background()

	const numGoroutines = 100
	const numOperations = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // readers, writers, health checkers

	// Concurrent readers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				providerName := fmt.Sprintf("provider-%d", id%10)
				_, _ = registry.GetProvider(providerName)
				_ = registry.ListProviders()
			}
		}(i)
	}

	// Concurrent writers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				providerName := fmt.Sprintf("provider-%d", id%10)
				provider := newMockProvider(providerName, true)
				_ = registry.RegisterProvider(provider)
				_ = registry.UnregisterProvider(providerName)
			}
		}(i)
	}

	// Concurrent health checkers
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_ = registry.Health(ctx)
			}
		}()
	}

	wg.Wait()
}

func TestRegistryRegisterAndUnregisterConcurrent(t *testing.T) {
	registry := NewLLMRegistry()

	const numProviders = 100
	var wg sync.WaitGroup
	wg.Add(numProviders * 2) // register and unregister

	// Register all providers concurrently
	for i := 0; i < numProviders; i++ {
		go func(id int) {
			defer wg.Done()
			provider := newMockProvider(fmt.Sprintf("provider-%d", id), true)
			_ = registry.RegisterProvider(provider)
		}(i)
	}

	// Unregister all providers concurrently
	for i := 0; i < numProviders; i++ {
		go func(id int) {
			defer wg.Done()
			_ = registry.UnregisterProvider(fmt.Sprintf("provider-%d", id))
		}(i)
	}

	wg.Wait()

	// After all operations, registry should be empty or have few providers
	// (due to race conditions, some may remain)
	providers := registry.ListProviders()
	t.Logf("After concurrent operations, %d providers remain", len(providers))
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
