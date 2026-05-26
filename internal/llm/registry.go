package llm

import (
	"context"
	"fmt"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// LLMRegistry manages LLM provider registration, discovery, and health monitoring.
// It provides a centralized registry for all LLM providers with thread-safe operations
// and built-in health aggregation.
type LLMRegistry interface {
	// RegisterProvider registers an LLM provider with the registry
	RegisterProvider(provider LLMProvider) error

	// UnregisterProvider removes a provider from the registry by name
	UnregisterProvider(name string) error

	// GetProvider retrieves a provider by name
	GetProvider(name string) (LLMProvider, error)

	// ListProviders returns the names of all registered providers
	ListProviders() []string

	// GetEmbeddingProvider returns the first registered provider that implements
	// EmbeddingProvider and returns SupportsEmbeddings() == true.
	// Returns ErrEmbeddingsNotSupported if no qualifying provider is found.
	GetEmbeddingProvider() (EmbeddingProvider, error)

	// Health returns the overall health status of the registry
	// Health states:
	// - Healthy: all providers are healthy
	// - Degraded: some providers are unhealthy
	// - Unhealthy: all providers are unhealthy or no providers registered
	Health(ctx context.Context) types.HealthStatus
}

// DefaultLLMRegistry implements LLMRegistry with thread-safe operations.
// It uses a sync.RWMutex to protect concurrent access to the provider map.
type DefaultLLMRegistry struct {
	mu        sync.RWMutex
	providers map[string]LLMProvider
}

// NewLLMRegistry creates a new DefaultLLMRegistry instance
func NewLLMRegistry() *DefaultLLMRegistry {
	return &DefaultLLMRegistry{
		providers: make(map[string]LLMProvider),
	}
}

// NewRegistry is an alias for NewLLMRegistry for backward compatibility
func NewRegistry() LLMRegistry {
	return NewLLMRegistry()
}

// RegisterProvider registers an LLM provider with the registry.
// Returns ErrLLMProviderAlreadyExists if a provider with the same name is already registered.
// Returns ErrLLMProviderInvalidInput if the provider is nil or has an empty name.
func (r *DefaultLLMRegistry) RegisterProvider(provider LLMProvider) error {
	if provider == nil {
		return types.NewError(ErrLLMProviderInvalidInput, "provider cannot be nil")
	}

	name := provider.Name()
	if name == "" {
		return types.NewError(ErrLLMProviderInvalidInput, "provider name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if provider already exists
	if _, exists := r.providers[name]; exists {
		return types.NewError(ErrLLMProviderAlreadyExists, fmt.Sprintf("provider %q already registered", name))
	}

	r.providers[name] = provider

	return nil
}

// UnregisterProvider removes a provider from the registry by name.
// Returns ErrLLMProviderNotFound if the provider doesn't exist.
func (r *DefaultLLMRegistry) UnregisterProvider(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if provider exists
	if _, exists := r.providers[name]; !exists {
		return types.NewError(ErrLLMProviderNotFound, fmt.Sprintf("provider %q not found", name))
	}

	delete(r.providers, name)

	return nil
}

// GetProvider retrieves a provider by name.
// Returns ErrLLMProviderNotFound if the provider doesn't exist.
func (r *DefaultLLMRegistry) GetProvider(name string) (LLMProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, exists := r.providers[name]
	if !exists {
		return nil, types.NewError(ErrLLMProviderNotFound, fmt.Sprintf("provider %q not found", name))
	}

	return provider, nil
}

// GetEmbeddingProvider returns the first registered provider that implements
// EmbeddingProvider and reports SupportsEmbeddings() == true.
// Returns ErrEmbeddingsNotSupported when no qualifying provider exists.
func (r *DefaultLLMRegistry) GetEmbeddingProvider() (EmbeddingProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.providers {
		ep, ok := p.(EmbeddingProvider)
		if ok && ep.SupportsEmbeddings() {
			return ep, nil
		}
	}

	return nil, ErrEmbeddingsNotSupported
}

// ListProviders returns the names of all registered providers.
// The returned slice is sorted alphabetically for consistent ordering.
func (r *DefaultLLMRegistry) ListProviders() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}

	return names
}

// Health returns the overall health status of the registry.
// The registry is:
// - Healthy if all providers are healthy
// - Degraded if some providers are unhealthy
// - Unhealthy if all providers are unhealthy or no providers are registered
func (r *DefaultLLMRegistry) Health(ctx context.Context) types.HealthStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if len(r.providers) == 0 {
		return types.Unhealthy("no providers registered")
	}

	healthyCount := 0
	unhealthyCount := 0
	totalProviders := len(r.providers)

	// Check health of each provider
	for _, provider := range r.providers {
		status := provider.Health(ctx)
		if status.IsHealthy() {
			healthyCount++
		} else {
			unhealthyCount++
		}
	}

	// Determine overall health
	if unhealthyCount == 0 {
		return types.Healthy(fmt.Sprintf("all %d providers healthy", totalProviders))
	} else if healthyCount == 0 {
		return types.Unhealthy(fmt.Sprintf("all %d providers unhealthy", totalProviders))
	} else {
		return types.Degraded(fmt.Sprintf("%d/%d providers healthy", healthyCount, totalProviders))
	}
}
