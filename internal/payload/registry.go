package payload

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// PayloadRegistry manages payload registration, lookup, and caching.
// The registry is the central point for discovering and retrieving payloads.
// It provides thread-safe access to payloads and caches frequently accessed payloads.
type PayloadRegistry interface {
	// Register adds a new payload to the registry
	Register(ctx context.Context, payload *Payload) error

	// Get retrieves a payload by ID with caching
	Get(ctx context.Context, id types.ID) (*Payload, error)

	// List retrieves payloads with optional filtering, delegating to store
	List(ctx context.Context, filter *PayloadFilter) ([]*Payload, error)

	// Search performs full-text search delegating to store FTS
	Search(ctx context.Context, query string, filter *PayloadFilter) ([]*Payload, error)

	// Update modifies an existing payload with version tracking
	Update(ctx context.Context, payload *Payload) error

	// Disable soft-deletes a payload (sets Enabled=false)
	Disable(ctx context.Context, id types.ID) error

	// Enable re-enables a disabled payload
	Enable(ctx context.Context, id types.ID) error

	// GetByCategory retrieves all payloads in a specific category
	GetByCategory(ctx context.Context, category PayloadCategory) ([]*Payload, error)

	// GetByMitreTechnique retrieves payloads mapped to a specific MITRE technique
	GetByMitreTechnique(ctx context.Context, technique string) ([]*Payload, error)

	// LoadBuiltIns loads all built-in payloads at initialization
	LoadBuiltIns(ctx context.Context) error

	// Count returns the total number of registered payloads
	Count(ctx context.Context, filter *PayloadFilter) (int, error)

	// ClearCache clears the payload cache
	ClearCache()

	// Health returns the health status of the registry
	Health(ctx context.Context) types.HealthStatus
}

// registryCache holds cached payloads with expiration
type registryCache struct {
	payload   *Payload
	expiresAt time.Time
}

// DefaultPayloadRegistry implements PayloadRegistry with thread-safe caching
type DefaultPayloadRegistry struct {
	mu               sync.RWMutex
	store            PayloadStore
	cache            map[types.ID]*registryCache
	cacheTTL         time.Duration
	builtInLoader    BuiltInLoader
	builtInsLoaded   bool
	enableAutoExpire bool // Set to true to enable automatic cache expiration
}

// RegistryConfig holds configuration for the payload registry
type RegistryConfig struct {
	CacheTTL         time.Duration
	EnableAutoExpire bool
}

// DefaultRegistryConfig returns the default registry configuration
func DefaultRegistryConfig() RegistryConfig {
	return RegistryConfig{
		CacheTTL:         5 * time.Minute,
		EnableAutoExpire: true,
	}
}

// NewPayloadRegistryWithStore creates a new payload registry with a custom PayloadStore.
// This allows using Redis-backed or other store implementations.
func NewPayloadRegistryWithStore(store PayloadStore, config RegistryConfig) *DefaultPayloadRegistry {
	return &DefaultPayloadRegistry{
		store:            store,
		cache:            make(map[types.ID]*registryCache),
		cacheTTL:         config.CacheTTL,
		builtInLoader:    NewBuiltInLoader(),
		builtInsLoaded:   false,
		enableAutoExpire: config.EnableAutoExpire,
	}
}

// Register adds a new payload to the registry
func (r *DefaultPayloadRegistry) Register(ctx context.Context, payload *Payload) error {
	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate by ID
	exists, err := r.store.Exists(ctx, payload.ID)
	if err != nil {
		return fmt.Errorf("failed to check payload existence: %w", err)
	}
	if exists {
		return fmt.Errorf("payload with ID %s already exists", payload.ID)
	}

	// Check for duplicate by name
	existsByName, err := r.store.ExistsByName(ctx, payload.Name)
	if err != nil {
		return fmt.Errorf("failed to check payload name existence: %w", err)
	}
	if existsByName {
		return fmt.Errorf("payload with name %s already exists", payload.Name)
	}

	// Save to store
	if err := r.store.Save(ctx, payload); err != nil {
		return fmt.Errorf("failed to save payload: %w", err)
	}

	// Add to cache
	r.cachePayload(payload)

	return nil
}

// Get retrieves a payload by ID with caching
func (r *DefaultPayloadRegistry) Get(ctx context.Context, id types.ID) (*Payload, error) {
	// Check cache first (with read lock)
	r.mu.RLock()
	if cached, ok := r.cache[id]; ok {
		// Check if cache entry is still valid
		if !r.enableAutoExpire || time.Now().Before(cached.expiresAt) {
			r.mu.RUnlock()
			// Return a copy to prevent external modifications
			payloadCopy := *cached.payload
			return &payloadCopy, nil
		}
	}
	r.mu.RUnlock()

	// Not in cache or expired, fetch from store
	payload, err := r.store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update cache with write lock
	r.mu.Lock()
	r.cachePayload(payload)
	r.mu.Unlock()

	// Return a copy
	payloadCopy := *payload
	return &payloadCopy, nil
}

// List retrieves payloads with optional filtering
func (r *DefaultPayloadRegistry) List(ctx context.Context, filter *PayloadFilter) ([]*Payload, error) {
	return r.store.List(ctx, filter)
}

// Search performs full-text search on payloads
func (r *DefaultPayloadRegistry) Search(ctx context.Context, query string, filter *PayloadFilter) ([]*Payload, error) {
	return r.store.Search(ctx, query, filter)
}

// Update modifies an existing payload with version tracking
func (r *DefaultPayloadRegistry) Update(ctx context.Context, payload *Payload) error {
	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Update in store
	if err := r.store.Update(ctx, payload); err != nil {
		return fmt.Errorf("failed to update payload: %w", err)
	}

	// Invalidate cache entry
	delete(r.cache, payload.ID)

	return nil
}

// Disable soft-deletes a payload by setting Enabled=false
func (r *DefaultPayloadRegistry) Disable(ctx context.Context, id types.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Delete from store (which performs soft delete)
	if err := r.store.Delete(ctx, id); err != nil {
		return fmt.Errorf("failed to disable payload: %w", err)
	}

	// Invalidate cache entry
	delete(r.cache, id)

	return nil
}

// Enable re-enables a disabled payload
func (r *DefaultPayloadRegistry) Enable(ctx context.Context, id types.ID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Fetch the payload
	payload, err := r.store.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to get payload: %w", err)
	}

	// Enable it
	payload.Enabled = true
	payload.UpdatedAt = time.Now()

	// Update in store
	if err := r.store.Update(ctx, payload); err != nil {
		return fmt.Errorf("failed to enable payload: %w", err)
	}

	// Invalidate cache entry
	delete(r.cache, id)

	return nil
}

// GetByCategory retrieves all payloads in a specific category
func (r *DefaultPayloadRegistry) GetByCategory(ctx context.Context, category PayloadCategory) ([]*Payload, error) {
	filter := &PayloadFilter{
		Categories: []PayloadCategory{category},
		Enabled:    boolPtr(true),
	}
	return r.store.List(ctx, filter)
}

// GetByMitreTechnique retrieves payloads mapped to a specific MITRE technique
func (r *DefaultPayloadRegistry) GetByMitreTechnique(ctx context.Context, technique string) ([]*Payload, error) {
	filter := &PayloadFilter{
		MitreTechniques: []string{technique},
		Enabled:         boolPtr(true),
	}
	return r.store.List(ctx, filter)
}

// LoadBuiltIns loads all built-in payloads at initialization
func (r *DefaultPayloadRegistry) LoadBuiltIns(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.builtInsLoaded {
		return nil // Already loaded
	}

	// Load built-in payloads
	payloads, err := r.builtInLoader.Load()
	if err != nil {
		return fmt.Errorf("failed to load built-in payloads: %w", err)
	}

	// Register each built-in payload
	registered := 0
	skipped := 0
	for i := range payloads {
		payload := &payloads[i]

		// Check if already exists
		exists, err := r.store.Exists(ctx, payload.ID)
		if err != nil {
			// Log error but continue
			continue
		}
		if exists {
			skipped++
			continue
		}

		// Save to store (no duplicate check needed, we already checked)
		if err := r.store.Save(ctx, payload); err != nil {
			// Log error but continue with other payloads
			continue
		}

		// Add to cache
		r.cachePayload(payload)
		registered++
	}

	r.builtInsLoaded = true

	// Return summary information as an error if some failed
	if skipped > 0 {
		return fmt.Errorf("loaded %d built-in payloads (%d already existed)", registered, skipped)
	}

	return nil
}

// Count returns the total number of registered payloads
func (r *DefaultPayloadRegistry) Count(ctx context.Context, filter *PayloadFilter) (int, error) {
	return r.store.Count(ctx, filter)
}

// ClearCache clears the entire payload cache
func (r *DefaultPayloadRegistry) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[types.ID]*registryCache)
}

// Health returns the health status of the registry
func (r *DefaultPayloadRegistry) Health(ctx context.Context) types.HealthStatus {
	r.mu.RLock()
	cacheSize := len(r.cache)
	builtInsLoaded := r.builtInsLoaded
	r.mu.RUnlock()

	// Check if we can query the store
	count, err := r.store.Count(ctx, nil)
	if err != nil {
		return types.Degraded(fmt.Sprintf("Failed to query payload store: %v", err))
	}

	return types.Healthy(fmt.Sprintf("Registry healthy: %d payloads, %d cached, built-ins loaded: %v",
		count, cacheSize, builtInsLoaded))
}

// cachePayload adds a payload to the cache (caller must hold write lock)
func (r *DefaultPayloadRegistry) cachePayload(payload *Payload) {
	if payload == nil {
		return
	}

	// Create a copy to prevent external modifications
	payloadCopy := *payload

	r.cache[payload.ID] = &registryCache{
		payload:   &payloadCopy,
		expiresAt: time.Now().Add(r.cacheTTL),
	}
}

// GetCacheStats returns statistics about the cache
func (r *DefaultPayloadRegistry) GetCacheStats() (size int, ttl time.Duration) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache), r.cacheTTL
}

// ListCategoryStats returns the number of payloads per category
func (r *DefaultPayloadRegistry) ListCategoryStats(ctx context.Context) (map[PayloadCategory]int, error) {
	stats := make(map[PayloadCategory]int)

	// Get all enabled payloads
	filter := &PayloadFilter{
		Enabled: boolPtr(true),
	}
	payloads, err := r.store.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list payloads: %w", err)
	}

	// Count by category
	for _, payload := range payloads {
		for _, category := range payload.Categories {
			stats[category]++
		}
	}

	return stats, nil
}

// ListMitreStats returns the number of payloads per MITRE technique
func (r *DefaultPayloadRegistry) ListMitreStats(ctx context.Context) (map[string]int, error) {
	stats := make(map[string]int)

	// Get all enabled payloads
	filter := &PayloadFilter{
		Enabled: boolPtr(true),
	}
	payloads, err := r.store.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list payloads: %w", err)
	}

	// Count by MITRE technique
	for _, payload := range payloads {
		for _, technique := range payload.MitreTechniques {
			stats[technique]++
		}
	}

	return stats, nil
}

// GetTopPayloads returns the most frequently accessed payloads from cache
func (r *DefaultPayloadRegistry) GetTopPayloads(limit int) []*Payload {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Get all cached payloads
	payloads := make([]*Payload, 0, len(r.cache))
	for _, cached := range r.cache {
		if !r.enableAutoExpire || time.Now().Before(cached.expiresAt) {
			// Return copies
			payloadCopy := *cached.payload
			payloads = append(payloads, &payloadCopy)
		}
	}

	// Sort by name for consistent ordering (in real implementation, could track access count)
	sort.Slice(payloads, func(i, j int) bool {
		return payloads[i].Name < payloads[j].Name
	})

	// Limit results
	if limit > 0 && len(payloads) > limit {
		payloads = payloads[:limit]
	}

	return payloads
}
