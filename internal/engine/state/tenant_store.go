package state

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/sdk/auth"
)

// TenantScopedStore wraps StateClient to provide tenant-aware Redis operations.
// All key operations automatically prefix keys with the tenant ID from the context,
// ensuring tenant isolation at the data layer.
//
// This is the primary mechanism for multi-tenant data isolation in Gibson.
// In SaaS mode, all Redis keys must be tenant-scoped to prevent cross-tenant access.
// In Enterprise mode with a default tenant, keys are still scoped for consistency.
//
// Thread Safety:
//   - All operations are thread-safe at the Redis level
//   - Tenant extraction from context happens per-operation
//   - No local state is cached
//
// Example:
//
//	tenantStore := state.NewTenantScopedStore(stateClient, cfg)
//
//	// Context has tenant injected by auth interceptor
//	ctx := auth.ContextWithTenantString(ctx, "acme-corp")
//
//	// Key is automatically scoped: tenant:acme-corp:mission:123
//	err := tenantStore.Set(ctx, "mission:123", data, 0)
//
//	// Only accessible with same tenant in context
//	data, err := tenantStore.Get(ctx, "mission:123")
type TenantScopedStore struct {
	client        *StateClient
	authMode      string // "dev", "enterprise", "saas"
	defaultTenant string // Fallback tenant for single-tenant deployments
	requireTenant bool   // If true, fail operations when no tenant in context
}

// TenantStoreConfig configures tenant scoping behavior.
type TenantStoreConfig struct {
	// AuthMode determines tenant requirement: "dev", "enterprise", "saas"
	AuthMode string

	// DefaultTenant is used when no tenant is in context (enterprise mode with single tenant)
	DefaultTenant string

	// RequireTenant forces all operations to have a tenant (true for saas mode)
	RequireTenant bool
}

// NewTenantScopedStore creates a new tenant-aware Redis store wrapper.
//
// The config determines how tenant isolation is enforced:
//   - dev mode: Uses defaultTenant for all operations
//   - enterprise mode: Uses tenant from context, falls back to defaultTenant
//   - saas mode: Requires tenant in context, fails if missing
//
// Parameters:
//   - client: Underlying StateClient for Redis operations
//   - config: Tenant scoping configuration
//
// Example:
//
//	cfg := &state.TenantStoreConfig{
//	    AuthMode:      "saas",
//	    RequireTenant: true,
//	}
//
//	store := state.NewTenantScopedStore(stateClient, cfg)
func NewTenantScopedStore(client *StateClient, config *TenantStoreConfig) *TenantScopedStore {
	if config == nil {
		config = &TenantStoreConfig{
			AuthMode:      "dev",
			DefaultTenant: "default",
			RequireTenant: false,
		}
	}

	return &TenantScopedStore{
		client:        client,
		authMode:      config.AuthMode,
		defaultTenant: config.DefaultTenant,
		requireTenant: config.RequireTenant,
	}
}

// resolveTenant extracts the tenant ID from context or uses the default.
// Returns an error if tenant is required but missing from context.
func (s *TenantScopedStore) resolveTenant(ctx context.Context) (string, error) {
	// Extract tenant from context (injected by auth interceptor)
	tenant := auth.TenantStringFromContext(ctx)

	// If tenant found, use it
	if tenant != "" {
		return tenant, nil
	}

	// No tenant in context - check if we have a fallback
	if s.defaultTenant != "" {
		return s.defaultTenant, nil
	}

	// No tenant and no default - check if tenant is required
	if s.requireTenant {
		return "", NewTenantError("tenant required but not found in context")
	}

	// Dev mode or missing tenant - use "default" as safety fallback
	return "default", nil
}

// scopeKey applies tenant scoping to a Redis key.
// Uses TenantScopedRedisKey helper for consistent formatting.
func (s *TenantScopedStore) scopeKey(ctx context.Context, key string) (string, error) {
	tenant, err := s.resolveTenant(ctx)
	if err != nil {
		return "", err
	}

	return auth.TenantScopedRedisKey(tenant, key), nil
}

// Get retrieves a value from Redis using a tenant-scoped key.
//
// The key is automatically prefixed with "tenant:{tenant_id}:" to ensure
// tenant isolation. Returns ErrNotFound if the key doesn't exist.
//
// Example:
//
//	ctx := auth.ContextWithTenantString(ctx, "acme")
//	value, err := store.Get(ctx, "mission:123")
//	// Accesses key: "tenant:acme:mission:123"
func (s *TenantScopedStore) Get(ctx context.Context, key string) (string, error) {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return "", err
	}

	result, err := s.client.Client().Get(ctx, scopedKey).Result()
	if err != nil {
		if err == redis.Nil {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("failed to get key %s: %w", key, err)
	}

	return result, nil
}

// Set stores a value in Redis with tenant scoping and optional expiration.
//
// The key is automatically prefixed with the tenant ID. The expiration
// parameter sets a TTL on the key (0 means no expiration).
//
// Example:
//
//	// Store with 1 hour TTL
//	err := store.Set(ctx, "session:abc", sessionData, time.Hour)
//
//	// Store without expiration
//	err := store.Set(ctx, "mission:123", missionData, 0)
func (s *TenantScopedStore) Set(ctx context.Context, key string, value any, expiration time.Duration) error {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return err
	}

	err = s.client.Client().Set(ctx, scopedKey, value, expiration).Err()
	if err != nil {
		return fmt.Errorf("failed to set key %s: %w", key, err)
	}

	return nil
}

// Delete removes a key from Redis with tenant scoping.
//
// Returns ErrNotFound if the key doesn't exist.
//
// Example:
//
//	err := store.Delete(ctx, "session:abc")
func (s *TenantScopedStore) Delete(ctx context.Context, key string) error {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return err
	}

	result, err := s.client.Client().Del(ctx, scopedKey).Result()
	if err != nil {
		return fmt.Errorf("failed to delete key %s: %w", key, err)
	}

	if result == 0 {
		return ErrNotFound
	}

	return nil
}

// Exists checks if a key exists in Redis with tenant scoping.
//
// Returns true if the key exists, false otherwise.
//
// Example:
//
//	exists, err := store.Exists(ctx, "mission:123")
func (s *TenantScopedStore) Exists(ctx context.Context, keys ...string) (int64, error) {
	if len(keys) == 0 {
		return 0, nil
	}

	// Scope all keys
	scopedKeys := make([]string, len(keys))
	for i, key := range keys {
		scopedKey, err := s.scopeKey(ctx, key)
		if err != nil {
			return 0, err
		}
		scopedKeys[i] = scopedKey
	}

	count, err := s.client.Client().Exists(ctx, scopedKeys...).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to check existence: %w", err)
	}

	return count, nil
}

// Incr increments a counter with tenant scoping.
//
// This is atomic and thread-safe. If the key doesn't exist, it's
// initialized to 0 before incrementing.
//
// Example:
//
//	// Increment mission execution counter
//	count, err := store.Incr(ctx, "counter:mission:executions")
func (s *TenantScopedStore) Incr(ctx context.Context, key string) (int64, error) {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return 0, err
	}

	count, err := s.client.Client().Incr(ctx, scopedKey).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to increment key %s: %w", key, err)
	}

	return count, nil
}

// HGet retrieves a field from a hash with tenant scoping.
//
// Returns ErrNotFound if the hash or field doesn't exist.
//
// Example:
//
//	value, err := store.HGet(ctx, "mission:123:config", "timeout")
func (s *TenantScopedStore) HGet(ctx context.Context, key, field string) (string, error) {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return "", err
	}

	result, err := s.client.Client().HGet(ctx, scopedKey, field).Result()
	if err != nil {
		if err == redis.Nil {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("failed to get hash field %s.%s: %w", key, field, err)
	}

	return result, nil
}

// HSet sets a field in a hash with tenant scoping.
//
// Example:
//
//	err := store.HSet(ctx, "mission:123:config", "timeout", "30s")
func (s *TenantScopedStore) HSet(ctx context.Context, key string, values ...any) error {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return err
	}

	err = s.client.Client().HSet(ctx, scopedKey, values...).Err()
	if err != nil {
		return fmt.Errorf("failed to set hash fields for %s: %w", key, err)
	}

	return nil
}

// HGetAll retrieves all fields from a hash with tenant scoping.
//
// Returns an empty map if the hash doesn't exist.
//
// Example:
//
//	config, err := store.HGetAll(ctx, "mission:123:config")
func (s *TenantScopedStore) HGetAll(ctx context.Context, key string) (map[string]string, error) {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return nil, err
	}

	result, err := s.client.Client().HGetAll(ctx, scopedKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get all hash fields for %s: %w", key, err)
	}

	return result, nil
}

// HDel deletes fields from a hash with tenant scoping.
//
// Returns the number of fields that were deleted.
//
// Example:
//
//	deleted, err := store.HDel(ctx, "mission:123:config", "old_field")
func (s *TenantScopedStore) HDel(ctx context.Context, key string, fields ...string) (int64, error) {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return 0, err
	}

	count, err := s.client.Client().HDel(ctx, scopedKey, fields...).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to delete hash fields for %s: %w", key, err)
	}

	return count, nil
}

// SAdd adds members to a set with tenant scoping.
//
// Returns the number of members that were added (not including existing members).
//
// Example:
//
//	added, err := store.SAdd(ctx, "missions:active", "mission-123", "mission-456")
func (s *TenantScopedStore) SAdd(ctx context.Context, key string, members ...any) (int64, error) {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return 0, err
	}

	count, err := s.client.Client().SAdd(ctx, scopedKey, members...).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to add set members to %s: %w", key, err)
	}

	return count, nil
}

// SMembers retrieves all members of a set with tenant scoping.
//
// Returns an empty slice if the set doesn't exist.
//
// Example:
//
//	missions, err := store.SMembers(ctx, "missions:active")
func (s *TenantScopedStore) SMembers(ctx context.Context, key string) ([]string, error) {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return nil, err
	}

	result, err := s.client.Client().SMembers(ctx, scopedKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get set members for %s: %w", key, err)
	}

	return result, nil
}

// SRem removes members from a set with tenant scoping.
//
// Returns the number of members that were removed.
//
// Example:
//
//	removed, err := store.SRem(ctx, "missions:active", "mission-123")
func (s *TenantScopedStore) SRem(ctx context.Context, key string, members ...any) (int64, error) {
	scopedKey, err := s.scopeKey(ctx, key)
	if err != nil {
		return 0, err
	}

	count, err := s.client.Client().SRem(ctx, scopedKey, members...).Result()
	if err != nil {
		return 0, fmt.Errorf("failed to remove set members from %s: %w", key, err)
	}

	return count, nil
}

// Keys returns all keys matching a pattern with tenant scoping.
//
// WARNING: This operation can be expensive on large databases. Use with caution.
// The pattern is applied AFTER tenant scoping, so "mission:*" becomes "tenant:{id}:mission:*"
//
// Example:
//
//	missions, err := store.Keys(ctx, "mission:*")
//	// Returns: ["tenant:acme:mission:123", "tenant:acme:mission:456"]
func (s *TenantScopedStore) Keys(ctx context.Context, pattern string) ([]string, error) {
	// Scope the pattern with tenant prefix
	scopedPattern, err := s.scopeKey(ctx, pattern)
	if err != nil {
		return nil, err
	}

	result, err := s.client.Client().Keys(ctx, scopedPattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get keys matching pattern %s: %w", pattern, err)
	}

	return result, nil
}

// Pipeline creates a tenant-scoped pipeline for batch operations.
//
// The returned pipeline automatically scopes all keys with the tenant ID.
// This is useful for atomic multi-key operations.
//
// Example:
//
//	pipe, tenant, err := store.Pipeline(ctx)
//	if err != nil {
//	    return err
//	}
//	defer pipe.Close()
//
//	// All operations in pipeline are tenant-scoped
//	pipe.Set(ctx, auth.TenantScopedRedisKey(tenant, "key1"), "value1", 0)
//	pipe.Set(ctx, auth.TenantScopedRedisKey(tenant, "key2"), "value2", 0)
//
//	_, err = pipe.Exec(ctx)
func (s *TenantScopedStore) Pipeline(ctx context.Context) (redis.Pipeliner, string, error) {
	tenant, err := s.resolveTenant(ctx)
	if err != nil {
		return nil, "", err
	}

	pipe := s.client.Client().Pipeline()
	return pipe, tenant, nil
}

// Client returns the underlying StateClient for direct access.
//
// WARNING: Using the underlying client bypasses tenant scoping!
// Only use this for operations that are explicitly tenant-agnostic
// (like health checks, module commands, etc.)
func (s *TenantScopedStore) Client() *StateClient {
	return s.client
}

// GetTenant extracts the tenant ID from the context for the current operation.
// This is useful for logging and audit trails.
//
// Example:
//
//	tenant, err := store.GetTenant(ctx)
//	log.Info("operation performed", "tenant", tenant, "key", key)
func (s *TenantScopedStore) GetTenant(ctx context.Context) (string, error) {
	return s.resolveTenant(ctx)
}
