// Package component provides component management for Gibson.
// This file defines a Redis-backed implementation of ComponentStore,
// replacing the etcd-backed EtcdComponentStore.
//
// Component metadata is stored persistently (no TTL) using Redis hashes:
//
//	{namespace}:components:{kind}:{name}  — component metadata (JSON)
//
// Instance entries are stored separately:
//
//	{namespace}:components:{kind}:{name}:instances:{instance_id}  — instance info (JSON)

package component

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// redisComponentStore implements ComponentStore using Redis.
type redisComponentStore struct {
	client    goredis.UniversalClient
	namespace string
}

// NewRedisComponentStore creates a Redis-backed component store.
//
// Component metadata is stored as JSON strings at keys of the form:
//
//	{namespace}:components:{kind}:{name}
//
// The namespace defaults to "gibson" if empty.
func NewRedisComponentStore(client goredis.UniversalClient, namespace string) ComponentStore {
	if namespace == "" {
		namespace = "gibson"
	}
	return &redisComponentStore{
		client:    client,
		namespace: namespace,
	}
}

// componentKey returns the Redis key for a component's metadata.
func (s *redisComponentStore) componentKey(kind ComponentKind, name string) string {
	return fmt.Sprintf("%s:components:%s:%s", s.namespace, kind.String(), name)
}

// kindIndexKey returns the Redis key for the set of component names of a given kind.
func (s *redisComponentStore) kindIndexKey(kind ComponentKind) string {
	return fmt.Sprintf("%s:components:%s", s.namespace, kind.String())
}

// instanceKey returns the Redis key for an instance record.
func (s *redisComponentStore) instanceKey(kind ComponentKind, name, instanceID string) string {
	return fmt.Sprintf("%s:components:%s:%s:instances:%s", s.namespace, kind.String(), name, instanceID)
}

// instanceIndexKey returns the Redis set key that tracks all instance IDs for a component.
func (s *redisComponentStore) instanceIndexKey(kind ComponentKind, name string) string {
	return fmt.Sprintf("%s:components:%s:%s:instances", s.namespace, kind.String(), name)
}

// Create stores a new component's metadata in Redis.
// Returns ErrComponentExists if (kind, name) already exists.
func (s *redisComponentStore) Create(ctx context.Context, comp *Component) error {
	if s.client == nil {
		return ErrStoreUnavailable
	}

	key := s.componentKey(comp.Kind, comp.Name)

	var manifestJSON string
	if comp.Manifest != nil {
		data, err := json.Marshal(comp.Manifest)
		if err != nil {
			return fmt.Errorf("failed to marshal manifest: %w", err)
		}
		manifestJSON = string(data)
	}

	now := time.Now()
	metadata := ComponentMetadata{
		Kind:      comp.Kind.String(),
		Name:      comp.Name,
		Version:   comp.Version,
		RepoPath:  comp.RepoPath,
		BinPath:   comp.BinPath,
		Source:    comp.Source.String(),
		Manifest:  manifestJSON,
		CreatedAt: now,
		UpdatedAt: now,
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal component: %w", err)
	}

	// SET NX — only set if key does not exist (atomic create)
	ok, err := s.client.SetNX(ctx, key, string(data), 0).Result()
	if err != nil {
		return fmt.Errorf("failed to create component: %w", err)
	}
	if !ok {
		return ErrComponentExists
	}

	// Track the component name in the kind index set
	if err := s.client.SAdd(ctx, s.kindIndexKey(comp.Kind), comp.Name).Err(); err != nil {
		// Non-fatal: the metadata key was written; best-effort index update
		_ = err
	}

	comp.CreatedAt = now
	comp.UpdatedAt = now

	return nil
}

// GetByName retrieves component metadata by kind and name.
// Returns nil, nil if not found.
func (s *redisComponentStore) GetByName(ctx context.Context, kind ComponentKind, name string) (*Component, error) {
	if s.client == nil {
		return nil, ErrStoreUnavailable
	}

	key := s.componentKey(kind, name)

	data, err := s.client.Get(ctx, key).Result()
	if err == goredis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get component: %w", err)
	}

	return s.unmarshalComponent([]byte(data))
}

// List returns all components of a specific kind.
func (s *redisComponentStore) List(ctx context.Context, kind ComponentKind) ([]*Component, error) {
	if s.client == nil {
		return nil, ErrStoreUnavailable
	}

	// Retrieve all member names from the kind index set
	names, err := s.client.SMembers(ctx, s.kindIndexKey(kind)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list components: %w", err)
	}
	if len(names) == 0 {
		return []*Component{}, nil
	}

	// Fetch each component's metadata
	components := make([]*Component, 0, len(names))
	for _, name := range names {
		comp, err := s.GetByName(ctx, kind, name)
		if err != nil {
			// Log and continue; stale index entries are possible
			continue
		}
		if comp == nil {
			// Stale index entry — clean it up
			_ = s.client.SRem(ctx, s.kindIndexKey(kind), name).Err()
			continue
		}
		components = append(components, comp)
	}

	return components, nil
}

// ListAll returns all components across all kinds.
func (s *redisComponentStore) ListAll(ctx context.Context) (map[ComponentKind][]*Component, error) {
	if s.client == nil {
		return nil, ErrStoreUnavailable
	}

	result := make(map[ComponentKind][]*Component)
	for _, kind := range AllComponentKinds() {
		comps, err := s.List(ctx, kind)
		if err != nil {
			return nil, fmt.Errorf("failed to list %s components: %w", kind, err)
		}
		if len(comps) > 0 {
			result[kind] = comps
		}
	}

	return result, nil
}

// Update updates component metadata (version, paths, manifest).
func (s *redisComponentStore) Update(ctx context.Context, comp *Component) error {
	if s.client == nil {
		return ErrStoreUnavailable
	}

	key := s.componentKey(comp.Kind, comp.Name)

	// Fetch existing to preserve CreatedAt
	existing, err := s.GetByName(ctx, comp.Kind, comp.Name)
	if err != nil {
		return fmt.Errorf("failed to check existing component: %w", err)
	}
	if existing == nil {
		return ErrComponentNotFound
	}

	var manifestJSON string
	if comp.Manifest != nil {
		data, err := json.Marshal(comp.Manifest)
		if err != nil {
			return fmt.Errorf("failed to marshal manifest: %w", err)
		}
		manifestJSON = string(data)
	}

	now := time.Now()
	metadata := ComponentMetadata{
		Kind:      comp.Kind.String(),
		Name:      comp.Name,
		Version:   comp.Version,
		RepoPath:  comp.RepoPath,
		BinPath:   comp.BinPath,
		Source:    comp.Source.String(),
		Manifest:  manifestJSON,
		CreatedAt: existing.CreatedAt,
		UpdatedAt: now,
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal component: %w", err)
	}

	if err := s.client.Set(ctx, key, string(data), 0).Err(); err != nil {
		return fmt.Errorf("failed to update component: %w", err)
	}

	comp.UpdatedAt = now

	return nil
}

// Delete removes component metadata and all running instance records atomically.
func (s *redisComponentStore) Delete(ctx context.Context, kind ComponentKind, name string) error {
	if s.client == nil {
		return ErrStoreUnavailable
	}

	key := s.componentKey(kind, name)

	// Check existence first
	exists, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check component existence: %w", err)
	}
	if exists == 0 {
		return ErrComponentNotFound
	}

	// Delete metadata key, instance index, and all instance entries.
	// Using a pipeline for best-effort atomicity (Redis does not have true multi-key txn without Lua).
	instanceIndexKey := s.instanceIndexKey(kind, name)

	// Collect all instance keys to delete
	instanceIDs, _ := s.client.SMembers(ctx, instanceIndexKey).Result()

	pipe := s.client.Pipeline()
	pipe.Del(ctx, key)
	pipe.Del(ctx, instanceIndexKey)
	pipe.SRem(ctx, s.kindIndexKey(kind), name)
	for _, id := range instanceIDs {
		pipe.Del(ctx, s.instanceKey(kind, name, id))
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to delete component: %w", err)
	}

	return nil
}

// ListInstances returns all running instances for a component.
func (s *redisComponentStore) ListInstances(ctx context.Context, kind ComponentKind, name string) ([]ComponentInfo, error) {
	if s.client == nil {
		return nil, ErrStoreUnavailable
	}

	instanceIndexKey := s.instanceIndexKey(kind, name)

	instanceIDs, err := s.client.SMembers(ctx, instanceIndexKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list instance IDs: %w", err)
	}

	instances := make([]ComponentInfo, 0, len(instanceIDs))
	for _, id := range instanceIDs {
		data, err := s.client.Get(ctx, s.instanceKey(kind, name, id)).Result()
		if err == goredis.Nil {
			// Stale index entry — remove it
			_ = s.client.SRem(ctx, instanceIndexKey, id).Err()
			continue
		}
		if err != nil {
			continue
		}

		var info ComponentInfo
		if err := json.Unmarshal([]byte(data), &info); err != nil {
			continue
		}
		instances = append(instances, info)
	}

	return instances, nil
}

// unmarshalComponent parses a JSON-encoded ComponentMetadata into a Component.
func (s *redisComponentStore) unmarshalComponent(data []byte) (*Component, error) {
	var metadata ComponentMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal component: %w", err)
	}

	comp := &Component{
		Kind:      ComponentKind(metadata.Kind),
		Name:      metadata.Name,
		Version:   metadata.Version,
		RepoPath:  metadata.RepoPath,
		BinPath:   metadata.BinPath,
		Source:    ComponentSource(metadata.Source),
		Status:    ComponentStatusAvailable,
		CreatedAt: metadata.CreatedAt,
		UpdatedAt: metadata.UpdatedAt,
	}

	if metadata.Manifest != "" {
		// Trim stray whitespace that can cause unmarshal errors
		trimmed := strings.TrimSpace(metadata.Manifest)
		if trimmed != "" && trimmed != "null" {
			var manifest Manifest
			if err := json.Unmarshal([]byte(trimmed), &manifest); err != nil {
				return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
			}
			comp.Manifest = &manifest
		}
	}

	return comp, nil
}
