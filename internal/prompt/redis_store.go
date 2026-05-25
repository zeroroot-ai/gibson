package prompt

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/state"
)

// ChangeType represents the type of change event for prompt updates
type ChangeType string

const (
	// ChangeTypeUpdate indicates a prompt was created or updated
	ChangeTypeUpdate ChangeType = "update"
	// ChangeTypeDelete indicates a prompt was deleted
	ChangeTypeDelete ChangeType = "delete"
)

// PromptChangeEvent represents a notification of a prompt change
type PromptChangeEvent struct {
	Type      ChangeType `json:"type"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Timestamp time.Time  `json:"timestamp"`
}

// PromptStore defines the interface for storing and retrieving prompts from Redis
type PromptStore interface {
	// Save stores a prompt in Redis using JSON.SET
	Save(ctx context.Context, prompt *Prompt) error

	// Get retrieves a prompt by name using JSON.GET
	Get(ctx context.Context, name string) (*Prompt, error)

	// List returns all prompts using SCAN pattern matching
	List(ctx context.Context) ([]*Prompt, error)

	// Delete removes a prompt using JSON.DEL
	Delete(ctx context.Context, name string) error

	// Exists checks if a prompt exists using EXISTS
	Exists(ctx context.Context, name string) (bool, error)

	// Watch subscribes to prompt change events and returns a channel
	Watch(ctx context.Context) (<-chan PromptChangeEvent, error)
}

// RedisPromptStore is a Redis-backed implementation of PromptStore
type RedisPromptStore struct {
	client        *state.StateClient
	keyPrefix     string
	pubsubChannel string
}

// NewRedisPromptStore creates a new RedisPromptStore
func NewRedisPromptStore(client *state.StateClient) *RedisPromptStore {
	return &RedisPromptStore{
		client:        client,
		keyPrefix:     "gibson:prompt:",
		pubsubChannel: "gibson:prompts:changes",
	}
}

// buildKey constructs the Redis key for a prompt name
func (s *RedisPromptStore) buildKey(name string) string {
	return s.keyPrefix + name
}

// extractNameFromKey extracts the prompt name from a Redis key
func (s *RedisPromptStore) extractNameFromKey(key string) string {
	return strings.TrimPrefix(key, s.keyPrefix)
}

// Save stores a prompt in Redis and publishes an update event
func (s *RedisPromptStore) Save(ctx context.Context, prompt *Prompt) error {
	if prompt == nil {
		return fmt.Errorf("prompt cannot be nil")
	}

	// Validate prompt before saving
	if err := prompt.Validate(); err != nil {
		return fmt.Errorf("prompt validation failed: %w", err)
	}

	// Use ID as the key name if Name is empty
	name := prompt.Name
	if name == "" {
		name = prompt.ID
	}

	key := s.buildKey(name)

	// Store the prompt using JSONSet
	if err := s.client.JSONSet(ctx, key, "$", prompt); err != nil {
		return fmt.Errorf("failed to save prompt %q: %w", name, err)
	}

	// Publish change event
	event := PromptChangeEvent{
		Type:      ChangeTypeUpdate,
		Name:      name,
		Version:   "", // Version can be added in the future
		Timestamp: time.Now(),
	}

	if err := s.publishEvent(ctx, event); err != nil {
		// Log error but don't fail the save operation
		// The prompt is already saved, just the notification failed
		return fmt.Errorf("prompt saved but notification failed: %w", err)
	}

	return nil
}

// Get retrieves a prompt by name from Redis
func (s *RedisPromptStore) Get(ctx context.Context, name string) (*Prompt, error) {
	if name == "" {
		return nil, fmt.Errorf("prompt name cannot be empty")
	}

	key := s.buildKey(name)

	var prompt Prompt
	if err := s.client.JSONGet(ctx, key, "$", &prompt); err != nil {
		if err == state.ErrNotFound {
			return nil, NewPromptNotFoundError(name)
		}
		return nil, fmt.Errorf("failed to get prompt %q: %w", name, err)
	}

	return &prompt, nil
}

// List returns all prompts by scanning for keys matching the pattern
func (s *RedisPromptStore) List(ctx context.Context) ([]*Prompt, error) {
	pattern := s.keyPrefix + "*"
	rdb := s.client.Client()

	// Use SCAN to iterate through all matching keys
	var keys []string
	iter := rdb.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan prompt keys: %w", err)
	}

	// No prompts found
	if len(keys) == 0 {
		return []*Prompt{}, nil
	}

	// Retrieve all prompts using JSON.MGET for efficiency
	paths := make([]string, len(keys))
	for i := range keys {
		paths[i] = "$"
	}

	results, err := s.client.JSONMGet(ctx, keys, "$")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve prompts: %w", err)
	}

	// Parse results into Prompt objects
	prompts := make([]*Prompt, 0, len(results))
	for i, raw := range results {
		if raw == nil {
			continue // Skip deleted or missing keys
		}

		// JSONMGet with path "$" wraps each result in a JSON array.
		var wrapped []Prompt
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			return nil, fmt.Errorf("failed to unmarshal prompt from key %q: %w", keys[i], err)
		}
		if len(wrapped) == 0 {
			continue
		}
		p := wrapped[0]
		prompts = append(prompts, &p)
	}

	return prompts, nil
}

// Delete removes a prompt from Redis and publishes a delete event
func (s *RedisPromptStore) Delete(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("prompt name cannot be empty")
	}

	key := s.buildKey(name)

	// Check if the prompt exists before deleting
	exists, err := s.Exists(ctx, name)
	if err != nil {
		return err
	}
	if !exists {
		return NewPromptNotFoundError(name)
	}

	// Delete the prompt using JSONDel
	if err := s.client.JSONDel(ctx, key, "$"); err != nil {
		return fmt.Errorf("failed to delete prompt %q: %w", name, err)
	}

	// Publish delete event
	event := PromptChangeEvent{
		Type:      ChangeTypeDelete,
		Name:      name,
		Version:   "",
		Timestamp: time.Now(),
	}

	if err := s.publishEvent(ctx, event); err != nil {
		// Log error but don't fail the delete operation
		return fmt.Errorf("prompt deleted but notification failed: %w", err)
	}

	return nil
}

// Exists checks if a prompt exists in Redis
func (s *RedisPromptStore) Exists(ctx context.Context, name string) (bool, error) {
	if name == "" {
		return false, fmt.Errorf("prompt name cannot be empty")
	}

	key := s.buildKey(name)
	rdb := s.client.Client()

	result := rdb.Exists(ctx, key)
	if err := result.Err(); err != nil {
		return false, fmt.Errorf("failed to check prompt existence: %w", err)
	}

	return result.Val() > 0, nil
}

// Watch subscribes to prompt change events and returns a channel that receives events
func (s *RedisPromptStore) Watch(ctx context.Context) (<-chan PromptChangeEvent, error) {
	rdb := s.client.Client()

	// Subscribe to the changes channel
	pubsub := rdb.Subscribe(ctx, s.pubsubChannel)

	// Wait for subscription confirmation
	_, err := pubsub.Receive(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to prompt changes: %w", err)
	}

	// Create output channel for events
	eventCh := make(chan PromptChangeEvent, 10)

	// Start goroutine to read from pubsub and send to event channel
	go func() {
		defer close(eventCh)
		defer pubsub.Close()

		ch := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}

				// Parse the message payload into a PromptChangeEvent
				var event PromptChangeEvent
				if err := json.Unmarshal([]byte(msg.Payload), &event); err != nil {
					// Skip malformed events
					continue
				}

				// Send event to output channel (non-blocking)
				select {
				case eventCh <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return eventCh, nil
}

// publishEvent publishes a change event to the pubsub channel
func (s *RedisPromptStore) publishEvent(ctx context.Context, event PromptChangeEvent) error {
	rdb := s.client.Client()

	// Marshal event to JSON
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	// Publish to channel
	result := rdb.Publish(ctx, s.pubsubChannel, string(data))
	if err := result.Err(); err != nil {
		return fmt.Errorf("failed to publish event: %w", err)
	}

	return nil
}
