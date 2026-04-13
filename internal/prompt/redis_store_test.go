package prompt

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/state"
)

// setupTestRedisStore creates a StateClient and RedisPromptStore for testing
// Requires a local Redis instance with RedisJSON module
func setupTestRedisStore(t *testing.T) (*state.StateClient, *RedisPromptStore, func()) {
	t.Helper()

	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Skipping Redis test: %v", err)
		return nil, nil, func() {}
	}

	store := NewRedisPromptStore(client)

	// Cleanup function to close client and clear test data
	cleanup := func() {
		// Clean up all test prompt keys
		ctx := context.Background()
		rdb := client.Client()
		iter := rdb.Scan(ctx, 0, "gibson:prompt:*", 0).Iterator()
		for iter.Next(ctx) {
			rdb.Del(ctx, iter.Val())
		}
		client.Close()
	}

	return client, store, cleanup
}

func TestNewRedisPromptStore(t *testing.T) {
	client, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	assert.NotNil(t, client)
	assert.NotNil(t, store)
	assert.Equal(t, "gibson:prompt:", store.keyPrefix)
	assert.Equal(t, "gibson:prompts:changes", store.pubsubChannel)
}

func TestRedisPromptStore_SaveAndGet(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Create a test prompt
	prompt := &Prompt{
		ID:       "test-prompt",
		Name:     "test-prompt",
		Position: PositionSystem,
		Content:  "This is a test prompt with {{.variable}}",
		Variables: []VariableDef{
			{Name: "variable", Required: true},
		},
		Priority: 10,
	}

	// Test Save
	err := store.Save(ctx, prompt)
	require.NoError(t, err)

	// Test Get
	retrieved, err := store.Get(ctx, "test-prompt")
	require.NoError(t, err)
	require.NotNil(t, retrieved)

	assert.Equal(t, prompt.ID, retrieved.ID)
	assert.Equal(t, prompt.Name, retrieved.Name)
	assert.Equal(t, prompt.Position, retrieved.Position)
	assert.Equal(t, prompt.Content, retrieved.Content)
	assert.Equal(t, prompt.Priority, retrieved.Priority)
	assert.Len(t, retrieved.Variables, 1)
	assert.Equal(t, "variable", retrieved.Variables[0].Name)
}

func TestRedisPromptStore_SaveUsesIDWhenNameEmpty(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Create a prompt with ID but no Name
	prompt := &Prompt{
		ID:       "id-only-prompt",
		Position: PositionSystem,
		Content:  "Test content",
	}

	err := store.Save(ctx, prompt)
	require.NoError(t, err)

	// Should be retrievable by ID
	retrieved, err := store.Get(ctx, "id-only-prompt")
	require.NoError(t, err)
	assert.Equal(t, "id-only-prompt", retrieved.ID)
}

func TestRedisPromptStore_SaveValidation(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name        string
		prompt      *Prompt
		expectError bool
	}{
		{
			name:        "nil prompt",
			prompt:      nil,
			expectError: true,
		},
		{
			name: "empty ID",
			prompt: &Prompt{
				Position: PositionSystem,
				Content:  "Test",
			},
			expectError: true,
		},
		{
			name: "invalid position",
			prompt: &Prompt{
				ID:       "test",
				Position: Position("invalid"),
				Content:  "Test",
			},
			expectError: true,
		},
		{
			name: "empty content",
			prompt: &Prompt{
				ID:       "test",
				Position: PositionSystem,
				Content:  "",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Save(ctx, tt.prompt)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRedisPromptStore_GetNotFound(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	_, err := store.Get(ctx, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRedisPromptStore_GetEmptyName(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	_, err := store.Get(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestRedisPromptStore_List(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Create multiple test prompts
	prompts := []*Prompt{
		{
			ID:       "prompt1",
			Name:     "prompt1",
			Position: PositionSystem,
			Content:  "Prompt 1 content",
			Priority: 10,
		},
		{
			ID:       "prompt2",
			Name:     "prompt2",
			Position: PositionUser,
			Content:  "Prompt 2 content",
			Priority: 20,
		},
		{
			ID:       "prompt3",
			Name:     "prompt3",
			Position: PositionContext,
			Content:  "Prompt 3 content",
			Priority: 15,
		},
	}

	// Save all prompts
	for _, p := range prompts {
		err := store.Save(ctx, p)
		require.NoError(t, err)
	}

	// List all prompts
	retrieved, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, retrieved, 3)

	// Verify all prompts are present
	ids := make(map[string]bool)
	for _, p := range retrieved {
		ids[p.ID] = true
	}
	assert.True(t, ids["prompt1"])
	assert.True(t, ids["prompt2"])
	assert.True(t, ids["prompt3"])
}

func TestRedisPromptStore_ListEmpty(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// List when no prompts exist
	prompts, err := store.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, prompts)
}

func TestRedisPromptStore_Delete(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Create and save a prompt
	prompt := &Prompt{
		ID:       "to-delete",
		Name:     "to-delete",
		Position: PositionSystem,
		Content:  "Will be deleted",
	}

	err := store.Save(ctx, prompt)
	require.NoError(t, err)

	// Verify it exists
	exists, err := store.Exists(ctx, "to-delete")
	require.NoError(t, err)
	assert.True(t, exists)

	// Delete it
	err = store.Delete(ctx, "to-delete")
	require.NoError(t, err)

	// Verify it no longer exists
	exists, err = store.Exists(ctx, "to-delete")
	require.NoError(t, err)
	assert.False(t, exists)

	// Get should return not found
	_, err = store.Get(ctx, "to-delete")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRedisPromptStore_DeleteNotFound(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	err := store.Delete(ctx, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRedisPromptStore_DeleteEmptyName(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	err := store.Delete(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestRedisPromptStore_Exists(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Check non-existent prompt
	exists, err := store.Exists(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, exists)

	// Create and save a prompt
	prompt := &Prompt{
		ID:       "exists-test",
		Name:     "exists-test",
		Position: PositionSystem,
		Content:  "Exists test",
	}

	err = store.Save(ctx, prompt)
	require.NoError(t, err)

	// Check existing prompt
	exists, err = store.Exists(ctx, "exists-test")
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestRedisPromptStore_ExistsEmptyName(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	_, err := store.Exists(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestRedisPromptStore_Watch(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start watching for changes
	eventCh, err := store.Watch(ctx)
	require.NoError(t, err)
	require.NotNil(t, eventCh)

	// Give the subscription time to establish
	time.Sleep(100 * time.Millisecond)

	// Save a prompt in a separate goroutine
	go func() {
		time.Sleep(100 * time.Millisecond)
		prompt := &Prompt{
			ID:       "watch-test",
			Name:     "watch-test",
			Position: PositionSystem,
			Content:  "Watch test",
		}
		store.Save(context.Background(), prompt)
	}()

	// Wait for update event
	select {
	case event := <-eventCh:
		assert.Equal(t, ChangeTypeUpdate, event.Type)
		assert.Equal(t, "watch-test", event.Name)
		assert.False(t, event.Timestamp.IsZero())
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for update event")
	}

	// Delete the prompt
	go func() {
		time.Sleep(100 * time.Millisecond)
		store.Delete(context.Background(), "watch-test")
	}()

	// Wait for delete event
	select {
	case event := <-eventCh:
		assert.Equal(t, ChangeTypeDelete, event.Type)
		assert.Equal(t, "watch-test", event.Name)
		assert.False(t, event.Timestamp.IsZero())
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for delete event")
	}
}

func TestRedisPromptStore_WatchContextCancellation(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())

	// Start watching
	eventCh, err := store.Watch(ctx)
	require.NoError(t, err)
	require.NotNil(t, eventCh)

	// Give the subscription time to establish
	time.Sleep(100 * time.Millisecond)

	// Cancel the context
	cancel()

	// Channel should be closed
	select {
	case _, ok := <-eventCh:
		assert.False(t, ok, "Event channel should be closed")
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for channel to close")
	}
}

func TestRedisPromptStore_BuildKey(t *testing.T) {
	store := &RedisPromptStore{
		keyPrefix: "gibson:prompt:",
	}

	tests := []struct {
		name     string
		expected string
	}{
		{"test", "gibson:prompt:test"},
		{"my-prompt", "gibson:prompt:my-prompt"},
		{"", "gibson:prompt:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := store.buildKey(tt.name)
			assert.Equal(t, tt.expected, key)
		})
	}
}

func TestRedisPromptStore_ExtractNameFromKey(t *testing.T) {
	store := &RedisPromptStore{
		keyPrefix: "gibson:prompt:",
	}

	tests := []struct {
		key      string
		expected string
	}{
		{"gibson:prompt:test", "test"},
		{"gibson:prompt:my-prompt", "my-prompt"},
		{"gibson:prompt:", ""},
		{"other:key", "other:key"}, // No prefix match
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			name := store.extractNameFromKey(tt.key)
			assert.Equal(t, tt.expected, name)
		})
	}
}

func TestRedisPromptStore_MultipleUpdates(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Create initial prompt
	prompt := &Prompt{
		ID:       "update-test",
		Name:     "update-test",
		Position: PositionSystem,
		Content:  "Version 1",
		Priority: 10,
	}

	err := store.Save(ctx, prompt)
	require.NoError(t, err)

	// Update the prompt
	prompt.Content = "Version 2"
	prompt.Priority = 20

	err = store.Save(ctx, prompt)
	require.NoError(t, err)

	// Retrieve and verify
	retrieved, err := store.Get(ctx, "update-test")
	require.NoError(t, err)
	assert.Equal(t, "Version 2", retrieved.Content)
	assert.Equal(t, 20, retrieved.Priority)
}

func TestRedisPromptStore_ComplexPromptData(t *testing.T) {
	_, store, cleanup := setupTestRedisStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	ctx := context.Background()

	// Create a prompt with all fields populated
	prompt := &Prompt{
		ID:          "complex-prompt",
		Name:        "complex-prompt",
		Description: "A complex prompt with all features",
		Position:    PositionSystem,
		Content:     "Hello {{.name}}, you are {{.age}} years old",
		Variables: []VariableDef{
			{Name: "name", Required: true},
			{Name: "age", Required: false},
		},
		Conditions: []Condition{
			{Field: "env", Operator: "eq", Value: "production"},
		},
		Examples: []Example{
			{
				Input:  `{"name": "Alice", "age": 30}`,
				Output: "Hello Alice, you are 30 years old",
			},
		},
		Priority: 100,
		Metadata: map[string]any{
			"author":  "test",
			"version": "1.0",
			"tags":    []string{"system", "greeting"},
		},
	}

	err := store.Save(ctx, prompt)
	require.NoError(t, err)

	// Retrieve and verify all fields
	retrieved, err := store.Get(ctx, "complex-prompt")
	require.NoError(t, err)

	assert.Equal(t, prompt.ID, retrieved.ID)
	assert.Equal(t, prompt.Name, retrieved.Name)
	assert.Equal(t, prompt.Description, retrieved.Description)
	assert.Equal(t, prompt.Position, retrieved.Position)
	assert.Equal(t, prompt.Content, retrieved.Content)
	assert.Len(t, retrieved.Variables, 2)
	assert.Len(t, retrieved.Conditions, 1)
	assert.Len(t, retrieved.Examples, 1)
	assert.Equal(t, prompt.Priority, retrieved.Priority)
	assert.NotNil(t, retrieved.Metadata)
	assert.Equal(t, "test", retrieved.Metadata["author"])
	assert.Equal(t, "1.0", retrieved.Metadata["version"])
}
