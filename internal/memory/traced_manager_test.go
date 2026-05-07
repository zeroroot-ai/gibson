package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestTracedMemoryManager_Working verifies that working memory operations create spans.
func TestTracedMemoryManager_Working(t *testing.T) {
	// Create mock memory manager
	missionID := types.NewID()
	innerWorking := NewWorkingMemory(1000)

	// Create a simple mock manager
	innerManager := &mockMemoryManager{
		missionID: missionID,
		working:   innerWorking,
	}

	// Create traced manager with noop tracer (for now)
	tracer := noop.NewTracerProvider().Tracer("test")
	tracedManager := NewTracedMemoryManager(innerManager, tracer)

	// Test working memory operations
	working := tracedManager.Working()
	require.NotNil(t, working)

	// Set a value
	err := working.Set("test-key", "test-value")
	require.NoError(t, err)

	// Get the value
	val, found := working.Get("test-key")
	assert.True(t, found)
	assert.Equal(t, "test-value", val)

	// List keys
	keys := working.List()
	assert.Contains(t, keys, "test-key")

	// Delete the value
	deleted := working.Delete("test-key")
	assert.True(t, deleted)

	// Clear
	working.Clear()
	keys = working.List()
	assert.Empty(t, keys)

	// Token count (pass-through)
	assert.Equal(t, 0, working.TokenCount())
	assert.Equal(t, 1000, working.MaxTokens())
}

// TestTracedMemoryManager_Mission verifies that mission memory operations create spans.
func TestTracedMemoryManager_Mission(t *testing.T) {
	// Create mock memory manager
	missionID := types.NewID()
	innerMission := &mockMissionMemory{
		missionID: missionID,
		storage:   make(map[string]*MemoryItem),
	}

	innerManager := &mockMemoryManager{
		missionID: missionID,
		mission:   innerMission,
	}

	// Create traced manager
	tracer := noop.NewTracerProvider().Tracer("test")
	tracedManager := NewTracedMemoryManager(innerManager, tracer)

	// Test mission memory operations
	mission := tracedManager.Mission()
	require.NotNil(t, mission)

	ctx := context.Background()

	// Store a value
	err := mission.Store(ctx, "mission-key", "mission-value", map[string]any{"tag": "test"})
	require.NoError(t, err)

	// Retrieve the value
	item, err := mission.Retrieve(ctx, "mission-key")
	require.NoError(t, err)
	assert.Equal(t, "mission-key", item.Key)
	assert.Equal(t, "mission-value", item.Value)

	// Keys
	keys, err := mission.Keys(ctx)
	require.NoError(t, err)
	assert.Contains(t, keys, "mission-key")

	// Search (mock returns empty)
	results, err := mission.Search(ctx, "mission", 10)
	require.NoError(t, err)
	assert.NotNil(t, results)

	// History (mock returns empty)
	items, err := mission.History(ctx, 10)
	require.NoError(t, err)
	assert.NotNil(t, items)

	// Delete
	err = mission.Delete(ctx, "mission-key")
	require.NoError(t, err)

	// MissionID (pass-through)
	assert.Equal(t, missionID, mission.MissionID())
}

// TestTracedMemoryManager_LongTerm verifies that long-term memory operations create spans.
func TestTracedMemoryManager_LongTerm(t *testing.T) {
	// Create mock memory manager
	missionID := types.NewID()
	innerLongTerm := &mockLongTermMemory{
		storage: make(map[string]*MemoryItem),
	}

	innerManager := &mockMemoryManager{
		missionID: missionID,
		longTerm:  innerLongTerm,
	}

	// Create traced manager
	tracer := noop.NewTracerProvider().Tracer("test")
	tracedManager := NewTracedMemoryManager(innerManager, tracer)

	// Test long-term memory operations
	longTerm := tracedManager.LongTerm()
	require.NotNil(t, longTerm)

	ctx := context.Background()

	// Store content
	err := longTerm.Store(ctx, "doc-1", "This is test content", map[string]any{"type": "test"})
	require.NoError(t, err)

	// Search
	results, err := longTerm.Search(ctx, "test content", 5, nil)
	require.NoError(t, err)
	assert.NotNil(t, results)

	// Similar findings
	findings, err := longTerm.SimilarFindings(ctx, "test content", 5)
	require.NoError(t, err)
	assert.NotNil(t, findings)

	// Similar patterns
	patterns, err := longTerm.SimilarPatterns(ctx, "test pattern", 5)
	require.NoError(t, err)
	assert.NotNil(t, patterns)

	// Delete
	err = longTerm.Delete(ctx, "doc-1")
	require.NoError(t, err)

	// Health
	health := longTerm.Health(ctx)
	assert.NotEmpty(t, health.State.String())
}

// TestTracedMemoryManager_Close verifies that Close creates a span.
func TestTracedMemoryManager_Close(t *testing.T) {
	// Create mock memory manager
	missionID := types.NewID()
	innerManager := &mockMemoryManager{
		missionID: missionID,
		working:   NewWorkingMemory(1000),
	}

	// Create traced manager
	tracer := noop.NewTracerProvider().Tracer("test")
	tracedManager := NewTracedMemoryManager(innerManager, tracer)

	// Close
	err := tracedManager.Close()
	require.NoError(t, err)

	// Verify idempotent
	err = tracedManager.Close()
	require.NoError(t, err)
}

// Mock implementations for testing

type mockMemoryManager struct {
	missionID types.ID
	working   WorkingMemory
	mission   MissionMemory
	longTerm  LongTermMemory
	closed    bool
}

func (m *mockMemoryManager) Working() WorkingMemory {
	return m.working
}

func (m *mockMemoryManager) Mission() MissionMemory {
	return m.mission
}

func (m *mockMemoryManager) LongTerm() LongTermMemory {
	return m.longTerm
}

func (m *mockMemoryManager) MissionID() types.ID {
	return m.missionID
}

func (m *mockMemoryManager) Close() error {
	if m.closed {
		return nil
	}
	m.closed = true
	if m.working != nil {
		m.working.Clear()
	}
	return nil
}

type mockMissionMemory struct {
	missionID types.ID
	storage   map[string]*MemoryItem
}

func (m *mockMissionMemory) Store(ctx context.Context, key string, value any, metadata map[string]any) error {
	m.storage[key] = &MemoryItem{
		Key:      key,
		Value:    value,
		Metadata: metadata,
	}
	return nil
}

func (m *mockMissionMemory) Retrieve(ctx context.Context, key string) (*MemoryItem, error) {
	item, ok := m.storage[key]
	if !ok {
		return nil, NewMissionMemoryNotFoundError(key)
	}
	return item, nil
}

func (m *mockMissionMemory) Delete(ctx context.Context, key string) error {
	delete(m.storage, key)
	return nil
}

func (m *mockMissionMemory) Search(ctx context.Context, query string, limit int) ([]MemoryResult, error) {
	return []MemoryResult{}, nil
}

func (m *mockMissionMemory) History(ctx context.Context, limit int) ([]MemoryItem, error) {
	return []MemoryItem{}, nil
}

func (m *mockMissionMemory) Keys(ctx context.Context) ([]string, error) {
	keys := make([]string, 0, len(m.storage))
	for k := range m.storage {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockMissionMemory) MissionID() types.ID {
	return m.missionID
}

func (m *mockMissionMemory) ContinuityMode() MemoryContinuityMode {
	return MemoryIsolated
}

func (m *mockMissionMemory) GetPreviousRunValue(ctx context.Context, key string) (any, error) {
	return nil, ErrContinuityNotSupported
}

func (m *mockMissionMemory) GetValueHistory(ctx context.Context, key string) ([]HistoricalValue, error) {
	return []HistoricalValue{}, nil
}

func (m *mockMissionMemory) GetAll(_ context.Context) (map[string]any, error) {
	result := make(map[string]any)
	for k, item := range m.storage {
		result[k] = item.Value
	}
	return result, nil
}

type mockLongTermMemory struct {
	storage map[string]*MemoryItem
}

func (l *mockLongTermMemory) Store(ctx context.Context, id string, content string, metadata map[string]any) error {
	l.storage[id] = &MemoryItem{
		Key:      id,
		Value:    content,
		Metadata: metadata,
	}
	return nil
}

func (l *mockLongTermMemory) Search(ctx context.Context, query string, topK int, filters map[string]any) ([]MemoryResult, error) {
	return []MemoryResult{}, nil
}

func (l *mockLongTermMemory) SimilarFindings(ctx context.Context, content string, topK int) ([]MemoryResult, error) {
	return []MemoryResult{}, nil
}

func (l *mockLongTermMemory) SimilarPatterns(ctx context.Context, pattern string, topK int) ([]MemoryResult, error) {
	return []MemoryResult{}, nil
}

func (l *mockLongTermMemory) Delete(ctx context.Context, id string) error {
	delete(l.storage, id)
	return nil
}

func (l *mockLongTermMemory) Health(ctx context.Context) types.HealthStatus {
	return types.Healthy("mock long-term memory healthy")
}

// Verify interface implementations at compile time
var _ MemoryManager = (*mockMemoryManager)(nil)
var _ MissionMemory = (*mockMissionMemory)(nil)
var _ LongTermMemory = (*mockLongTermMemory)(nil)
