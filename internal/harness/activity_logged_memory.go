package harness

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ActivityLoggedMemoryManager wraps a MemoryManager with activity logging.
// It emits activity events for memory store and recall operations.
type ActivityLoggedMemoryManager struct {
	inner          memory.MemoryManager
	activityLogger activityLoggerMemory
}

// activityLoggerMemory is the subset of the activity logger interface needed for memory operations.
type activityLoggerMemory interface {
	EmitMemoryStore(ctx context.Context, tier string, key string, dataSize int)
	EmitMemoryRecall(ctx context.Context, tier string, key string, found bool)
}

// NewActivityLoggedMemoryManager creates a new activity-logged memory manager.
func NewActivityLoggedMemoryManager(mm memory.MemoryManager, logger activityLoggerMemory) *ActivityLoggedMemoryManager {
	return &ActivityLoggedMemoryManager{
		inner:          mm,
		activityLogger: logger,
	}
}

// Working returns an activity-logged working memory instance.
func (m *ActivityLoggedMemoryManager) Working() memory.WorkingMemory {
	return &activityLoggedWorkingMemory{
		inner:          m.inner.Working(),
		activityLogger: m.activityLogger,
	}
}

// Mission returns an activity-logged mission memory instance.
func (m *ActivityLoggedMemoryManager) Mission() memory.MissionMemory {
	return &activityLoggedMissionMemory{
		inner:          m.inner.Mission(),
		activityLogger: m.activityLogger,
	}
}

// LongTerm returns an activity-logged long-term memory instance.
func (m *ActivityLoggedMemoryManager) LongTerm() memory.LongTermMemory {
	return &activityLoggedLongTermMemory{
		inner:          m.inner.LongTerm(),
		activityLogger: m.activityLogger,
	}
}

// MissionID returns the mission ID this manager is scoped to.
func (m *ActivityLoggedMemoryManager) MissionID() types.ID {
	return m.inner.MissionID()
}

// Close releases all resources held by the memory manager.
func (m *ActivityLoggedMemoryManager) Close() error {
	return m.inner.Close()
}

// activityLoggedWorkingMemory wraps WorkingMemory with activity logging.
type activityLoggedWorkingMemory struct {
	inner          memory.WorkingMemory
	activityLogger activityLoggerMemory
}

// Get retrieves a value and emits a recall event.
func (w *activityLoggedWorkingMemory) Get(key string) (any, bool) {
	value, found := w.inner.Get(key)

	// Emit recall event
	if w.activityLogger != nil {
		ctx := context.Background()
		w.activityLogger.EmitMemoryRecall(ctx, "working", key, found)
	}

	return value, found
}

// Set stores a value and emits a store event.
func (w *activityLoggedWorkingMemory) Set(key string, value any) error {
	err := w.inner.Set(key, value)

	// Emit store event on success
	if err == nil && w.activityLogger != nil {
		ctx := context.Background()
		// Calculate data size as string length for simple types
		dataSize := estimateSize(value)
		w.activityLogger.EmitMemoryStore(ctx, "working", key, dataSize)
	}

	return err
}

// Delete removes an entry.
func (w *activityLoggedWorkingMemory) Delete(key string) bool {
	return w.inner.Delete(key)
}

// Clear removes all entries.
func (w *activityLoggedWorkingMemory) Clear() {
	w.inner.Clear()
}

// List returns all stored keys.
func (w *activityLoggedWorkingMemory) List() []string {
	return w.inner.List()
}

// TokenCount returns the current total token usage.
func (w *activityLoggedWorkingMemory) TokenCount() int {
	return w.inner.TokenCount()
}

// MaxTokens returns the configured token limit.
func (w *activityLoggedWorkingMemory) MaxTokens() int {
	return w.inner.MaxTokens()
}

// activityLoggedMissionMemory wraps MissionMemory with activity logging.
type activityLoggedMissionMemory struct {
	inner          memory.MissionMemory
	activityLogger activityLoggerMemory
}

// Store persists a key-value pair and emits a store event.
func (m *activityLoggedMissionMemory) Store(ctx context.Context, key string, value any, metadata map[string]any) error {
	err := m.inner.Store(ctx, key, value, metadata)

	// Emit store event on success
	if err == nil && m.activityLogger != nil {
		dataSize := estimateSize(value)
		m.activityLogger.EmitMemoryStore(ctx, "mission", key, dataSize)
	}

	return err
}

// Retrieve gets an item by key and emits a recall event.
func (m *activityLoggedMissionMemory) Retrieve(ctx context.Context, key string) (*memory.MemoryItem, error) {
	item, err := m.inner.Retrieve(ctx, key)

	// Emit recall event
	if m.activityLogger != nil {
		found := (err == nil)
		m.activityLogger.EmitMemoryRecall(ctx, "mission", key, found)
	}

	return item, err
}

// Delete removes an entry.
func (m *activityLoggedMissionMemory) Delete(ctx context.Context, key string) error {
	return m.inner.Delete(ctx, key)
}

// Search performs full-text search.
func (m *activityLoggedMissionMemory) Search(ctx context.Context, query string, limit int) ([]memory.MemoryResult, error) {
	return m.inner.Search(ctx, query, limit)
}

// History returns recent entries ordered by time.
func (m *activityLoggedMissionMemory) History(ctx context.Context, limit int) ([]memory.MemoryItem, error) {
	return m.inner.History(ctx, limit)
}

// Keys returns all keys for this mission.
func (m *activityLoggedMissionMemory) Keys(ctx context.Context) ([]string, error) {
	return m.inner.Keys(ctx)
}

// MissionID returns the mission this memory is scoped to.
func (m *activityLoggedMissionMemory) MissionID() types.ID {
	return m.inner.MissionID()
}

// ContinuityMode returns the current memory continuity mode.
func (m *activityLoggedMissionMemory) ContinuityMode() memory.MemoryContinuityMode {
	return m.inner.ContinuityMode()
}

// GetPreviousRunValue retrieves a value from the prior run's memory.
func (m *activityLoggedMissionMemory) GetPreviousRunValue(ctx context.Context, key string) (any, error) {
	return m.inner.GetPreviousRunValue(ctx, key)
}

// GetValueHistory returns values for a key across all runs.
func (m *activityLoggedMissionMemory) GetValueHistory(ctx context.Context, key string) ([]memory.HistoricalValue, error) {
	return m.inner.GetValueHistory(ctx, key)
}

// activityLoggedLongTermMemory wraps LongTermMemory with activity logging.
type activityLoggedLongTermMemory struct {
	inner          memory.LongTermMemory
	activityLogger activityLoggerMemory
}

// Store stores content with embeddings and emits a store event.
func (l *activityLoggedLongTermMemory) Store(ctx context.Context, id string, content string, metadata map[string]any) error {
	err := l.inner.Store(ctx, id, content, metadata)

	// Emit store event on success
	if err == nil && l.activityLogger != nil {
		l.activityLogger.EmitMemoryStore(ctx, "longterm", id, len(content))
	}

	return err
}

// Search performs semantic search and emits recall events.
func (l *activityLoggedLongTermMemory) Search(ctx context.Context, query string, topK int, filters map[string]any) ([]memory.MemoryResult, error) {
	results, err := l.inner.Search(ctx, query, topK, filters)

	// Emit recall event
	if l.activityLogger != nil {
		found := (err == nil && len(results) > 0)
		l.activityLogger.EmitMemoryRecall(ctx, "longterm", query, found)
	}

	return results, err
}

// SimilarFindings finds findings similar to the given content.
func (l *activityLoggedLongTermMemory) SimilarFindings(ctx context.Context, content string, topK int) ([]memory.MemoryResult, error) {
	return l.inner.SimilarFindings(ctx, content, topK)
}

// SimilarPatterns finds attack patterns similar to the query.
func (l *activityLoggedLongTermMemory) SimilarPatterns(ctx context.Context, pattern string, topK int) ([]memory.MemoryResult, error) {
	return l.inner.SimilarPatterns(ctx, pattern, topK)
}

// Delete removes content by ID from the vector store.
func (l *activityLoggedLongTermMemory) Delete(ctx context.Context, id string) error {
	return l.inner.Delete(ctx, id)
}

// Health returns the combined health of the vector store and embedder.
func (l *activityLoggedLongTermMemory) Health(ctx context.Context) types.HealthStatus {
	return l.inner.Health(ctx)
}

// estimateSize estimates the size of a value in bytes for logging purposes.
// This is a simple heuristic and doesn't need to be exact.
func estimateSize(value any) int {
	if value == nil {
		return 0
	}

	switch v := value.(type) {
	case string:
		return len(v)
	case []byte:
		return len(v)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return 8
	case float32, float64:
		return 8
	case bool:
		return 1
	default:
		// For complex types, use a rough estimate based on string representation
		return len(fmt.Sprintf("%v", v))
	}
}
