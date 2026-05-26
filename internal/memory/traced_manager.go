package memory

import (
	"context"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// TracedMemoryManager wraps a MemoryManager with OpenTelemetry tracing.
// It creates spans for all memory operations across working, mission, and long-term tiers.
//
// All memory operations are traced with appropriate span names:
//   - Working memory: "gibson.memory.working.{operation}"
//   - Mission memory: "gibson.memory.mission.{operation}"
//   - Long-term memory: "gibson.memory.longterm.{operation}"
//
// Each span includes attributes for:
//   - Memory tier (working/mission/longterm)
//   - Operation type (set/get/delete/search/store)
//   - Key names and namespaces where applicable
//   - Result counts and relevance scores for searches
type TracedMemoryManager struct {
	inner  MemoryManager
	tracer trace.Tracer
}

// NewTracedMemoryManager creates a new TracedMemoryManager that wraps the provided
// inner manager with OpenTelemetry tracing.
//
// Parameters:
//   - mm: The underlying MemoryManager to wrap
//   - tracer: The OpenTelemetry tracer to use for creating spans
//
// Returns:
//   - *TracedMemoryManager: A traced memory manager ready for use
//
// Example:
//
//	traced := NewTracedMemoryManager(innerManager, myTracer)
//	working := traced.Working()
//	working.Set("key", "value") // Creates span "gibson.memory.working.set"
func NewTracedMemoryManager(mm MemoryManager, tracer trace.Tracer) *TracedMemoryManager {
	return &TracedMemoryManager{
		inner:  mm,
		tracer: tracer,
	}
}

// Working returns a traced working memory instance.
func (m *TracedMemoryManager) Working() WorkingMemory {
	return &tracedWorkingMemory{
		inner:  m.inner.Working(),
		tracer: m.tracer,
	}
}

// Mission returns a traced mission memory instance.
func (m *TracedMemoryManager) Mission() MissionMemory {
	return &tracedMissionMemory{
		inner:  m.inner.Mission(),
		tracer: m.tracer,
	}
}

// LongTerm returns a traced long-term memory instance.
func (m *TracedMemoryManager) LongTerm() LongTermMemory {
	return &tracedLongTermMemory{
		inner:  m.inner.LongTerm(),
		tracer: m.tracer,
	}
}

// MissionID returns the mission ID this manager is scoped to.
// This is a pass-through operation without additional tracing.
func (m *TracedMemoryManager) MissionID() types.ID {
	return m.inner.MissionID()
}

// Close releases all resources held by the memory manager.
// Creates a span "gibson.memory.close" to track the cleanup operation.
func (m *TracedMemoryManager) Close() error {
	ctx := context.Background()
	ctx, span := m.tracer.Start(ctx, "gibson.memory.close")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
	)

	err := m.inner.Close()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "memory manager closed")
	return nil
}

// tracedWorkingMemory wraps WorkingMemory with tracing.
type tracedWorkingMemory struct {
	inner  WorkingMemory
	tracer trace.Tracer
}

// Set stores a value with tracing.
// Creates a span "gibson.memory.working.set" with key attribute.
func (w *tracedWorkingMemory) Set(key string, value any) error {
	ctx := context.Background()
	ctx, span := w.tracer.Start(ctx, "gibson.memory.working.set")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "working"),
		attribute.String("gibson.memory.operation", "set"),
		attribute.String("gibson.memory.key", key),
	)

	startTime := time.Now()
	err := w.inner.Set(key, value)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
		attribute.Int("gibson.memory.token_count", w.inner.TokenCount()),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "set succeeded")
	return nil
}

// Get retrieves a value with tracing.
// Creates a span "gibson.memory.working.get" with key and found attributes.
func (w *tracedWorkingMemory) Get(key string) (any, bool) {
	ctx := context.Background()
	ctx, span := w.tracer.Start(ctx, "gibson.memory.working.get")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "working"),
		attribute.String("gibson.memory.operation", "get"),
		attribute.String("gibson.memory.key", key),
	)

	startTime := time.Now()
	value, found := w.inner.Get(key)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Bool("gibson.memory.found", found),
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	span.SetStatus(codes.Ok, "get completed")
	return value, found
}

// Delete removes an entry with tracing.
// Creates a span "gibson.memory.working.delete" with key attribute.
func (w *tracedWorkingMemory) Delete(key string) bool {
	ctx := context.Background()
	ctx, span := w.tracer.Start(ctx, "gibson.memory.working.delete")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "working"),
		attribute.String("gibson.memory.operation", "delete"),
		attribute.String("gibson.memory.key", key),
	)

	startTime := time.Now()
	existed := w.inner.Delete(key)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Bool("gibson.memory.existed", existed),
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
		attribute.Int("gibson.memory.token_count", w.inner.TokenCount()),
	)

	span.SetStatus(codes.Ok, "delete completed")
	return existed
}

// Clear removes all entries with tracing.
// Creates a span "gibson.memory.working.clear".
func (w *tracedWorkingMemory) Clear() {
	ctx := context.Background()
	ctx, span := w.tracer.Start(ctx, "gibson.memory.working.clear")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "working"),
		attribute.String("gibson.memory.operation", "clear"),
	)

	startTime := time.Now()
	w.inner.Clear()
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	span.SetStatus(codes.Ok, "clear completed")
}

// List returns all stored keys with tracing.
// Creates a span "gibson.memory.working.list" with count attribute.
func (w *tracedWorkingMemory) List() []string {
	ctx := context.Background()
	ctx, span := w.tracer.Start(ctx, "gibson.memory.working.list")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "working"),
		attribute.String("gibson.memory.operation", "list"),
	)

	startTime := time.Now()
	keys := w.inner.List()
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Int("gibson.memory.count", len(keys)),
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	span.SetStatus(codes.Ok, "list completed")
	return keys
}

// GetAll returns a snapshot of all key-value pairs with tracing.
// Creates a span "gibson.memory.working.get_all" with count attribute.
func (w *tracedWorkingMemory) GetAll() (map[string]any, error) {
	ctx := context.Background()
	ctx, span := w.tracer.Start(ctx, "gibson.memory.working.get_all")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "working"),
		attribute.String("gibson.memory.operation", "get_all"),
	)

	startTime := time.Now()
	result, err := w.inner.GetAll()
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
		attribute.Int("gibson.memory.count", len(result)),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetStatus(codes.Ok, "get_all completed")
	return result, nil
}

// TokenCount returns the current token usage.
// This is a pass-through operation without additional tracing.
func (w *tracedWorkingMemory) TokenCount() int {
	return w.inner.TokenCount()
}

// MaxTokens returns the configured token limit.
// This is a pass-through operation without additional tracing.
func (w *tracedWorkingMemory) MaxTokens() int {
	return w.inner.MaxTokens()
}

// tracedMissionMemory wraps MissionMemory with tracing.
type tracedMissionMemory struct {
	inner  MissionMemory
	tracer trace.Tracer
}

// Store persists a key-value pair with tracing.
// Creates a span "gibson.memory.mission.store" with key attribute.
func (m *tracedMissionMemory) Store(ctx context.Context, key string, value any, metadata map[string]any) error {
	ctx, span := m.tracer.Start(ctx, "gibson.memory.mission.store")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "mission"),
		attribute.String("gibson.memory.operation", "store"),
		attribute.String("gibson.memory.key", key),
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
	)

	if metadata != nil {
		span.SetAttributes(attribute.Int("gibson.memory.metadata_count", len(metadata)))
	}

	startTime := time.Now()
	err := m.inner.Store(ctx, key, value, metadata)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "store succeeded")
	return nil
}

// Retrieve gets an item by key with tracing.
// Creates a span "gibson.memory.mission.retrieve" with key and found attributes.
func (m *tracedMissionMemory) Retrieve(ctx context.Context, key string) (*MemoryItem, error) {
	ctx, span := m.tracer.Start(ctx, "gibson.memory.mission.retrieve")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "mission"),
		attribute.String("gibson.memory.operation", "retrieve"),
		attribute.String("gibson.memory.key", key),
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
	)

	startTime := time.Now()
	item, err := m.inner.Retrieve(ctx, key)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.SetAttributes(attribute.Bool("gibson.memory.found", false))
		return nil, err
	}

	span.SetAttributes(attribute.Bool("gibson.memory.found", true))
	span.SetStatus(codes.Ok, "retrieve succeeded")
	return item, nil
}

// Delete removes an entry with tracing.
// Creates a span "gibson.memory.mission.delete" with key attribute.
func (m *tracedMissionMemory) Delete(ctx context.Context, key string) error {
	ctx, span := m.tracer.Start(ctx, "gibson.memory.mission.delete")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "mission"),
		attribute.String("gibson.memory.operation", "delete"),
		attribute.String("gibson.memory.key", key),
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
	)

	startTime := time.Now()
	err := m.inner.Delete(ctx, key)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "delete succeeded")
	return nil
}

// Search performs full-text search with tracing.
// Creates a span "gibson.memory.mission.search" with query and results_count attributes.
func (m *tracedMissionMemory) Search(ctx context.Context, query string, limit int) ([]MemoryResult, error) {
	ctx, span := m.tracer.Start(ctx, "gibson.memory.mission.search")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "mission"),
		attribute.String("gibson.memory.operation", "search"),
		attribute.String("gibson.memory.query", query),
		attribute.Int("gibson.memory.limit", limit),
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
	)

	startTime := time.Now()
	results, err := m.inner.Search(ctx, query, limit)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(attribute.Int("gibson.memory.results_count", len(results)))
	span.SetStatus(codes.Ok, "search succeeded")
	return results, nil
}

// History returns recent entries with tracing.
// Creates a span "gibson.memory.mission.history".
func (m *tracedMissionMemory) History(ctx context.Context, limit int) ([]MemoryItem, error) {
	ctx, span := m.tracer.Start(ctx, "gibson.memory.mission.history")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "mission"),
		attribute.String("gibson.memory.operation", "history"),
		attribute.Int("gibson.memory.limit", limit),
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
	)

	startTime := time.Now()
	items, err := m.inner.History(ctx, limit)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(attribute.Int("gibson.memory.count", len(items)))
	span.SetStatus(codes.Ok, "history succeeded")
	return items, nil
}

// Keys returns all keys with tracing.
// Creates a span "gibson.memory.mission.keys".
func (m *tracedMissionMemory) Keys(ctx context.Context) ([]string, error) {
	ctx, span := m.tracer.Start(ctx, "gibson.memory.mission.keys")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "mission"),
		attribute.String("gibson.memory.operation", "keys"),
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
	)

	startTime := time.Now()
	keys, err := m.inner.Keys(ctx)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(attribute.Int("gibson.memory.count", len(keys)))
	span.SetStatus(codes.Ok, "keys succeeded")
	return keys, nil
}

// GetAll returns a snapshot of all mission memory with tracing.
// Creates a span "gibson.memory.mission.get_all" with count attribute.
func (m *tracedMissionMemory) GetAll(ctx context.Context) (map[string]any, error) {
	ctx, span := m.tracer.Start(ctx, "gibson.memory.mission.get_all")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "mission"),
		attribute.String("gibson.memory.operation", "get_all"),
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
	)

	startTime := time.Now()
	result, err := m.inner.GetAll(ctx)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
		attribute.Int("gibson.memory.count", len(result)),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetStatus(codes.Ok, "get_all completed")
	return result, nil
}

// MissionID returns the mission this memory is scoped to.
// This is a pass-through operation without additional tracing.
func (m *tracedMissionMemory) MissionID() types.ID {
	return m.inner.MissionID()
}

// ContinuityMode returns the current memory continuity mode.
// This is a pass-through operation without additional tracing.
func (m *tracedMissionMemory) ContinuityMode() MemoryContinuityMode {
	return m.inner.ContinuityMode()
}

// GetPreviousRunValue retrieves a value from the prior run's memory with tracing.
// Creates a span "gibson.memory.mission.get_previous_run_value".
func (m *tracedMissionMemory) GetPreviousRunValue(ctx context.Context, key string) (any, error) {
	ctx, span := m.tracer.Start(ctx, "gibson.memory.mission.get_previous_run_value")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "mission"),
		attribute.String("gibson.memory.operation", "get_previous_run_value"),
		attribute.String("gibson.memory.key", key),
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
		attribute.String("gibson.memory.continuity_mode", string(m.inner.ContinuityMode())),
	)

	startTime := time.Now()
	value, err := m.inner.GetPreviousRunValue(ctx, key)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(attribute.Bool("gibson.memory.found", true))
	span.SetStatus(codes.Ok, "get previous run value succeeded")
	return value, nil
}

// GetValueHistory returns values for a key across all runs with tracing.
// Creates a span "gibson.memory.mission.get_value_history".
func (m *tracedMissionMemory) GetValueHistory(ctx context.Context, key string) ([]HistoricalValue, error) {
	ctx, span := m.tracer.Start(ctx, "gibson.memory.mission.get_value_history")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "mission"),
		attribute.String("gibson.memory.operation", "get_value_history"),
		attribute.String("gibson.memory.key", key),
		attribute.String("gibson.memory.mission_id", m.inner.MissionID().String()),
		attribute.String("gibson.memory.continuity_mode", string(m.inner.ContinuityMode())),
	)

	startTime := time.Now()
	history, err := m.inner.GetValueHistory(ctx, key)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(attribute.Int("gibson.memory.history_count", len(history)))
	span.SetStatus(codes.Ok, "get value history succeeded")
	return history, nil
}

// tracedLongTermMemory wraps LongTermMemory with tracing.
type tracedLongTermMemory struct {
	inner  LongTermMemory
	tracer trace.Tracer
}

// Store adds content with tracing.
// Creates a span "gibson.memory.longterm.store".
func (l *tracedLongTermMemory) Store(ctx context.Context, id string, content string, metadata map[string]any) error {
	ctx, span := l.tracer.Start(ctx, "gibson.memory.longterm.store")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "longterm"),
		attribute.String("gibson.memory.operation", "store"),
		attribute.String("gibson.memory.id", id),
		attribute.Int("gibson.memory.content_length", len(content)),
	)

	if metadata != nil {
		span.SetAttributes(attribute.Int("gibson.memory.metadata_count", len(metadata)))
	}

	startTime := time.Now()
	err := l.inner.Store(ctx, id, content, metadata)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "store succeeded")
	return nil
}

// Search finds similar content with tracing.
// Creates a span "gibson.memory.longterm.search" with query, results_count, and relevance_scores.
func (l *tracedLongTermMemory) Search(ctx context.Context, query string, topK int, filters map[string]any) ([]MemoryResult, error) {
	ctx, span := l.tracer.Start(ctx, "gibson.memory.longterm.search")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "longterm"),
		attribute.String("gibson.memory.operation", "search"),
		attribute.String("gibson.memory.query", query),
		attribute.Int("gibson.memory.top_k", topK),
	)

	if filters != nil {
		span.SetAttributes(attribute.Int("gibson.memory.filter_count", len(filters)))
	}

	startTime := time.Now()
	results, err := l.inner.Search(ctx, query, topK, filters)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	// Add result count and relevance scores
	span.SetAttributes(attribute.Int("gibson.memory.results_count", len(results)))

	if len(results) > 0 {
		// Record min/max/avg relevance scores
		minScore, maxScore, sumScore := results[0].Score, results[0].Score, 0.0
		for _, r := range results {
			if r.Score < minScore {
				minScore = r.Score
			}
			if r.Score > maxScore {
				maxScore = r.Score
			}
			sumScore += r.Score
		}
		avgScore := sumScore / float64(len(results))

		span.SetAttributes(
			attribute.Float64("gibson.memory.relevance_min", minScore),
			attribute.Float64("gibson.memory.relevance_max", maxScore),
			attribute.Float64("gibson.memory.relevance_avg", avgScore),
		)
	}

	span.SetStatus(codes.Ok, "search succeeded")
	return results, nil
}

// SimilarFindings finds findings similar to the given content with tracing.
// Creates a span "gibson.memory.longterm.similar_findings".
func (l *tracedLongTermMemory) SimilarFindings(ctx context.Context, content string, topK int) ([]MemoryResult, error) {
	ctx, span := l.tracer.Start(ctx, "gibson.memory.longterm.similar_findings")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "longterm"),
		attribute.String("gibson.memory.operation", "similar_findings"),
		attribute.Int("gibson.memory.content_length", len(content)),
		attribute.Int("gibson.memory.top_k", topK),
	)

	startTime := time.Now()
	results, err := l.inner.SimilarFindings(ctx, content, topK)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(attribute.Int("gibson.memory.results_count", len(results)))
	span.SetStatus(codes.Ok, "similar findings search succeeded")
	return results, nil
}

// SimilarPatterns finds attack patterns similar to the query with tracing.
// Creates a span "gibson.memory.longterm.similar_patterns".
func (l *tracedLongTermMemory) SimilarPatterns(ctx context.Context, pattern string, topK int) ([]MemoryResult, error) {
	ctx, span := l.tracer.Start(ctx, "gibson.memory.longterm.similar_patterns")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "longterm"),
		attribute.String("gibson.memory.operation", "similar_patterns"),
		attribute.String("gibson.memory.pattern", pattern),
		attribute.Int("gibson.memory.top_k", topK),
	)

	startTime := time.Now()
	results, err := l.inner.SimilarPatterns(ctx, pattern, topK)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	span.SetAttributes(attribute.Int("gibson.memory.results_count", len(results)))
	span.SetStatus(codes.Ok, "similar patterns search succeeded")
	return results, nil
}

// Delete removes content by ID with tracing.
// Creates a span "gibson.memory.longterm.delete".
func (l *tracedLongTermMemory) Delete(ctx context.Context, id string) error {
	ctx, span := l.tracer.Start(ctx, "gibson.memory.longterm.delete")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "longterm"),
		attribute.String("gibson.memory.operation", "delete"),
		attribute.String("gibson.memory.id", id),
	)

	startTime := time.Now()
	err := l.inner.Delete(ctx, id)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "delete succeeded")
	return nil
}

// Health returns the health status with tracing.
// Creates a span "gibson.memory.longterm.health".
func (l *tracedLongTermMemory) Health(ctx context.Context) types.HealthStatus {
	ctx, span := l.tracer.Start(ctx, "gibson.memory.longterm.health")
	defer span.End()

	span.SetAttributes(
		attribute.String("gibson.memory.tier", "longterm"),
		attribute.String("gibson.memory.operation", "health"),
	)

	startTime := time.Now()
	status := l.inner.Health(ctx)
	duration := time.Since(startTime)

	span.SetAttributes(
		attribute.Float64("gibson.memory.duration_ms", float64(duration.Milliseconds())),
		attribute.String("gibson.memory.health_status", status.State.String()),
		attribute.String("gibson.memory.health_message", status.Message),
	)

	span.SetStatus(codes.Ok, "health check completed")
	return status
}

// Ensure TracedMemoryManager implements MemoryManager at compile time
var _ MemoryManager = (*TracedMemoryManager)(nil)
