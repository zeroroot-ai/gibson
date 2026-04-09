package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
)

// RecallQuery defines the parameters for a memory recall operation.
type RecallQuery struct {
	// Query is the search query string
	Query string

	// MemoryTier specifies which memory tier to query: "mission", "long_term", or "both"
	MemoryTier string

	// MissionID is the mission context for the recall
	MissionID string

	// Filters are optional key-value filters (e.g., target_ip, time_range)
	// Support depends on underlying memory implementation
	Filters map[string]string

	// MaxResults limits the number of results per tier
	MaxResults int
}

// Validate checks if the recall query is valid.
func (q *RecallQuery) Validate() error {
	if q.Query == "" {
		return fmt.Errorf("query cannot be empty")
	}

	if q.MemoryTier == "" {
		return fmt.Errorf("memory_tier is required")
	}

	tier := q.MemoryTier
	if tier != "mission" && tier != "long_term" && tier != "both" {
		return fmt.Errorf("invalid memory_tier: %s (must be mission, long_term, or both)", tier)
	}

	if q.MaxResults < 0 {
		return fmt.Errorf("max_results cannot be negative")
	}

	return nil
}

// RecallResult contains the results of a memory recall operation.
type RecallResult struct {
	// MissionResults contains results from mission memory (if queried)
	MissionResults []MemoryEntry

	// LongTermResults contains results from long-term memory (if queried)
	LongTermResults []MemoryEntry

	// FormattedContext is a markdown-formatted string ready for prompt injection
	FormattedContext string

	// QueryTimeMs is the total time spent querying memory in milliseconds
	QueryTimeMs int64
}

// MemoryEntry represents a single memory result with metadata.
type MemoryEntry struct {
	// Key is the memory key or ID
	Key string

	// Value is the stored content
	Value interface{}

	// Timestamp is when the entry was created or stored
	Timestamp time.Time

	// Source indicates which tier this came from: "mission" or "long_term"
	Source string

	// Score is the relevance score for semantic search (0.0-1.0)
	Score float64
}

// MemoryRecaller defines the interface for querying memory tiers.
type MemoryRecaller interface {
	// Recall queries specified memory tiers and returns formatted results.
	// The query will be executed against mission memory, long-term memory, or both
	// depending on the RecallQuery.MemoryTier field.
	Recall(ctx context.Context, query RecallQuery) (*RecallResult, error)
}

// DefaultMemoryRecaller implements MemoryRecaller using existing memory tier interfaces.
type DefaultMemoryRecaller struct {
	missionMemory  memory.MissionMemory
	longTermMemory memory.LongTermMemory
	eventBus       EventBus
}

// NewDefaultMemoryRecaller creates a new DefaultMemoryRecaller.
//
// Parameters:
//   - missionMemory: Mission memory instance for FTS queries
//   - longTermMemory: Long-term memory instance for semantic search
//   - eventBus: Event bus for emitting recall events (optional, can be nil)
//
// Returns a configured DefaultMemoryRecaller ready to perform recalls.
func NewDefaultMemoryRecaller(
	missionMemory memory.MissionMemory,
	longTermMemory memory.LongTermMemory,
	eventBus EventBus,
) *DefaultMemoryRecaller {
	return &DefaultMemoryRecaller{
		missionMemory:  missionMemory,
		longTermMemory: longTermMemory,
		eventBus:       eventBus,
	}
}

// Recall performs a memory query across specified tiers with timeouts.
func (r *DefaultMemoryRecaller) Recall(ctx context.Context, query RecallQuery) (*RecallResult, error) {
	// Validate query
	if err := query.Validate(); err != nil {
		return nil, fmt.Errorf("invalid recall query: %w", err)
	}

	// Set default max results if not specified
	maxResults := query.MaxResults
	if maxResults == 0 {
		maxResults = 10
	}

	// Emit recall started event
	if r.eventBus != nil {
		r.eventBus.Publish(events.Event{
			Type:      events.EventRecallStarted,
			Timestamp: time.Now(),
			MissionID: types.ID(query.MissionID),
			Payload: map[string]any{
				"query":       query.Query,
				"memory_tier": query.MemoryTier,
				"max_results": maxResults,
				"has_filters": len(query.Filters) > 0,
			},
		})
	}

	startTime := time.Now()

	result := &RecallResult{
		MissionResults:  []MemoryEntry{},
		LongTermResults: []MemoryEntry{},
	}

	// Query mission memory if requested
	if query.MemoryTier == "mission" || query.MemoryTier == "both" {
		missionResults, err := r.queryMissionMemory(ctx, query, maxResults)
		if err != nil {
			// Log warning but continue - partial results are acceptable
			fmt.Printf("Warning: mission memory query failed: %v\n", err)
		} else {
			result.MissionResults = missionResults
		}
	}

	// Query long-term memory if requested
	if query.MemoryTier == "long_term" || query.MemoryTier == "both" {
		longTermResults, err := r.queryLongTermMemory(ctx, query, maxResults)
		if err != nil {
			// Log warning but continue - partial results are acceptable
			fmt.Printf("Warning: long-term memory query failed: %v\n", err)
		} else {
			result.LongTermResults = longTermResults
		}
	}

	// Calculate query time
	queryDuration := time.Since(startTime)
	result.QueryTimeMs = queryDuration.Milliseconds()

	// Format context for prompt injection
	result.FormattedContext = r.formatContext(result, query)

	// Emit recall completed event
	if r.eventBus != nil {
		r.eventBus.Publish(events.Event{
			Type:      events.EventRecallCompleted,
			Timestamp: time.Now(),
			MissionID: types.ID(query.MissionID),
			Payload: map[string]any{
				"query":             query.Query,
				"memory_tier":       query.MemoryTier,
				"mission_results":   len(result.MissionResults),
				"long_term_results": len(result.LongTermResults),
				"total_results":     len(result.MissionResults) + len(result.LongTermResults),
				"query_time_ms":     result.QueryTimeMs,
				"formatted_length":  len(result.FormattedContext),
			},
		})
	}

	return result, nil
}

// queryMissionMemory queries mission memory with timeout.
func (r *DefaultMemoryRecaller) queryMissionMemory(ctx context.Context, query RecallQuery, maxResults int) ([]MemoryEntry, error) {
	if r.missionMemory == nil {
		return nil, fmt.Errorf("mission memory is not available")
	}

	// Create context with timeout for mission memory (500ms)
	queryCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	// Execute search
	results, err := r.missionMemory.Search(queryCtx, query.Query, maxResults)
	if err != nil {
		return nil, fmt.Errorf("mission memory search failed: %w", err)
	}

	// Convert to MemoryEntry
	entries := make([]MemoryEntry, 0, len(results))
	for _, res := range results {
		entries = append(entries, MemoryEntry{
			Key:       res.Item.Key,
			Value:     res.Item.Value,
			Timestamp: res.Item.CreatedAt,
			Source:    "mission",
			Score:     res.Score,
		})
	}

	return entries, nil
}

// queryLongTermMemory queries long-term memory with timeout.
func (r *DefaultMemoryRecaller) queryLongTermMemory(ctx context.Context, query RecallQuery, maxResults int) ([]MemoryEntry, error) {
	if r.longTermMemory == nil {
		return nil, fmt.Errorf("long-term memory is not available")
	}

	// Create context with timeout for long-term memory (2s)
	queryCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	// Build filters map from query filters (convert to map[string]any)
	filters := make(map[string]any)
	for k, v := range query.Filters {
		filters[k] = v
	}

	// Execute semantic search
	results, err := r.longTermMemory.Search(queryCtx, query.Query, maxResults, filters)
	if err != nil {
		return nil, fmt.Errorf("long-term memory search failed: %w", err)
	}

	// Convert to MemoryEntry
	entries := make([]MemoryEntry, 0, len(results))
	for _, res := range results {
		entries = append(entries, MemoryEntry{
			Key:       res.Item.Key,
			Value:     res.Item.Value,
			Timestamp: res.Item.CreatedAt,
			Source:    "long_term",
			Score:     res.Score,
		})
	}

	return entries, nil
}

// formatContext formats recall results into markdown ready for prompt injection.
func (r *DefaultMemoryRecaller) formatContext(result *RecallResult, query RecallQuery) string {
	var sb strings.Builder

	sb.WriteString("## Recalled Context\n\n")

	// Handle empty results
	if len(result.MissionResults) == 0 && len(result.LongTermResults) == 0 {
		sb.WriteString("*No relevant context found in memory.*\n")
		return sb.String()
	}

	// Format mission memory results
	if len(result.MissionResults) > 0 {
		sb.WriteString(fmt.Sprintf("### Mission Memory Results (%d entries)\n\n", len(result.MissionResults)))

		for _, entry := range result.MissionResults {
			// Format timestamp
			timeStr := entry.Timestamp.Format("2006-01-02 15:04")

			// Format value based on type
			valueStr := formatValue(entry.Value)

			// Truncate if too long
			if len(valueStr) > 200 {
				valueStr = valueStr[:197] + "..."
			}

			sb.WriteString(fmt.Sprintf("- [%s] **%s**: %s\n", timeStr, entry.Key, valueStr))
		}
		sb.WriteString("\n")
	}

	// Format long-term memory results
	if len(result.LongTermResults) > 0 {
		sb.WriteString(fmt.Sprintf("### Long-term Memory Results (%d entries)\n\n", len(result.LongTermResults)))

		for _, entry := range result.LongTermResults {
			// Format score
			scoreStr := fmt.Sprintf("%.2f", entry.Score)

			// Format value based on type
			valueStr := formatValue(entry.Value)

			// Truncate if too long
			if len(valueStr) > 200 {
				valueStr = valueStr[:197] + "..."
			}

			sb.WriteString(fmt.Sprintf("- [Score: %s] %s\n", scoreStr, valueStr))
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("*Query: \"%s\" | Tier: %s | Time: %dms*\n", query.Query, query.MemoryTier, result.QueryTimeMs))

	return sb.String()
}

// formatValue converts a value to a string representation for display.
func formatValue(value interface{}) string {
	if value == nil {
		return "(empty)"
	}

	switch v := value.(type) {
	case string:
		return v
	case map[string]interface{}:
		// Format map as key-value pairs
		var parts []string
		for k, val := range v {
			parts = append(parts, fmt.Sprintf("%s=%v", k, val))
		}
		return strings.Join(parts, ", ")
	case []interface{}:
		// Format array
		var parts []string
		for _, item := range v {
			parts = append(parts, fmt.Sprintf("%v", item))
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}
