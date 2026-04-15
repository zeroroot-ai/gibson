package orchestrator

import (
	"sort"
	"time"
)

// GraphEntry represents a single graph query result with metadata.
type GraphEntry struct {
	// ID is the unique identifier of the graph entity
	ID string

	// Type is the entity type (host, port, service, endpoint, finding, etc.)
	Type string

	// Score is the relevance score for this result (0.0-1.0)
	Score float64

	// Source indicates which query strategy produced this result
	// (e.g., "entity_lookup", "relationship_traversal")
	Source string
}

// MergedResult is a unified search result combining memory and graph data.
type MergedResult struct {
	// ID is the unique identifier (memory key or graph entity ID)
	ID string

	// Type is the result type (e.g., "graph_entity", "memory_entry")
	Type string

	// Source indicates which tier produced this result
	// (e.g., "mission_memory", "long_term_memory", "graph_entity_lookup")
	Source string

	// Content is the result data
	Content interface{}

	// Score is the combined relevance score (0.0-1.0)
	Score float64

	// Timestamp records when the underlying data was captured
	Timestamp time.Time
}

// ResultMerger combines and ranks results from multiple memory and graph tiers.
type ResultMerger struct{}

// NewResultMerger constructs a new ResultMerger.
func NewResultMerger() *ResultMerger {
	return &ResultMerger{}
}

// Merge combines mission memory results, long-term memory results, and graph
// results into a single ranked slice, limited to topK entries.
func (m *ResultMerger) Merge(missionResults, longTermResults []MemoryEntry, graphResults []GraphEntry, topK int) []MergedResult {
	var all []MergedResult

	for _, e := range missionResults {
		all = append(all, MergedResult{
			ID:        e.Key,
			Type:      "memory_entry",
			Source:    "mission_memory",
			Content:   e.Value,
			Score:     e.Score,
			Timestamp: e.Timestamp,
		})
	}

	for _, e := range longTermResults {
		all = append(all, MergedResult{
			ID:        e.Key,
			Type:      "memory_entry",
			Source:    "long_term_memory",
			Content:   e.Value,
			Score:     e.Score,
			Timestamp: e.Timestamp,
		})
	}

	for _, g := range graphResults {
		source := "graph_entity"
		if g.Source != "" {
			source = "graph_entity_" + g.Source
		}
		all = append(all, MergedResult{
			ID:     g.ID,
			Type:   "graph_entity",
			Source: source,
			Score:  g.Score,
		})
	}

	m.Rank(all)

	if topK > 0 && len(all) > topK {
		all = all[:topK]
	}

	return all
}

// Deduplicate removes duplicate entries by ID, keeping the one with the higher score.
func (m *ResultMerger) Deduplicate(results []MergedResult) []MergedResult {
	seen := make(map[string]int) // ID -> index in output
	out := make([]MergedResult, 0, len(results))

	for _, r := range results {
		if idx, exists := seen[r.ID]; exists {
			if r.Score > out[idx].Score {
				out[idx] = r
			}
		} else {
			seen[r.ID] = len(out)
			out = append(out, r)
		}
	}

	return out
}

// Rank sorts results in-place by score descending.
func (m *ResultMerger) Rank(results []MergedResult) {
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})
}

// FilterByMinRelevance returns only results whose score meets the minimum threshold.
func (m *ResultMerger) FilterByMinRelevance(results []MergedResult, minScore float64) []MergedResult {
	out := results[:0:0]
	for _, r := range results {
		if r.Score >= minScore {
			out = append(out, r)
		}
	}
	return out
}

// calculateRecencyScore returns a score in [0, 1] based on how recently the
// entry was captured relative to now.
func (m *ResultMerger) calculateRecencyScore(ts, now time.Time) float64 {
	age := now.Sub(ts)
	switch {
	case age < time.Hour:
		return 1.0
	case age < 24*time.Hour:
		// Linearly interpolate from 1.0 at 1h to 0.8 at 24h
		fraction := float64(age-time.Hour) / float64(23*time.Hour)
		return 1.0 - fraction*0.2
	case age < 7*24*time.Hour:
		// Linearly interpolate from 0.8 at 24h to 0.6 at 7d
		fraction := float64(age-24*time.Hour) / float64(6*24*time.Hour)
		return 0.8 - fraction*0.2
	case age < 30*24*time.Hour:
		// Linearly interpolate from 0.6 at 7d to 0.3 at 30d
		fraction := float64(age-7*24*time.Hour) / float64(23*24*time.Hour)
		return 0.6 - fraction*0.3
	default:
		// Linearly interpolate from 0.3 at 30d to 0.1 for very old
		fraction := float64(age-30*24*time.Hour) / float64(30*24*time.Hour)
		if fraction > 1.0 {
			fraction = 1.0
		}
		return 0.3 - fraction*0.2
	}
}

// calculateImportanceScore returns a static importance score based on entity type.
// Findings are most important; hosts and ports are less so.
func (m *ResultMerger) calculateImportanceScore(entityType string) float64 {
	scores := map[string]float64{
		"finding":  0.95,
		"vuln":     0.90,
		"service":  0.75,
		"endpoint": 0.70,
		"domain":   0.65,
		"port":     0.60,
		"host":     0.55,
		"ip":       0.55,
		"network":  0.50,
		"memory":   0.50,
	}
	if score, ok := scores[entityType]; ok {
		return score
	}
	return 0.5
}
