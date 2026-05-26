package memory

import (
	"encoding/json"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// MemoryItem represents a stored memory entry with metadata
type MemoryItem struct {
	Key       string         `json:"key"`
	Value     any            `json:"value"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// MemoryResult represents a search result with relevance score
type MemoryResult struct {
	Item  MemoryItem `json:"item"`
	Score float64    `json:"score"` // Relevance score (0-1 or BM25 score)
}

// NewMemoryItem creates a new MemoryItem with the current timestamp
func NewMemoryItem(key string, value any, metadata map[string]any) *MemoryItem {
	now := time.Now()
	return &MemoryItem{
		Key:       key,
		Value:     value,
		Metadata:  metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// Validate checks if the MemoryItem is valid
func (m *MemoryItem) Validate() error {
	if m.Key == "" {
		return types.NewError("MEMORY_INVALID", "key cannot be empty")
	}
	return nil
}

// MarshalValue marshals the value to JSON for storage
func (m *MemoryItem) MarshalValue() ([]byte, error) {
	return json.Marshal(m.Value)
}

// UnmarshalValue unmarshals the value from JSON
func (m *MemoryItem) UnmarshalValue(data []byte) error {
	return json.Unmarshal(data, &m.Value)
}

// NewMemoryResult creates a new MemoryResult with the given item and score
func NewMemoryResult(item MemoryItem, score float64) *MemoryResult {
	return &MemoryResult{
		Item:  item,
		Score: score,
	}
}
