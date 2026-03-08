package memory

import (
	"context"
	"errors"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// Memory continuity errors
var (
	// ErrNoPreviousRun is returned when attempting to access prior run data but no prior run exists
	ErrNoPreviousRun = errors.New("no previous run exists")

	// ErrContinuityNotSupported is returned when attempting continuity operations in isolated mode
	ErrContinuityNotSupported = errors.New("memory continuity not supported in isolated mode")
)

// MemoryContinuityMode defines how memory state is handled across multiple runs
type MemoryContinuityMode string

const (
	// MemoryIsolated indicates that each run has completely isolated memory (default)
	MemoryIsolated MemoryContinuityMode = "isolated"

	// MemoryInherit indicates that new runs can read memory from prior runs
	// but cannot modify the shared state (copy-on-write semantics)
	MemoryInherit MemoryContinuityMode = "inherit"

	// MemoryShared indicates that all runs share the same memory namespace
	// with full read and write access
	MemoryShared MemoryContinuityMode = "shared"
)

// HistoricalValue represents a value retrieved from a previous run's memory
type HistoricalValue struct {
	// Value is the actual data stored in memory
	Value any `json:"value"`

	// RunNumber is the sequential run number within the mission (1-based)
	RunNumber int `json:"run_number"`

	// MissionID is the unique identifier of the mission this value belongs to
	MissionID string `json:"mission_id"`

	// StoredAt is the timestamp when this value was stored
	StoredAt time.Time `json:"stored_at"`
}

// MissionMemory provides persistent per-mission storage with FTS
type MissionMemory interface {
	// Store persists a key-value pair with optional metadata
	Store(ctx context.Context, key string, value any, metadata map[string]any) error

	// Retrieve gets an item by key
	Retrieve(ctx context.Context, key string) (*MemoryItem, error)

	// Delete removes an entry
	Delete(ctx context.Context, key string) error

	// Search performs full-text search across stored content
	Search(ctx context.Context, query string, limit int) ([]MemoryResult, error)

	// History returns recent entries ordered by time
	History(ctx context.Context, limit int) ([]MemoryItem, error)

	// Keys returns all keys for this mission
	Keys(ctx context.Context) ([]string, error)

	// MissionID returns the mission this memory is scoped to
	MissionID() types.ID

	// Memory Continuity Methods

	// ContinuityMode returns the current memory continuity mode
	// Returns MemoryIsolated if not explicitly configured
	ContinuityMode() MemoryContinuityMode

	// GetPreviousRunValue retrieves a value from the prior run's memory
	// Only works if continuity mode is 'inherit' or 'shared'
	// Returns ErrNoPreviousRun if no prior run exists
	// Returns ErrContinuityNotSupported if mode is 'isolated'
	GetPreviousRunValue(ctx context.Context, key string) (any, error)

	// GetValueHistory returns values for a key across all runs
	// Returns in chronological order with run metadata
	// Returns empty slice if key was never stored
	GetValueHistory(ctx context.Context, key string) ([]HistoricalValue, error)
}
