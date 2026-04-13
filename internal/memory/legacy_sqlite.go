package memory

import (
	"fmt"

	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
)

// NewMemoryManager creates a MemoryManager backed by the given SQLite database.
// This constructor is retained for backward compatibility with tests written against
// the SQLite-backed layer. In production, use the MemoryFactory with Redis instead.
// Since database.Open always returns an error, tests will fail before reaching this.
func NewMemoryManager(missionID types.ID, db *database.DB, config *MemoryConfig) (MemoryManager, error) {
	_ = db
	_ = config
	return nil, fmt.Errorf("NewMemoryManager: SQLite database layer has been removed; use MemoryFactory with Redis")
}
