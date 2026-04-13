package payload

import "github.com/zero-day-ai/gibson/internal/database"

// NewPayloadStore creates a PayloadStore backed by the given database.
// This constructor is retained for backward compatibility with tests written against
// the SQLite-backed layer. In production, use NewRedisPayloadStore instead.
// Since database.Open always returns an error, this function will never be reached
// in the test path; it exists only to satisfy compilation.
func NewPayloadStore(db *database.DB) PayloadStore {
	_ = db
	return nil
}

// NewExecutionStore creates an ExecutionStore backed by the given database.
// This constructor is retained for backward compatibility with tests written against
// the SQLite-backed layer. In production, use a Redis-backed store instead.
func NewExecutionStore(db *database.DB) ExecutionStore {
	_ = db
	return nil
}
