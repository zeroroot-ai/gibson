package database

import (
	"context"
	"fmt"
)

// DB is a stub type retained for backward compatibility with tests written against
// the SQLite-backed database layer. The production database layer now uses Redis.
// Tests that depend on DB will fail at runtime when calling Open.
type DB struct{}

// Migrator is a stub retained for backward compatibility.
type Migrator struct{}

// Open is a stub that always returns an error because SQLite is no longer supported.
func Open(_ string) (*DB, error) {
	return nil, fmt.Errorf("database.Open: SQLite database layer has been removed; use Redis-backed stores")
}

// Close is a no-op stub.
func (db *DB) Close() {}

// InitSchema is a stub that always returns an error.
func (db *DB) InitSchema() error {
	return fmt.Errorf("database.InitSchema: SQLite database layer has been removed")
}

// NewMigrator returns a stub Migrator.
func NewMigrator(_ *DB) *Migrator {
	return &Migrator{}
}

// Migrate is a stub that always returns an error.
func (m *Migrator) Migrate(_ context.Context) error {
	return fmt.Errorf("database.Migrator.Migrate: SQLite database layer has been removed")
}
