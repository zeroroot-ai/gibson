/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package migrations

// Tests for dirty-state recovery in runUp. We use golang-migrate's own
// stub source and database drivers so the test has no external
// dependencies (no Postgres, no Docker).

import (
	"testing"

	"github.com/golang-migrate/migrate/v4"
	dbstub "github.com/golang-migrate/migrate/v4/database/stub"
	"github.com/golang-migrate/migrate/v4/source"
	srcstub "github.com/golang-migrate/migrate/v4/source/stub"
)

// buildMigrateInstance wires a stub source (with the given migrations) to a
// stub database driver pre-seeded with dbVersion/dbDirty. Returns the
// *migrate.Migrate instance and a pointer to the stub database so tests can
// inspect post-run state.
func buildMigrateInstance(t *testing.T, migrations []*source.Migration, dbVersion int, dbDirty bool) (*migrate.Migrate, *dbstub.Stub) {
	t.Helper()

	// Source stub
	srcInstance, err := srcstub.WithInstance(nil, &srcstub.Config{})
	if err != nil {
		t.Fatalf("srcstub.WithInstance: %v", err)
	}
	ss := srcInstance.(*srcstub.Stub)
	ss.Migrations = source.NewMigrations()
	for _, m := range migrations {
		ss.Migrations.Append(m)
	}

	// Database stub — pre-seed version and dirty flag to simulate the
	// state left after a mid-migration pod kill.
	dbInstance, err := dbstub.WithInstance(nil, &dbstub.Config{})
	if err != nil {
		t.Fatalf("dbstub.WithInstance: %v", err)
	}
	ds := dbInstance.(*dbstub.Stub)
	ds.CurrentVersion = dbVersion
	ds.IsDirty = dbDirty

	m, err := migrate.NewWithInstance("stub", srcInstance, "stub", dbInstance)
	if err != nil {
		t.Fatalf("migrate.NewWithInstance: %v", err)
	}
	return m, ds
}

// TestRunUp_DirtyRecovery_NormalVersion tests the primary dirty-state
// recovery path: the database is at (version=2, dirty=true) simulating a pod
// kill mid-migration. runUp must force back to version 1 and re-run the
// migration, leaving the database clean.
func TestRunUp_DirtyRecovery_NormalVersion(t *testing.T) {
	// Source has migrations 1 and 2. DB is dirty at version 2 (pod was
	// killed while migration 2 was executing).
	migrationsInSource := []*source.Migration{
		{Version: 1, Identifier: "create_foo", Direction: source.Up},
		{Version: 1, Identifier: "drop_foo", Direction: source.Down},
		{Version: 2, Identifier: "create_bar", Direction: source.Up},
		{Version: 2, Identifier: "drop_bar", Direction: source.Down},
	}

	m, ds := buildMigrateInstance(t, migrationsInSource, 2, true)
	defer func() { _, _ = m.Close() }()

	err := runUp(m)
	if err != nil {
		t.Fatalf("runUp returned unexpected error: %v", err)
	}

	// After recovery the database must be at version 2, not dirty.
	if ds.CurrentVersion != 2 {
		t.Errorf("expected db version 2 after recovery, got %d", ds.CurrentVersion)
	}
	if ds.IsDirty {
		t.Errorf("expected db not dirty after recovery, but IsDirty=true")
	}
}

// TestRunUp_DirtyRecovery_Version1 tests the edge case where version 1 is
// dirty (the very first migration was interrupted). prevVersion clamps to 0,
// Force(0) resets to NilVersion, and m.Up() re-runs migration 1.
func TestRunUp_DirtyRecovery_Version1(t *testing.T) {
	migrationsInSource := []*source.Migration{
		{Version: 1, Identifier: "create_foo", Direction: source.Up},
		{Version: 1, Identifier: "drop_foo", Direction: source.Down},
	}

	m, ds := buildMigrateInstance(t, migrationsInSource, 1, true)
	defer func() { _, _ = m.Close() }()

	err := runUp(m)
	if err != nil {
		t.Fatalf("runUp returned unexpected error: %v", err)
	}

	if ds.CurrentVersion != 1 {
		t.Errorf("expected db version 1 after recovery, got %d", ds.CurrentVersion)
	}
	if ds.IsDirty {
		t.Errorf("expected db not dirty after recovery, but IsDirty=true")
	}
}

// TestRunUp_CleanUpToDate verifies that a database that is already at the
// latest version returns nil without error (ErrNoChange path).
func TestRunUp_CleanUpToDate(t *testing.T) {
	migrationsInSource := []*source.Migration{
		{Version: 1, Identifier: "create_foo", Direction: source.Up},
		{Version: 1, Identifier: "drop_foo", Direction: source.Down},
	}

	// DB already at version 1, clean.
	m, _ := buildMigrateInstance(t, migrationsInSource, 1, false)
	defer func() { _, _ = m.Close() }()

	if err := runUp(m); err != nil {
		t.Fatalf("runUp on up-to-date db returned error: %v", err)
	}
}

// TestRunUp_CleanFreshDB verifies that a database with no migrations applied
// (NilVersion=-1) runs all migrations and returns nil.
func TestRunUp_CleanFreshDB(t *testing.T) {
	migrationsInSource := []*source.Migration{
		{Version: 1, Identifier: "create_foo", Direction: source.Up},
		{Version: 1, Identifier: "drop_foo", Direction: source.Down},
		{Version: 2, Identifier: "create_bar", Direction: source.Up},
		{Version: 2, Identifier: "drop_bar", Direction: source.Down},
	}

	// NilVersion = -1 (no migrations applied yet).
	m, ds := buildMigrateInstance(t, migrationsInSource, -1, false)
	defer func() { _, _ = m.Close() }()

	if err := runUp(m); err != nil {
		t.Fatalf("runUp on fresh db returned error: %v", err)
	}
	if ds.CurrentVersion != 2 {
		t.Errorf("expected db version 2 after fresh run, got %d", ds.CurrentVersion)
	}
	if ds.IsDirty {
		t.Errorf("expected db not dirty after fresh run, but IsDirty=true")
	}
}
