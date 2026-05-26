// Copyright 2026 Zero Day AI.

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	pgmigrations "github.com/zeroroot-ai/gibson/pkg/platform/migrations"
)

func TestAssertPlatformSchemaVersion_Missing(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT version, dirty FROM schema_migrations").
		WillReturnError(errors.New(`pq: relation "schema_migrations" does not exist`))

	err = assertPlatformSchemaVersion(context.Background(), db, nil)
	if err == nil || !strings.Contains(err.Error(), "schema_migrations table unavailable") {
		t.Fatalf("expected schema_migrations missing error, got %v", err)
	}
}

func TestAssertPlatformSchemaVersion_Dirty(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT version, dirty FROM schema_migrations").
		WillReturnRows(sqlmock.NewRows([]string{"version", "dirty"}).AddRow(2, true))

	err = assertPlatformSchemaVersion(context.Background(), db, nil)
	if err == nil || !strings.Contains(err.Error(), "dirty") {
		t.Fatalf("expected dirty error, got %v", err)
	}
}

func TestAssertPlatformSchemaVersion_VersionBehind(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT version, dirty FROM schema_migrations").
		WillReturnRows(sqlmock.NewRows([]string{"version", "dirty"}).AddRow(1, false))

	err = assertPlatformSchemaVersion(context.Background(), db, nil)
	if err == nil || !strings.Contains(err.Error(), "< required") {
		t.Fatalf("expected version-behind error, got %v", err)
	}
}

// TestRunPlatformMigrations_SkipEnvVar verifies that SKIP_MIGRATIONS=true
// causes runPlatformMigrations to return nil without touching the database.
func TestRunPlatformMigrations_SkipEnvVar(t *testing.T) {
	t.Setenv("SKIP_MIGRATIONS", "true")

	// Pass a nil db — if the function tries to use it, it will panic/error.
	if err := runPlatformMigrations(context.Background(), nil, nil); err != nil {
		t.Fatalf("expected nil with SKIP_MIGRATIONS=true, got: %v", err)
	}
}

func TestAssertPlatformSchemaVersion_OK(t *testing.T) {
	// Use the actual embedded max version rather than a hardcoded constant
	// so the test stays green as new migrations are added.
	maxVer, err := pgmigrations.PlatformMaxVersion()
	if err != nil {
		t.Fatalf("PlatformMaxVersion: %v", err)
	}
	if maxVer == 0 {
		t.Skip("no platform migrations embedded yet")
	}

	db, mock, sqlErr := sqlmock.New()
	if sqlErr != nil {
		t.Fatal(sqlErr)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT version, dirty FROM schema_migrations").
		WillReturnRows(sqlmock.NewRows([]string{"version", "dirty"}).AddRow(maxVer, false))

	if err := assertPlatformSchemaVersion(context.Background(), db, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
