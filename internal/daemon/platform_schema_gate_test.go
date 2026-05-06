// Copyright 2026 Zero Day AI.

package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
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

func TestAssertPlatformSchemaVersion_OK(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectQuery("SELECT version, dirty FROM schema_migrations").
		WillReturnRows(sqlmock.NewRows([]string{"version", "dirty"}).AddRow(2, false))

	if err := assertPlatformSchemaVersion(context.Background(), db, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
