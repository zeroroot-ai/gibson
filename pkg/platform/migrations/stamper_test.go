package migrations

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStamp_NilDB(t *testing.T) {
	t.Parallel()
	if err := Stamp(context.Background(), nil, KindTenant); err == nil {
		t.Error("expected error on nil *sql.DB")
	}
}

func TestStamp_UnknownKind(t *testing.T) {
	t.Parallel()
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := Stamp(context.Background(), db, Kind("nonsense")); err == nil {
		t.Error("expected error on unknown kind")
	}
}

func TestStamp_SchemaMigrationsAlreadyExists_NoOp(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("schema_migrations").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	if err := Stamp(context.Background(), db, KindTenant); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestStamp_FreshDB_NoFingerprint_NoOp(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("schema_migrations").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("tenant_secrets").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	if err := Stamp(context.Background(), db, KindTenant); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestStamp_LegacyTenantState_StampsVersion7(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("schema_migrations").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("tenant_secrets").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	mock.ExpectBegin()
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO schema_migrations").
		WithArgs(uint(7)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := Stamp(context.Background(), db, KindTenant); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// TestStamp_LegacyPlatformState_StampsCurrentVersion verifies that the
// legacy-state stamper inserts the *current* PlatformMaxVersion() row
// (not a hardcoded constant). The expected value tracks
// platformMaxVersionWant in migrations_test.go; bump alongside any new
// platform migration.
func TestStamp_LegacyPlatformState_StampsCurrentVersion(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("schema_migrations").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("tenant_secrets_broker_config").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	mock.ExpectBegin()
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO schema_migrations").
		WithArgs(uint(9)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := Stamp(context.Background(), db, KindPlatform); err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestStamp_PropagatesProbeError(t *testing.T) {
	t.Parallel()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	want := errors.New("connection reset")
	mock.ExpectQuery("SELECT EXISTS").
		WithArgs("schema_migrations").
		WillReturnError(want)

	err = Stamp(context.Background(), db, KindTenant)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, want) {
		t.Errorf("expected wrapped probe error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
