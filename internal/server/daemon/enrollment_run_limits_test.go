package daemon

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// TestEnrollmentRunLimits_ReadsThroughTheLazyPool proves the dispatcher's
// source reads the cap the tenant-operator reported (gibson#597), resolves
// the pool on each call, and names both failures: no pool, and a failed read.
func TestEnrollmentRunLimits_ReadsThroughTheLazyPool(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var pool *sql.DB
	limits := &enrollmentRunLimits{db: func() *sql.DB { return pool }}

	if _, _, err := limits.AgentRunLimit(context.Background(), "acme", "breach-checker"); !errors.Is(err, errPlatformDBUnset) {
		t.Fatalf("before the pool exists: err = %v, want errPlatformDBUnset", err)
	}

	pool = db
	mock.ExpectQuery("SELECT max_runtime_seconds FROM agent_enrollment_limits").
		WithArgs("acme", "breach-checker").
		WillReturnRows(sqlmock.NewRows([]string{"max_runtime_seconds"}).AddRow(int64(900)))
	limit, ok, err := limits.AgentRunLimit(context.Background(), "acme", "breach-checker")
	if err != nil || !ok || limit != 15*time.Minute {
		t.Fatalf("AgentRunLimit = (%v, %v, %v), want (15m, true, nil)", limit, ok, err)
	}

	mock.ExpectQuery("SELECT max_runtime_seconds FROM agent_enrollment_limits").WillReturnError(errors.New("connection reset"))
	if _, _, err := limits.AgentRunLimit(context.Background(), "acme", "breach-checker"); err == nil || !strings.Contains(err.Error(), "enrollment run limits") {
		t.Fatalf("read failure = %v, want an error naming the enrollment run limits", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
