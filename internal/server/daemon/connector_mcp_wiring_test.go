// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// The daemon stores the tool count of a connector that it listed, and a
// failed write does not stop the list (gibson#723).
func TestRecordConnectorTools_StoresTheCount(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d := &daemonImpl{platformDB: db, logger: observability.NewLogger(observability.ConfigFromEnv())}

	mock.ExpectExec("UPDATE tenant_connectors").WithArgs("acme", "github", int32(3)).
		WillReturnResult(sqlmock.NewResult(0, 1))
	d.recordConnectorTools(context.Background(), "acme", "github", 3)

	mock.ExpectExec("UPDATE tenant_connectors").WillReturnError(errors.New("postgres down"))
	d.recordConnectorTools(context.Background(), "acme", "github", 3)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}

// With no platform database the daemon records nothing.
func TestRecordConnectorTools_NoDatabaseRecordsNothing(t *testing.T) {
	d := &daemonImpl{}
	d.recordConnectorTools(context.Background(), "acme", "github", 3)
}
