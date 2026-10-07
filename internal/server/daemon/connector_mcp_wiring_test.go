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

// The daemon builds one MCP client, and with no SPIFFE JWT source a request
// carries no token.
func TestConnectorMCPClient_OneClientAndNoTokenWithNoSource(t *testing.T) {
	d := testDaemonForRegistry(t)
	first, second := d.connectorMCPClient(), d.connectorMCPClient()
	if first == nil || first != second {
		t.Fatal("the daemon must build exactly one MCP client")
	}
	tok, err := d.connectorProxyToken(context.Background())
	if err != nil || tok != "" {
		t.Fatalf("token = %q, err = %v; want no token and no error", tok, err)
	}
}
