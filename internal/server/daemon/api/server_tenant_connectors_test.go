// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

func connectorServer(t *testing.T) (*DaemonServer, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := newPendingServer()
	srv.platformDB = db
	return srv, mock
}

func TestListDesiredConnectors_ReturnsCatalogFields(t *testing.T) {
	srv, mock := connectorServer(t)
	mock.ExpectQuery("FROM tenant_connectors ORDER BY tenant_id, connector_id").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "connector_id", "phase", "discovered_tools", "last_error"}).
			AddRow("acme", "gitlab", "Ready", 3, "").
			AddRow("acme", "left-the-catalog", "Ready", 0, "").
			AddRow("globex", "gitlab", "Pending", 0, ""))

	resp, err := srv.ListDesiredConnectors(context.Background(), &daemonoperatorv1.ListDesiredConnectorsRequest{})
	if err != nil {
		t.Fatalf("ListDesiredConnectors: %v", err)
	}
	got := resp.GetConnectors()
	if len(got) != 2 {
		t.Fatalf("connectors = %v, want the two catalog rows", got)
	}
	if got[0].GetShape() != "Remote" || got[0].GetEndpoint() == "" || got[0].GetAuth() == "" {
		t.Errorf("the answer must carry the catalog fields, got %v", got[0])
	}
	if got[1].GetTenantId() != "globex" {
		t.Errorf("second = %v", got[1])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestTenantConnectorRPCs_FailClosed(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	ctx := context.Background()
	if _, err := srv.ListDesiredConnectors(ctx, &daemonoperatorv1.ListDesiredConnectorsRequest{}); status.Code(err) != codes.Unavailable {
		t.Errorf("list with no db: %v", err)
	}
	if _, err := srv.ReportConnectorStatus(ctx, &daemonoperatorv1.ReportConnectorStatusRequest{
		TenantId: "acme", ConnectorId: "gitlab", Phase: "Ready",
	}); status.Code(err) != codes.Unavailable {
		t.Errorf("report with no db: %v", err)
	}

	srv2, mock := connectorServer(t)
	mock.ExpectQuery("FROM tenant_connectors").WillReturnError(errors.New("db down"))
	if _, err := srv2.ListDesiredConnectors(ctx, &daemonoperatorv1.ListDesiredConnectorsRequest{}); status.Code(err) != codes.Internal {
		t.Errorf("list with a db error: %v", err)
	}
}

func TestReportConnectorStatus(t *testing.T) {
	srv, mock := connectorServer(t)
	ctx := context.Background()
	mock.ExpectExec("UPDATE tenant_connectors").WithArgs("acme", "gitlab", "Ready", "").
		WillReturnResult(sqlmock.NewResult(0, 1))
	resp, err := srv.ReportConnectorStatus(ctx, &daemonoperatorv1.ReportConnectorStatusRequest{
		TenantId: "acme", ConnectorId: "gitlab", Phase: "Ready",
	})
	if err != nil || !resp.GetUpdated() {
		t.Fatalf("report: %v %v", resp, err)
	}
	for _, bad := range []*daemonoperatorv1.ReportConnectorStatusRequest{
		{ConnectorId: "gitlab", Phase: "Ready"},
		{TenantId: "acme", Phase: "Ready"},
		{TenantId: "acme", ConnectorId: "gitlab"},
	} {
		if _, err := srv.ReportConnectorStatus(ctx, bad); status.Code(err) != codes.InvalidArgument {
			t.Errorf("request %v: code %v, want InvalidArgument", bad, status.Code(err))
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestAdoptConnector(t *testing.T) {
	srv, mock := connectorServer(t)
	ctx := context.Background()
	mock.ExpectExec("INSERT INTO tenant_connectors").WithArgs("acme", "gitlab").
		WillReturnResult(sqlmock.NewResult(0, 1))
	if _, err := srv.AdoptConnector(ctx, &daemonoperatorv1.AdoptConnectorRequest{TenantId: "acme", ConnectorId: "gitlab"}); err != nil {
		t.Fatalf("adopt: %v", err)
	}
	if _, err := srv.AdoptConnector(ctx, &daemonoperatorv1.AdoptConnectorRequest{
		TenantId: "acme", ConnectorId: "not-in-catalog",
	}); status.Code(err) != codes.NotFound {
		t.Errorf("a connector outside the catalog: code %v, want NotFound", status.Code(err))
	}
	if _, err := srv.AdoptConnector(ctx, &daemonoperatorv1.AdoptConnectorRequest{TenantId: "acme"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no connector: code %v, want InvalidArgument", status.Code(err))
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
