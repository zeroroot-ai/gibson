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
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "connector_id", "phase", "discovered_tools", "last_error", "endpoint", "oauth_client_id", "oauth_client_secret_name", "variables"}).
			AddRow("acme", "gitlab", "Ready", 3, "", "", "", "", "{}").
			AddRow("acme", "left-the-catalog", "Ready", 0, "", "", "", "", "{}").
			AddRow("globex", "gitlab", "Pending", 0, "", "", "", "", "{}"))

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

// A stored value that the catalog rules refuse fails loudly: the connector is
// not desired, and its status says Failed with the cause (review M10).
func TestListDesiredConnectors_ARefusedValueFailsTheConnector(t *testing.T) {
	srv, mock := connectorServer(t)
	mock.ExpectQuery("FROM tenant_connectors ORDER BY tenant_id, connector_id").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "connector_id", "phase", "discovered_tools", "last_error", "endpoint", "oauth_client_id", "oauth_client_secret_name", "variables"}).
			AddRow("acme", "github-fixloop", "Ready", 3, "", "", "", "", `{"api_url":"https://169.254.169.254.nip.io/"}`))
	mock.ExpectExec("UPDATE tenant_connectors").WithArgs("acme", "github-fixloop", "Failed", sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := srv.ListDesiredConnectors(context.Background(), &daemonoperatorv1.ListDesiredConnectorsRequest{})
	if err != nil {
		t.Fatalf("ListDesiredConnectors: %v", err)
	}
	if len(resp.GetConnectors()) != 0 {
		t.Fatalf("connectors = %v, want none", resp.GetConnectors())
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
	mock.ExpectExec("INSERT INTO tenant_connectors").WithArgs("acme", "gitlab", "", "", "", "{}").
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

// The egress allow-list follows the endpoint of the tenant, and a stored
// endpoint that the manifest no longer allows reaches no host (gibson#1534).
func TestListDesiredConnectors_EndpointFollowsTheTenant(t *testing.T) {
	cols := []string{"tenant_id", "connector_id", "phase", "discovered_tools", "last_error",
		"endpoint", "oauth_client_id", "oauth_client_secret_name", "variables"}
	srv, mock := connectorServer(t)
	mock.ExpectQuery("FROM tenant_connectors ORDER BY tenant_id, connector_id").
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow("acme", "datadog", "Ready", 0, "", "https://mcp.datadoghq.eu/v1/mcp", "", "", "{}").
			AddRow("globex", "datadog", "Ready", 0, "", "", "", "", "{}").
			AddRow("initech", "datadog", "Ready", 0, "", "https://mcp.evil.example/v1/mcp", "", "", "{}"))

	resp, err := srv.ListDesiredConnectors(context.Background(), &daemonoperatorv1.ListDesiredConnectorsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	got := resp.GetConnectors()
	if len(got) != 3 {
		t.Fatalf("connectors = %v", got)
	}
	if got[0].GetEndpoint() != "https://mcp.datadoghq.eu/v1/mcp" ||
		len(got[0].GetEgressAllow()) != 1 || got[0].GetEgressAllow()[0] != "mcp.datadoghq.eu:443" {
		t.Errorf("the EU tenant got endpoint %q egress %v", got[0].GetEndpoint(), got[0].GetEgressAllow())
	}
	if got[1].GetEndpoint() != "https://mcp.datadoghq.com/v1/mcp" || got[1].GetEgressAllow()[0] != "mcp.datadoghq.com:443" {
		t.Errorf("the default tenant got endpoint %q egress %v", got[1].GetEndpoint(), got[1].GetEgressAllow())
	}
	if got[2].GetEndpoint() != "" || len(got[2].GetEgressAllow()) != 0 {
		t.Errorf("a stored endpoint outside the patterns must reach no host, got %q %v",
			got[2].GetEndpoint(), got[2].GetEgressAllow())
	}
}

// A Hosted entry sends its configuration to the operator (gibson#1536). The
// answer holds the names of secrets and never a value.
func TestListDesiredConnectors_HostedConfiguration(t *testing.T) {
	cols := []string{"tenant_id", "connector_id", "phase", "discovered_tools", "last_error",
		"endpoint", "oauth_client_id", "oauth_client_secret_name", "variables"}
	srv, mock := connectorServer(t)
	mock.ExpectQuery("FROM tenant_connectors").
		WillReturnRows(sqlmock.NewRows(cols).AddRow("acme", "crowdstrike-falcon", "Ready", 0, "", "", "", "", "{}"))
	resp, err := srv.ListDesiredConnectors(context.Background(), &daemonoperatorv1.ListDesiredConnectorsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	d := resp.GetConnectors()[0]
	if len(d.GetCredentials()) != 2 || d.GetCredentials()[0].GetTargetEnv() != "FALCON_CLIENT_ID" ||
		d.GetCredentials()[1].GetTargetEnv() != "FALCON_CLIENT_SECRET" {
		t.Errorf("credentials = %v", d.GetCredentials())
	}
	if d.GetEnv()["FALCON_BASE_URL"] == "" || len(d.GetArgs()) == 0 {
		t.Errorf("env %v args %v", d.GetEnv(), d.GetArgs())
	}
}
