// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

func TestListDesiredCatalogPlugins_ReturnsEveryPair(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := newPendingServer()
	srv.platformDB = db

	mock.ExpectQuery("FROM   tenant_catalog_plugins").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "plugin_id", "phase", "last_error"}).
			AddRow("acme", "github", "Ready", "").
			AddRow("acme", "left-the-catalog", "Ready", "").
			AddRow("globex", "github", "Pending", ""))

	resp, err := srv.ListDesiredCatalogPlugins(context.Background(), &daemonoperatorv1.ListDesiredCatalogPluginsRequest{})
	if err != nil {
		t.Fatalf("ListDesiredCatalogPlugins: %v", err)
	}
	// The row of a plugin the catalog no longer lists is not in the answer.
	if len(resp.GetPlugins()) != 2 || resp.GetPlugins()[1].GetTenantId() != "globex" || resp.GetPlugins()[1].GetPluginId() != "github" {
		t.Fatalf("plugins = %v", resp.GetPlugins())
	}
	first := resp.GetPlugins()[0]
	if !strings.Contains(first.GetImage(), "@sha256:") || len(first.GetEgressAllow()) == 0 {
		t.Fatalf("the answer must carry the catalog image and egress list, got %v", first)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestListDesiredCatalogPlugins_FailsClosed(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.ListDesiredCatalogPlugins(context.Background(), &daemonoperatorv1.ListDesiredCatalogPluginsRequest{})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("no db: code = %v, want Unavailable", status.Code(err))
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv.platformDB = db
	mock.ExpectQuery("FROM   tenant_catalog_plugins").WillReturnError(errors.New("db down"))
	_, err = srv.ListDesiredCatalogPlugins(context.Background(), &daemonoperatorv1.ListDesiredCatalogPluginsRequest{})
	if status.Code(err) != codes.Internal {
		t.Errorf("db error: code = %v, want Internal", status.Code(err))
	}
}

func TestReportCatalogPluginStatus_WritesTheReport(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv := newPendingServer()
	srv.platformDB = db

	mock.ExpectExec("UPDATE tenant_catalog_plugins").
		WithArgs("acme", "github", "Ready", "").
		WillReturnResult(sqlmock.NewResult(0, 1))
	resp, err := srv.ReportCatalogPluginStatus(context.Background(), &daemonoperatorv1.ReportCatalogPluginStatusRequest{
		TenantId: "acme", PluginId: "github", Phase: "Ready",
	})
	if err != nil || !resp.GetUpdated() {
		t.Fatalf("resp = %v, err = %v, want updated", resp, err)
	}

	// A report for a pair no tenant enabled changes nothing.
	mock.ExpectExec("UPDATE tenant_catalog_plugins").
		WithArgs("acme", "gitlab", "Ready", "").
		WillReturnResult(sqlmock.NewResult(0, 0))
	resp, err = srv.ReportCatalogPluginStatus(context.Background(), &daemonoperatorv1.ReportCatalogPluginStatusRequest{
		TenantId: "acme", PluginId: "gitlab", Phase: "Ready",
	})
	if err != nil || resp.GetUpdated() {
		t.Fatalf("resp = %v, err = %v, want not updated", resp, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestReportCatalogPluginStatus_RefusesBadInput(t *testing.T) {
	srv := newPendingServer()
	for name, req := range map[string]*daemonoperatorv1.ReportCatalogPluginStatusRequest{
		"no tenant": {PluginId: "github", Phase: "Ready"},
		"no plugin": {TenantId: "acme", Phase: "Ready"},
		"no phase":  {TenantId: "acme", PluginId: "github"},
	} {
		_, err := srv.ReportCatalogPluginStatus(context.Background(), req)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", name, status.Code(err))
		}
	}
	srv.platformDB = nil
	_, err := srv.ReportCatalogPluginStatus(context.Background(), &daemonoperatorv1.ReportCatalogPluginStatusRequest{
		TenantId: "acme", PluginId: "github", Phase: "Ready",
	})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("no db: code = %v, want Unavailable", status.Code(err))
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	srv.platformDB = db
	mock.ExpectExec("UPDATE tenant_catalog_plugins").WillReturnError(errors.New("db down"))
	_, err = srv.ReportCatalogPluginStatus(context.Background(), &daemonoperatorv1.ReportCatalogPluginStatusRequest{
		TenantId: "acme", PluginId: "github", Phase: "Ready",
	})
	if status.Code(err) != codes.Internal {
		t.Errorf("db error: code = %v, want Internal", status.Code(err))
	}
}
