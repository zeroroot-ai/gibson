// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/alicebob/miniredis/v2"
	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/audit/audittest"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// failingDurableWriter refuses each synchronous write.
type failingDurableWriter struct{ audittest.Recorder }

func (f *failingDurableWriter) WriteSync(context.Context, audit.Event) error {
	return errors.New("postgres is down")
}

func retentionAuditLogger(t *testing.T, w audit.DurableWriter) *audit.AuditLogger {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	if err != nil {
		t.Fatalf("state client: %v", err)
	}
	t.Cleanup(func() { _ = sc.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return audit.NewAuditLogger(ctx, sc, w, slog.Default())
}

// retentionServer returns a server where admin1 is a tenant admin of acme,
// with retention settings on sqlmock and an install period of installMonths.
func retentionServer(t *testing.T, installMonths int, w audit.DurableWriter) (*DaemonServer, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	settings, err := audit.NewRetentionSettings(db, installMonths)
	if err != nil {
		t.Fatalf("retention settings: %v", err)
	}
	srv := &DaemonServer{
		logger:     slog.Default(),
		authorizer: newFakeAuthorizer().allow("user:admin1", "admin", "tenant:acme"),
	}
	srv.WithAuditRetention(settings)
	srv.WithAuditLogger(retentionAuditLogger(t, w))
	return srv, mock
}

func TestGetAuditRetention(t *testing.T) {
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	t.Run("returns the period", func(t *testing.T) {
		srv, mock := retentionServer(t, 13, &audittest.Recorder{})
		mock.ExpectQuery("FROM audit_retention_tenant").WithArgs("acme").
			WillReturnRows(sqlmock.NewRows([]string{"months"}).AddRow(36))
		resp, err := srv.GetAuditRetention(ctx, &tenantv1.GetAuditRetentionRequest{})
		if err != nil {
			t.Fatalf("GetAuditRetention: %v", err)
		}
		got := resp.GetRetention()
		if got.GetInstallMonths() != 13 || got.GetTenantMonths() != 36 || got.GetEffectiveMonths() != 36 {
			t.Fatalf("retention = %+v", got)
		}
	})
	t.Run("a member who is not an admin is refused", func(t *testing.T) {
		srv, _ := retentionServer(t, 13, &audittest.Recorder{})
		member := ctxWithTenantAdmin(context.Background(), "acme", "member1")
		_, err := srv.GetAuditRetention(member, &tenantv1.GetAuditRetentionRequest{})
		if status_grpc.Code(err) != codes.PermissionDenied {
			t.Fatalf("want PermissionDenied, got %v", err)
		}
	})
	t.Run("no settings wired", func(t *testing.T) {
		srv := &DaemonServer{logger: slog.Default(), authorizer: newFakeAuthorizer().allow("user:admin1", "admin", "tenant:acme")}
		_, err := srv.GetAuditRetention(ctx, &tenantv1.GetAuditRetentionRequest{})
		if status_grpc.Code(err) != codes.Unavailable {
			t.Fatalf("want Unavailable, got %v", err)
		}
	})
	t.Run("a read failure", func(t *testing.T) {
		srv, mock := retentionServer(t, 13, &audittest.Recorder{})
		mock.ExpectQuery("FROM audit_retention_tenant").WillReturnError(errors.New("down"))
		_, err := srv.GetAuditRetention(ctx, &tenantv1.GetAuditRetentionRequest{})
		if status_grpc.Code(err) != codes.Internal {
			t.Fatalf("want Internal, got %v", err)
		}
	})
}

func TestSetAuditRetention(t *testing.T) {
	ctx := ctxWithTenantAdmin(context.Background(), "acme", "admin1")

	t.Run("a longer period is recorded first, then written", func(t *testing.T) {
		rec := &audittest.Recorder{}
		srv, mock := retentionServer(t, 13, rec)
		mock.ExpectExec("INSERT INTO audit_retention_tenant").WithArgs("acme", 24, "admin1").
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery("FROM audit_retention_tenant").WithArgs("acme").
			WillReturnRows(sqlmock.NewRows([]string{"months"}).AddRow(24))
		resp, err := srv.SetAuditRetention(ctx, &tenantv1.SetAuditRetentionRequest{Months: 24})
		if err != nil {
			t.Fatalf("SetAuditRetention: %v", err)
		}
		if resp.GetRetention().GetEffectiveMonths() != 24 {
			t.Fatalf("retention = %+v", resp.GetRetention())
		}
		events := rec.Events()
		if len(events) != 1 || events[0].Action != auditActionRetentionSet {
			t.Fatalf("want one durable %s record, got %+v", auditActionRetentionSet, events)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a period under the install is refused and recorded as a failure", func(t *testing.T) {
		rec := &audittest.Recorder{}
		srv, mock := retentionServer(t, 24, rec)
		_, err := srv.SetAuditRetention(ctx, &tenantv1.SetAuditRetentionRequest{Months: 13})
		if status_grpc.Code(err) != codes.InvalidArgument {
			t.Fatalf("want InvalidArgument, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("a refused period writes nothing: %v", err)
		}
	})
	t.Run("no change without its audit record", func(t *testing.T) {
		srv, mock := retentionServer(t, 13, &failingDurableWriter{})
		_, err := srv.SetAuditRetention(ctx, &tenantv1.SetAuditRetentionRequest{Months: 24})
		if status_grpc.Code(err) != codes.Unavailable {
			t.Fatalf("want Unavailable, got %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("nothing is written without the record: %v", err)
		}
	})
	t.Run("no audit logger", func(t *testing.T) {
		srv, _ := retentionServer(t, 13, &audittest.Recorder{})
		srv.auditLogger = nil
		_, err := srv.SetAuditRetention(ctx, &tenantv1.SetAuditRetentionRequest{Months: 24})
		if status_grpc.Code(err) != codes.Unavailable {
			t.Fatalf("want Unavailable, got %v", err)
		}
	})
	t.Run("a write failure", func(t *testing.T) {
		srv, mock := retentionServer(t, 13, &audittest.Recorder{})
		mock.ExpectExec("INSERT INTO audit_retention_tenant").WillReturnError(errors.New("down"))
		_, err := srv.SetAuditRetention(ctx, &tenantv1.SetAuditRetentionRequest{Months: 24})
		if status_grpc.Code(err) != codes.Internal {
			t.Fatalf("want Internal, got %v", err)
		}
	})
	t.Run("a read failure after the write", func(t *testing.T) {
		srv, mock := retentionServer(t, 13, &audittest.Recorder{})
		mock.ExpectExec("DELETE FROM audit_retention_tenant").WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectQuery("FROM audit_retention_tenant").WillReturnError(errors.New("down"))
		_, err := srv.SetAuditRetention(ctx, &tenantv1.SetAuditRetentionRequest{Months: 0})
		if status_grpc.Code(err) != codes.Internal {
			t.Fatalf("want Internal, got %v", err)
		}
	})
	t.Run("no tenant", func(t *testing.T) {
		srv, _ := retentionServer(t, 13, &audittest.Recorder{})
		_, err := srv.SetAuditRetention(context.Background(), &tenantv1.SetAuditRetentionRequest{Months: 24})
		if status_grpc.Code(err) != codes.InvalidArgument {
			t.Fatalf("want InvalidArgument, got %v", err)
		}
	})
}
