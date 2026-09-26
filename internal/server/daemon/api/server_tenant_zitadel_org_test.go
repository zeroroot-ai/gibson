// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// server_tenant_zitadel_org_test.go — tests for SetTenantZitadelOrg and the
// ZitadelOrgResolver reverse lookup (ADR-0093 decision 4, hosted#195).
package api

import (
	"context"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// fakePgUniqueViolation simulates a Postgres unique-constraint violation
// (SQLSTATE 23505), the shape isPgUniqueViolation matches on.
type fakePgUniqueViolation struct{}

func (fakePgUniqueViolation) Error() string    { return "duplicate key value violates unique constraint" }
func (fakePgUniqueViolation) SQLState() string { return "23505" }

func expectEnsureZitadelOrgsTable(mock sqlmock.Sqlmock) {
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_zitadel_orgs").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("CREATE UNIQUE INDEX IF NOT EXISTS tenant_zitadel_orgs_org_uidx").
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func TestSetTenantZitadelOrg_EmptyTenantID_InvalidArgument(t *testing.T) {
	srv := newPendingServer()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv.platformDB = db

	_, err = srv.SetTenantZitadelOrg(context.Background(),
		&daemonoperatorv1.SetTenantZitadelOrgRequest{ZitadelOrgId: "123"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestSetTenantZitadelOrg_EmptyOrgID_InvalidArgument(t *testing.T) {
	srv := newPendingServer()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv.platformDB = db

	_, err = srv.SetTenantZitadelOrg(context.Background(),
		&daemonoperatorv1.SetTenantZitadelOrgRequest{TenantId: "acme"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// TestSetTenantZitadelOrg_RefusesThePlatformOrg is the ADR-0093 decision 4
// guard: mapping the platform org (where the Platform owner and service
// accounts live) to a tenant would give them a tenant. Refused before any
// database write.
func TestSetTenantZitadelOrg_RefusesThePlatformOrg(t *testing.T) {
	t.Setenv(envIDPZitadelOrgID, "platform-org-1")
	srv := newPendingServer()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv.platformDB = db

	_, err = srv.SetTenantZitadelOrg(context.Background(),
		&daemonoperatorv1.SetTenantZitadelOrgRequest{TenantId: "acme", ZitadelOrgId: "platform-org-1"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for the platform org, got %v", err)
	}
	// No table-ensure, no insert: refused before touching the database.
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestSetTenantZitadelOrg_FreshInsert(t *testing.T) {
	t.Setenv(envIDPZitadelOrgID, "platform-org-1")
	srv := newPendingServer()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv.platformDB = db

	expectEnsureZitadelOrgsTable(mock)
	mock.ExpectExec("INSERT INTO tenant_zitadel_orgs").
		WithArgs("acme", "org-123").
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = srv.SetTenantZitadelOrg(context.Background(),
		&daemonoperatorv1.SetTenantZitadelOrgRequest{TenantId: "acme", ZitadelOrgId: "org-123"})
	if err != nil {
		t.Fatalf("SetTenantZitadelOrg: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// TestSetTenantZitadelOrg_SecondTenantForOneOrg_FailedPrecondition is the
// migration-027 unique index in effect: an org already mapped to a
// different tenant refuses with FailedPrecondition, never a 500.
func TestSetTenantZitadelOrg_SecondTenantForOneOrg_FailedPrecondition(t *testing.T) {
	srv := newPendingServer()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv.platformDB = db

	expectEnsureZitadelOrgsTable(mock)
	mock.ExpectExec("INSERT INTO tenant_zitadel_orgs").
		WithArgs("beta", "org-123").
		WillReturnError(fakePgUniqueViolation{})

	_, err = srv.SetTenantZitadelOrg(context.Background(),
		&daemonoperatorv1.SetTenantZitadelOrgRequest{TenantId: "beta", ZitadelOrgId: "org-123"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition on a unique violation, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestSetTenantZitadelOrg_NoDB_Unavailable(t *testing.T) {
	srv := newPendingServer()
	_, err := srv.SetTenantZitadelOrg(context.Background(),
		&daemonoperatorv1.SetTenantZitadelOrgRequest{TenantId: "acme", ZitadelOrgId: "org-123"})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable with no platform DB, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// ZitadelOrgResolver.TenantForOrg — the reverse lookup the daemon's
// org-tenant route (org_tenant_route.go) reads.
// ---------------------------------------------------------------------------

func TestZitadelOrgResolver_TenantForOrg_Mapped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("SELECT tenant_id FROM tenant_zitadel_orgs WHERE zitadel_org_id = \\$1").
		WithArgs("org-123").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme"))

	r := NewZitadelOrgResolver(db)
	tenantID, err := r.TenantForOrg(context.Background(), "org-123")
	if err != nil {
		t.Fatalf("TenantForOrg: %v", err)
	}
	if tenantID != "acme" {
		t.Fatalf("tenantID = %q, want acme", tenantID)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestZitadelOrgResolver_TenantForOrg_Unmapped(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectQuery("SELECT tenant_id FROM tenant_zitadel_orgs WHERE zitadel_org_id = \\$1").
		WithArgs("org-999").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}))

	r := NewZitadelOrgResolver(db)
	tenantID, err := r.TenantForOrg(context.Background(), "org-999")
	if err != nil {
		t.Fatalf("TenantForOrg: %v", err)
	}
	if tenantID != "" {
		t.Fatalf("tenantID = %q, want empty for an unmapped org", tenantID)
	}
}

func TestZitadelOrgResolver_TenantForOrg_NilDB_ReturnsEmpty(t *testing.T) {
	r := NewZitadelOrgResolver(nil)
	tenantID, err := r.TenantForOrg(context.Background(), "org-123")
	if err != nil {
		t.Fatalf("TenantForOrg with nil db: %v", err)
	}
	if tenantID != "" {
		t.Fatalf("tenantID = %q, want empty with no DB configured", tenantID)
	}
}

func TestZitadelOrgResolver_TenantForOrg_NilResolver_ReturnsEmpty(t *testing.T) {
	var r *ZitadelOrgResolver
	tenantID, err := r.TenantForOrg(context.Background(), "org-123")
	if err != nil {
		t.Fatalf("TenantForOrg on a nil resolver: %v", err)
	}
	if tenantID != "" {
		t.Fatalf("tenantID = %q, want empty on a nil resolver", tenantID)
	}
}
