// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
)

// TestBankTenantLister_ReadsReadyTenantsFromTenantStatus proves the bank
// reconciler gets its tenants from platform Postgres (gibson#661): the query
// takes only tenants whose data plane is ready and that are not in teardown,
// and a row whose id cannot be a tenant id is skipped.
func TestBankTenantLister_ReadsReadyTenantsFromTenantStatus(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// The filter is in the SQL, so the test pins the two predicates. A query
	// that drops one would hand a member to a tenant with no database, or to
	// a tenant in teardown.
	mock.ExpectQuery(`FROM tenant_status\s+WHERE data_plane_ready\s+AND phase NOT IN \('Terminating', 'Terminated'\)\s+ORDER BY tenant_id`).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).
			AddRow("acme").AddRow("Not A Tenant!").AddRow("globex"))

	lister := &bankTenantLister{db: func() *sql.DB { return db }}
	got, err := lister.ListTenants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].String() != "acme" || got[1].String() != "globex" {
		t.Fatalf("tenants = %v, want acme and globex", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// TestBankTenantsQuery_HoldsBothPredicates is the failing fixture of the
// filter: the query text must name the ready gate and both teardown phases.
func TestBankTenantsQuery_HoldsBothPredicates(t *testing.T) {
	q := regexp.MustCompile(`\s+`).ReplaceAllString(bankTenantsQuery, " ")
	for _, want := range []string{"FROM tenant_status", "WHERE data_plane_ready", "'Terminating'", "'Terminated'"} {
		if !strings.Contains(q, want) {
			t.Errorf("the tenant query lost %q: %s", want, q)
		}
	}
}

// TestBankTenantLister_FailuresAreNamed proves a pass fails with a named
// error, and lists no tenant, when the pool is not open yet, when the query
// fails, and when a row cannot be read.
func TestBankTenantLister_FailuresAreNamed(t *testing.T) {
	none := &bankTenantLister{db: func() *sql.DB { return nil }}
	if _, err := none.ListTenants(context.Background()); !errors.Is(err, errBankPlatformDBUnset) {
		t.Fatalf("no pool: err = %v, want errBankPlatformDBUnset", err)
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lister := &bankTenantLister{db: func() *sql.DB { return db }}

	mock.ExpectQuery("FROM tenant_status").WillReturnError(errors.New("connection reset"))
	if got, err := lister.ListTenants(context.Background()); err == nil || got != nil || !strings.Contains(err.Error(), "tenant_status") {
		t.Fatalf("query failure: tenants=%v err=%v, want a named error and no tenant", got, err)
	}

	mock.ExpectQuery("FROM tenant_status").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(nil))
	if _, err := lister.ListTenants(context.Background()); err == nil || !strings.Contains(err.Error(), "tenant_status row") {
		t.Fatalf("scan failure: err = %v, want a named error", err)
	}

	mock.ExpectQuery("FROM tenant_status").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme").RowError(0, errors.New("stream broke")))
	if _, err := lister.ListTenants(context.Background()); err == nil {
		t.Fatal("a row error must fail the pass")
	}
}
