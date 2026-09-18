// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeAdminConn records the statements the terminate path issues and answers
// them from a script, so the path is proven without a Postgres.
type fakeAdminConn struct {
	exists     bool
	backends   []fakeBackend
	execs      []string
	queryErr   error
	existsErr  error
	scanErr    error
	rowsClosed bool
}

type fakeBackend struct {
	pid int32
	ok  bool
}

func (f *fakeAdminConn) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, sql)
	return pgconn.CommandTag{}, nil
}

func (f *fakeAdminConn) QueryRow(_ context.Context, _ string, _ ...any) pgx.Row {
	return fakeRow{exists: f.exists, err: f.existsErr}
}

func (f *fakeAdminConn) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return &fakeRows{backends: f.backends, scanErr: f.scanErr, conn: f}, nil
}

type fakeRow struct {
	exists bool
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*bool)) = r.exists
	return nil
}

type fakeRows struct {
	pgx.Rows
	backends []fakeBackend
	i        int
	scanErr  error
	conn     *fakeAdminConn
}

func (r *fakeRows) Next() bool { return r.i < len(r.backends) }
func (r *fakeRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	b := r.backends[r.i]
	r.i++
	*(dest[0].(*int32)) = b.pid
	*(dest[1].(*bool)) = b.ok
	return nil
}
func (r *fakeRows) Err() error { return nil }
func (r *fakeRows) Close()     { r.conn.rowsClosed = true }

func TestTerminateTenantBackends(t *testing.T) {
	p := &pgProvisioner{}
	ctx := context.Background()

	t.Run("absent database is a no-op", func(t *testing.T) {
		f := &fakeAdminConn{exists: false}
		if err := p.terminateTenantBackends(ctx, f, "tenant_x", "tenant_x_app"); err != nil {
			t.Fatalf("err = %v", err)
		}
		if len(f.execs) != 0 {
			t.Fatalf("no statement may run for an absent database, got %v", f.execs)
		}
	})

	// THE FIXTURE THIS EXISTS FOR: on CNPG the admin is not a superuser, so it
	// refuses new connections, takes the tenant role, and terminates every
	// backend itself before the drop.
	t.Run("live database: connections refused, role granted, every backend terminated", func(t *testing.T) {
		f := &fakeAdminConn{exists: true, backends: []fakeBackend{{101, true}, {102, true}}}
		if err := p.terminateTenantBackends(ctx, f, "tenant_x", "tenant_x_app"); err != nil {
			t.Fatalf("err = %v", err)
		}
		want := []string{`ALTER DATABASE "tenant_x" WITH ALLOW_CONNECTIONS false`, `GRANT "tenant_x_app" TO CURRENT_USER`}
		if len(f.execs) != 2 || f.execs[0] != want[0] || f.execs[1] != want[1] {
			t.Fatalf("statements = %q, want %q", f.execs, want)
		}
		if !f.rowsClosed {
			t.Fatalf("the backend rows must be closed")
		}
	})

	t.Run("a backend that will not terminate names the role the admin must hold", func(t *testing.T) {
		f := &fakeAdminConn{exists: true, backends: []fakeBackend{{101, false}}}
		err := p.terminateTenantBackends(ctx, f, "tenant_x", "tenant_x_app")
		if err == nil || !strings.Contains(err.Error(), "101") || !strings.Contains(err.Error(), "tenant_x_app") {
			t.Fatalf("err = %v, want the pid and the role named", err)
		}
	})

	t.Run("errors from the catalog, the query and the scan are reported", func(t *testing.T) {
		boom := errors.New("boom")
		for name, f := range map[string]*fakeAdminConn{
			"catalog": {existsErr: boom},
			"query":   {exists: true, queryErr: boom},
			"scan":    {exists: true, backends: []fakeBackend{{1, true}}, scanErr: boom},
		} {
			if err := p.terminateTenantBackends(ctx, f, "tenant_x", "tenant_x_app"); !errors.Is(err, boom) {
				t.Errorf("%s: err = %v, want boom wrapped", name, err)
			}
		}
	})
}
