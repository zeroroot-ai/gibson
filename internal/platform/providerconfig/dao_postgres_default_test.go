// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providerconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// fakeQuerier answers QueryRow with one row and records every Exec. It is the
// pgQuerier seam the DAO reads the default provider through.
type fakeQuerier struct {
	row   fakeRow
	execs []string
}

type fakeRow struct {
	name string
	err  error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.name
	return nil
}

func (f *fakeQuerier) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, sql)
	return pgconn.CommandTag{}, nil
}

func (f *fakeQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not used")
}

func (f *fakeQuerier) QueryRow(context.Context, string, ...any) pgx.Row { return f.row }

// The default provider is the one flagged is_default; no flag is ErrNotFound,
// and a query failure is named (gibson#505: the provider_config_meta pointer
// that used to shadow the column is gone).
func TestDAO_GetDefault(t *testing.T) {
	d := newProviderConfigDAO(&fakeQuerier{row: fakeRow{name: "openai"}})
	name, err := d.getDefault(context.Background())
	if err != nil || name != "openai" {
		t.Fatalf("getDefault = %q, %v; want openai", name, err)
	}

	d = newProviderConfigDAO(&fakeQuerier{row: fakeRow{err: pgx.ErrNoRows}})
	if _, err := d.getDefault(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("getDefault with no default = %v, want ErrNotFound", err)
	}

	boom := errors.New("boom")
	d = newProviderConfigDAO(&fakeQuerier{row: fakeRow{err: boom}})
	if _, err := d.getDefault(context.Background()); !errors.Is(err, boom) || !strings.Contains(err.Error(), "get default") {
		t.Fatalf("getDefault with a failing query = %v, want boom wrapped and named", err)
	}
}

// setDefault writes only the column.
func TestDAO_SetDefault_WritesTheColumnOnly(t *testing.T) {
	q := &fakeQuerier{}
	if err := newProviderConfigDAO(q).setDefault(context.Background(), "openai"); err != nil {
		t.Fatalf("setDefault: %v", err)
	}
	if len(q.execs) != 1 || !strings.Contains(q.execs[0], "SET is_default = (name = $1)") {
		t.Fatalf("execs = %q, want one UPDATE of is_default", q.execs)
	}
}
