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

// versionQuerier plays a tenant database at a given schema version. It answers
// the version query, records every other statement, and serves one provider row
// shaped by the columns that the statement names.
type versionQuerier struct {
	version    int64
	versionErr error
	queries    []string
	execs      []string
	rowWindow  int
}

type columnRow struct {
	fields func(dest []any) error
}

func (r columnRow) Scan(dest ...any) error { return r.fields(dest) }

func (q *versionQuerier) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	q.execs = append(q.execs, sql)
	return pgconn.CommandTag{}, nil
}

func (q *versionQuerier) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	q.queries = append(q.queries, sql)
	return nil, errors.New("stop after recording the statement")
}

func (q *versionQuerier) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	if strings.Contains(sql, "schema_migrations") {
		return columnRow{fields: func(dest []any) error {
			if q.versionErr != nil {
				return q.versionErr
			}
			*(dest[0].(*int64)) = q.version
			return nil
		}}
	}
	q.queries = append(q.queries, sql)
	withWindow := strings.Contains(sql, "default_model_context_window")
	return columnRow{fields: func(dest []any) error {
		// id, type, default_model, [window], is_default, enabled, capabilities,
		// default_embedding_model, created_at, updated_at
		i := 0
		*(dest[i].(*string)) = "id-1"
		i++
		*(dest[i].(*string)) = "anthropic"
		i++
		*(dest[i].(*string)) = "claude-x"
		i++
		if withWindow {
			*(dest[i].(*int)) = q.rowWindow
			i++
		}
		if len(dest) != i+6 {
			return errors.New("the statement names a column set that the scan does not match")
		}
		return nil
	}}
}

// R1: the daemon can roll ahead of the tenant operator. On a tenant database
// below migration 016 the daemon never names the window column, so the provider
// list still loads and the window reads as unreported (0).
func TestDAO_WindowColumnIsReadOnlyFromMigration016(t *testing.T) {
	cases := []struct {
		name       string
		version    int64
		versionErr error
		wantColumn bool
		wantWindow int
	}{
		{"version 15 has no column", 15, nil, false, 0},
		{"version 16 has the column", 16, nil, true, 200000},
		{"a later version has the column", 17, nil, true, 200000},
		{"no schema_migrations table counts as not migrated", 0, errors.New(`relation "schema_migrations" does not exist`), false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := &versionQuerier{version: tc.version, versionErr: tc.versionErr, rowWindow: 200000}
			d := newProviderConfigDAO(q)

			cfg, err := d.get(context.Background(), "acme", "p")
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if got := strings.Contains(q.queries[0], "default_model_context_window"); got != tc.wantColumn {
				t.Errorf("get names the window column = %v, want %v\n%s", got, tc.wantColumn, q.queries[0])
			}
			if cfg.DefaultModelContextWindow != tc.wantWindow {
				t.Errorf("window = %d, want %d", cfg.DefaultModelContextWindow, tc.wantWindow)
			}
			if cfg.DefaultModel != "claude-x" {
				t.Errorf("the provider still loads on a database at this version, got model %q", cfg.DefaultModel)
			}

			_, _ = d.list(context.Background(), "acme")
			if got := strings.Contains(q.queries[len(q.queries)-1], "default_model_context_window"); got != tc.wantColumn {
				t.Errorf("list names the window column = %v, want %v", got, tc.wantColumn)
			}

			in := &ProviderConfigInput{Name: "p", Type: "anthropic", DefaultModel: "claude-x", DefaultModelContextWindow: 200000}
			created, err := d.insert(context.Background(), "acme", in)
			if err != nil {
				t.Fatalf("insert: %v", err)
			}
			if got := strings.Contains(q.execs[len(q.execs)-1], "default_model_context_window"); got != tc.wantColumn {
				t.Errorf("insert names the window column = %v, want %v", got, tc.wantColumn)
			}
			wantStored := 0
			if tc.wantColumn {
				wantStored = 200000
			}
			if created.DefaultModelContextWindow != wantStored {
				t.Errorf("insert reports window %d, want %d", created.DefaultModelContextWindow, wantStored)
			}
		})
	}
}
