// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package outsideagentstore

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/sdk/auth"
)

// The fake answers each statement from a function that the test sets. The SQL
// itself needs a real Postgres.

var errBoom = errors.New("boom")

type fakeRow struct {
	values []any
	err    error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, v := range r.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(v))
	}
	return nil
}

type fakeRows struct {
	rows    [][]any
	scanErr error
	err     error
	pos     int
}

func (r *fakeRows) Next() bool { r.pos++; return r.pos <= len(r.rows) }
func (r *fakeRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	return fakeRow{values: r.rows[r.pos-1]}.Scan(dest...)
}
func (r *fakeRows) Err() error { return r.err }
func (r *fakeRows) Close()     {}

type fakeDB struct {
	forErr   error
	exec     func(sql string) (int64, error)
	queryRow func(sql string) datapool.Row
	query    func(sql string) (datapool.Rows, error)
	released int
	seen     []string
}

func (d *fakeDB) For(context.Context, string) (conn, error) {
	if d.forErr != nil {
		return nil, d.forErr
	}
	return d, nil
}
func (d *fakeDB) SQL() datapool.SQL { return d }
func (d *fakeDB) Release()          { d.released++ }
func (d *fakeDB) InTx(_ context.Context, fn func(datapool.SQL) error) error {
	return fn(d)
}
func (d *fakeDB) Exec(_ context.Context, sql string, _ ...any) (int64, error) {
	d.seen = append(d.seen, sql)
	return d.exec(sql)
}
func (d *fakeDB) QueryRow(_ context.Context, sql string, _ ...any) datapool.Row {
	d.seen = append(d.seen, sql)
	return d.queryRow(sql)
}
func (d *fakeDB) Query(_ context.Context, sql string, _ ...any) (datapool.Rows, error) {
	d.seen = append(d.seen, sql)
	return d.query(sql)
}

func newStore(db *fakeDB) *postgresStore { return &postgresStore{conns: db} }

var created = time.Date(2026, 11, 1, 10, 0, 0, 0, time.FixedZone("x", 3600))

func rowOf(e Entry) []any {
	return []any{e.Name, e.A2AURL, e.CredentialSecret, e.CABundleSecret, e.Description, created}
}

func sample() Entry {
	return Entry{
		Name: "scout", A2AURL: "https://a.example/a2a", CredentialSecret: "scout-key",
		CABundleSecret: "scout-ca", Description: "recon agent",
	}
}

func okExec(string) (int64, error) { return 1, nil }

func TestRegister(t *testing.T) {
	e := sample()
	other := sample()
	other.A2AURL = "https://b.example/a2a"
	tests := []struct {
		name    string
		entry   Entry
		db      *fakeDB
		want    string
		wantIs  error
		wantGot bool
	}{
		{"stores and returns the entry", e,
			&fakeDB{exec: okExec, queryRow: func(string) datapool.Row { return fakeRow{values: rowOf(e)} }}, "", nil, true},
		{"the same entry again", e,
			&fakeDB{exec: func(string) (int64, error) { return 0, nil },
				queryRow: func(string) datapool.Row { return fakeRow{values: rowOf(e)} }}, "", nil, true},
		{"no name", Entry{A2AURL: "u"}, &fakeDB{}, "needs a name and a URL", nil, false},
		{"no URL", Entry{Name: "n"}, &fakeDB{}, "needs a name and a URL", nil, false},
		{"no conn", e, &fakeDB{forErr: errBoom}, "boom", errBoom, false},
		{"insert fails", e, &fakeDB{exec: func(string) (int64, error) { return 0, errBoom }},
			"insert", errBoom, false},
		{"read back fails", e, &fakeDB{exec: okExec,
			queryRow: func(string) datapool.Row { return fakeRow{err: errBoom} }}, "scan outside agent row", errBoom, false},
		{"the name holds other fields", other,
			&fakeDB{exec: okExec, queryRow: func(string) datapool.Row { return fakeRow{values: rowOf(e)} }},
			"scout", ErrConflict, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newStore(tt.db).Register(context.Background(), "acme", tt.entry)
			if tt.want == "" {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, e.Name, got.Name)
				assert.Equal(t, time.UTC, got.CreatedAt.Location(), "the creation time is UTC")
				assert.True(t, got.CreatedAt.Equal(created))
				return
			}
			require.Error(t, err)
			assert.Nil(t, got)
			assert.Contains(t, err.Error(), tt.want)
			if tt.wantIs != nil {
				assert.ErrorIs(t, err, tt.wantIs)
			}
		})
	}
}

func TestRegister_ConflictOnEachField(t *testing.T) {
	stored := sample()
	fields := map[string]func(*Entry){
		"credential":  func(e *Entry) { e.CredentialSecret = "x" },
		"ca bundle":   func(e *Entry) { e.CABundleSecret = "x" },
		"description": func(e *Entry) { e.Description = "x" },
	}
	for name, change := range fields {
		t.Run(name, func(t *testing.T) {
			want := sample()
			change(&want)
			db := &fakeDB{exec: okExec, queryRow: func(string) datapool.Row { return fakeRow{values: rowOf(stored)} }}
			_, err := newStore(db).Register(context.Background(), "acme", want)
			assert.ErrorIs(t, err, ErrConflict)
			assert.Equal(t, 1, db.released)
		})
	}
}

func TestList(t *testing.T) {
	a, b := sample(), sample()
	b.Name = "tracer"
	db := &fakeDB{query: func(string) (datapool.Rows, error) {
		return &fakeRows{rows: [][]any{rowOf(a), rowOf(b)}}, nil
	}}

	got, err := newStore(db).List(context.Background(), "acme")

	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "scout", got[0].Name)
	assert.Equal(t, "tracer", got[1].Name)
	assert.Contains(t, db.seen[0], "ORDER BY name ASC")
	assert.Equal(t, 1, db.released)
}

func TestList_Failures(t *testing.T) {
	tests := []struct {
		name string
		db   *fakeDB
		want string
	}{
		{"no conn", &fakeDB{forErr: errBoom}, "boom"},
		{"query fails", &fakeDB{query: func(string) (datapool.Rows, error) { return nil, errBoom }}, "list"},
		{"scan fails", &fakeDB{query: func(string) (datapool.Rows, error) {
			return &fakeRows{rows: [][]any{rowOf(sample())}, scanErr: errBoom}, nil
		}}, "scan outside agent row"},
		{"rows fail", &fakeDB{query: func(string) (datapool.Rows, error) {
			return &fakeRows{err: errBoom}, nil
		}}, "list rows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newStore(tt.db).List(context.Background(), "acme")
			require.Error(t, err)
			assert.ErrorIs(t, err, errBoom)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
		})
	}
}

func TestGet(t *testing.T) {
	e := sample()
	db := &fakeDB{queryRow: func(string) datapool.Row { return fakeRow{values: rowOf(e)} }}
	got, err := newStore(db).Get(context.Background(), "acme", "scout")
	require.NoError(t, err)
	assert.Equal(t, "https://a.example/a2a", got.A2AURL)
	assert.Equal(t, 1, db.released)

	tests := []struct {
		name   string
		db     *fakeDB
		wantIs error
	}{
		{"no conn", &fakeDB{forErr: errBoom}, errBoom},
		{"no row", &fakeDB{queryRow: func(string) datapool.Row { return fakeRow{err: datapool.ErrNoRows} }}, ErrNotFound},
		{"read fails", &fakeDB{queryRow: func(string) datapool.Row { return fakeRow{err: errBoom} }}, errBoom},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newStore(tt.db).Get(context.Background(), "acme", "scout")
			require.ErrorIs(t, err, tt.wantIs)
			assert.Nil(t, got)
		})
	}
}

func TestDelete(t *testing.T) {
	db := &fakeDB{exec: func(string) (int64, error) { return 1, nil }}
	require.NoError(t, newStore(db).Delete(context.Background(), "acme", "scout"))
	assert.True(t, strings.HasPrefix(db.seen[0], "DELETE FROM outside_agents"))

	tests := []struct {
		name   string
		db     *fakeDB
		wantIs error
	}{
		{"no conn", &fakeDB{forErr: errBoom}, errBoom},
		{"exec fails", &fakeDB{exec: func(string) (int64, error) { return 0, errBoom }}, errBoom},
		{"no such name", &fakeDB{exec: func(string) (int64, error) { return 0, nil }}, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, newStore(tt.db).Delete(context.Background(), "acme", "scout"), tt.wantIs)
		})
	}
}

// fakePool answers only For.
type fakePool struct {
	datapool.Pool
	err error
}

func (p fakePool) For(context.Context, auth.TenantID) (*datapool.Conn, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &datapool.Conn{}, nil
}

func TestPoolConns_For(t *testing.T) {
	_, err := poolConns{pool: fakePool{}}.For(context.Background(), "Not A Tenant!")
	require.ErrorContains(t, err, "invalid tenant")

	_, err = poolConns{pool: fakePool{err: errBoom}}.For(context.Background(), "acme")
	require.ErrorIs(t, err, errBoom)
	assert.Contains(t, err.Error(), "acquire conn for acme")

	c, err := poolConns{pool: fakePool{}}.For(context.Background(), "acme")
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestNewPostgresStore(t *testing.T) {
	assert.Panics(t, func() { NewPostgresStore(nil) }, "a nil pool is a configuration error")

	s := NewPostgresStore(fakePool{})
	require.NotNil(t, s)
	assert.IsType(t, &postgresStore{}, s)
}
