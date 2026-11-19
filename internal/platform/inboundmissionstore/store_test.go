// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package inboundmissionstore

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
	targets := `["` + strings.Join(e.TargetIDs, `","`) + `"]`
	return []any{e.Agent, e.DefinitionID, targets, e.PublishedBy, created}
}

func sample() Entry {
	return Entry{Agent: "recon", DefinitionID: "def-1", TargetIDs: []string{"t1", "t2"}, PublishedBy: "user:ana"}
}

func okExec(string) (int64, error) { return 1, nil }

func TestPublish(t *testing.T) {
	e := sample()
	otherDef, otherTargets := sample(), sample()
	otherDef.DefinitionID = "def-2"
	otherTargets.TargetIDs = []string{"t1"}
	stored := func(string) datapool.Row { return fakeRow{values: rowOf(e)} }
	tests := []struct {
		name   string
		entry  Entry
		db     *fakeDB
		want   string
		wantIs error
	}{
		{"stores and returns the entry", e, &fakeDB{exec: okExec, queryRow: stored}, "", nil},
		{"the same entry again", e,
			&fakeDB{exec: func(string) (int64, error) { return 0, nil }, queryRow: stored}, "", nil},
		{"no agent", Entry{DefinitionID: "d", TargetIDs: []string{"t"}}, &fakeDB{}, "needs an agent", nil},
		{"no definition", Entry{Agent: "a", TargetIDs: []string{"t"}}, &fakeDB{}, "needs an agent", nil},
		{"no target", Entry{Agent: "a", DefinitionID: "d"}, &fakeDB{}, "needs an agent", nil},
		{"no conn", e, &fakeDB{forErr: errBoom}, "boom", errBoom},
		{"insert fails", e, &fakeDB{exec: func(string) (int64, error) { return 0, errBoom }}, "insert", errBoom},
		{"read back fails", e, &fakeDB{exec: okExec,
			queryRow: func(string) datapool.Row { return fakeRow{err: errBoom} }}, "scan inbound mission row", errBoom},
		{"the agent holds another definition", otherDef, &fakeDB{exec: okExec, queryRow: stored}, "recon", ErrConflict},
		{"the agent holds other targets", otherTargets, &fakeDB{exec: okExec, queryRow: stored}, "recon", ErrConflict},
		{"the stored targets are not JSON", e, &fakeDB{exec: okExec, queryRow: func(string) datapool.Row {
			return fakeRow{values: []any{"recon", "def-1", "not json", "", created}}
		}}, "decode the targets", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newStore(tt.db).Publish(context.Background(), "acme", tt.entry)
			if tt.want == "" {
				require.NoError(t, err)
				assert.Equal(t, e.TargetIDs, got.TargetIDs)
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

func TestGet(t *testing.T) {
	e := sample()
	db := &fakeDB{queryRow: func(string) datapool.Row { return fakeRow{values: rowOf(e)} }}
	got, err := newStore(db).Get(context.Background(), "acme", "recon")
	require.NoError(t, err)
	assert.Equal(t, "def-1", got.DefinitionID)
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
			got, err := newStore(tt.db).Get(context.Background(), "acme", "recon")
			require.ErrorIs(t, err, tt.wantIs)
			assert.Nil(t, got)
		})
	}
}

func TestDelete(t *testing.T) {
	db := &fakeDB{exec: okExec}
	require.NoError(t, newStore(db).Delete(context.Background(), "acme", "recon"))
	assert.True(t, strings.HasPrefix(db.seen[0], "DELETE FROM inbound_missions"))

	tests := []struct {
		name   string
		db     *fakeDB
		wantIs error
	}{
		{"no conn", &fakeDB{forErr: errBoom}, errBoom},
		{"exec fails", &fakeDB{exec: func(string) (int64, error) { return 0, errBoom }}, errBoom},
		{"not published", &fakeDB{exec: func(string) (int64, error) { return 0, nil }}, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, newStore(tt.db).Delete(context.Background(), "acme", "recon"), tt.wantIs)
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
	assert.IsType(t, &postgresStore{}, NewPostgresStore(fakePool{}))
}

func TestListPage(t *testing.T) {
	a, b := sample(), sample()
	b.Agent = "tracer"
	db := &fakeDB{query: func(string) (datapool.Rows, error) {
		return &fakeRows{rows: [][]any{rowOf(a), rowOf(b)}}, nil
	}}

	got, err := newStore(db).ListPage(context.Background(), "acme", "alpha", true, 2)

	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "tracer", got[1].Agent)
	assert.Contains(t, db.seen[0], "ORDER BY agent ASC LIMIT")
	assert.Equal(t, 1, db.released)
}

func TestListPage_Failures(t *testing.T) {
	tests := []struct {
		name string
		db   *fakeDB
		want string
	}{
		{"no conn", &fakeDB{forErr: errBoom}, "boom"},
		{"query fails", &fakeDB{query: func(string) (datapool.Rows, error) { return nil, errBoom }}, "list page"},
		{"scan fails", &fakeDB{query: func(string) (datapool.Rows, error) {
			return &fakeRows{rows: [][]any{rowOf(sample())}, scanErr: errBoom}, nil
		}}, "scan inbound mission row"},
		{"rows fail", &fakeDB{query: func(string) (datapool.Rows, error) {
			return &fakeRows{err: errBoom}, nil
		}}, "list page rows"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newStore(tt.db).ListPage(context.Background(), "acme", "", false, 10)
			require.ErrorIs(t, err, errBoom)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
		})
	}
}
