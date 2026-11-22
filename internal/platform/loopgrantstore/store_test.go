// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package loopgrantstore

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
)

// The fake keeps one in-memory table for each tenant, as the per-tenant
// database does. The SQL itself needs a real Postgres.

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
	rows [][]any
	pos  int
}

func (r *fakeRows) Next() bool { r.pos++; return r.pos <= len(r.rows) }
func (r *fakeRows) Scan(dest ...any) error {
	return fakeRow{values: r.rows[r.pos-1]}.Scan(dest...)
}
func (r *fakeRows) Err() error { return nil }
func (r *fakeRows) Close()     {}

var stamp = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

type tenantDB struct {
	grants map[string]Grant
}

func (d *tenantDB) row(g Grant) []any {
	return []any{g.ID, g.AgentName, g.ToolClasses, g.HarnessCalls, g.Grantor, stamp}
}

func (d *tenantDB) SQL() datapool.SQL { return d }
func (d *tenantDB) Release()          {}

func (d *tenantDB) Exec(_ context.Context, _ string, args ...any) (int64, error) {
	delete(d.grants, args[0].(string))
	return 1, nil
}

func (d *tenantDB) QueryRow(_ context.Context, _ string, args ...any) datapool.Row {
	if len(args) == 5 { // the upsert
		g := Grant{
			ID: args[0].(string), AgentName: args[1].(string), ToolClasses: args[2].([]string),
			HarnessCalls: args[3].([]string), Grantor: args[4].(string),
		}
		d.grants[g.AgentName] = g
		return fakeRow{values: d.row(g)}
	}
	g, ok := d.grants[args[0].(string)]
	if !ok {
		return fakeRow{err: datapool.ErrNoRows}
	}
	return fakeRow{values: d.row(g)}
}

func (d *tenantDB) Query(context.Context, string, ...any) (datapool.Rows, error) {
	rows := &fakeRows{}
	for _, name := range []string{"a-agent", "b-agent"} {
		if g, ok := d.grants[name]; ok {
			rows.rows = append(rows.rows, d.row(g))
		}
	}
	return rows, nil
}

type fakeConns struct {
	dbs map[string]*tenantDB
	err error
}

func (f *fakeConns) For(_ context.Context, tenant string) (conn, error) {
	if f.err != nil {
		return nil, f.err
	}
	db, ok := f.dbs[tenant]
	if !ok {
		db = &tenantDB{grants: map[string]Grant{}}
		f.dbs[tenant] = db
	}
	return db, nil
}

func newStore() *postgresStore {
	return &postgresStore{conns: &fakeConns{dbs: map[string]*tenantDB{}}}
}

func sample(id string) Grant {
	return Grant{
		ID: id, AgentName: "a-agent", ToolClasses: []string{"ticket", "paging"},
		HarnessCalls: []string{"SubmitFinding"}, Grantor: "user:alice",
	}
}

func TestPutGetListDelete(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	put, err := s.Put(ctx, "tenant-a", sample("g1"))
	require.NoError(t, err)
	assert.Equal(t, "g1", put.ID)
	assert.Equal(t, stamp, put.GrantedAt)

	got, err := s.Get(ctx, "tenant-a", "a-agent")
	require.NoError(t, err)
	assert.Equal(t, []string{"ticket", "paging"}, got.ToolClasses)
	assert.Equal(t, "user:alice", got.Grantor)

	all, err := s.List(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Len(t, all, 1)

	require.NoError(t, s.Delete(ctx, "tenant-a", "a-agent"))
	require.NoError(t, s.Delete(ctx, "tenant-a", "a-agent"), "a second delete is idempotent")
	_, err = s.Get(ctx, "tenant-a", "a-agent")
	require.ErrorIs(t, err, ErrNotFound)
}

// A grant of tenant B is not visible to tenant A.
func TestGetIsPerTenant(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	_, err := s.Put(ctx, "tenant-b", sample("gB"))
	require.NoError(t, err)

	_, err = s.Get(ctx, "tenant-a", "a-agent")
	require.ErrorIs(t, err, ErrNotFound)
	all, err := s.List(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestPutRefusesIncompleteGrant(t *testing.T) {
	s := newStore()
	for _, g := range []Grant{{AgentName: "a", Grantor: "u"}, {ID: "i", Grantor: "u"}, {ID: "i", AgentName: "a"}} {
		_, err := s.Put(context.Background(), "t", g)
		assert.Error(t, err)
	}
}

func TestConnectionErrorIsWrapped(t *testing.T) {
	boom := errors.New("boom")
	s := &postgresStore{conns: &fakeConns{err: boom}}
	_, err := s.Get(context.Background(), "t", "a")
	assert.ErrorIs(t, err, boom)
}
