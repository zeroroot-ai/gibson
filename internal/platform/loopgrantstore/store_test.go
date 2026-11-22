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
	rows    [][]any
	pos     int
	err     error
	scanBad bool
}

func (r *fakeRows) Next() bool { r.pos++; return r.pos <= len(r.rows) }
func (r *fakeRows) Scan(dest ...any) error {
	if r.scanBad {
		return errors.New("scan failed")
	}
	return fakeRow{values: r.rows[r.pos-1]}.Scan(dest...)
}
func (r *fakeRows) Err() error { return r.err }
func (r *fakeRows) Close()     {}

var stamp = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)

type tenantDB struct {
	grants map[string]Grant
	// The knobs make one kind of statement fail.
	execErr, queryErr, rowErr, rowsErr error
	// scanBad makes a row scan fail.
	scanBad bool
}

func (d *tenantDB) row(g Grant) []any {
	return []any{g.ID, g.MemberID, g.AgentName, g.ToolClasses, g.HarnessCalls, g.Grantor, stamp}
}

func (d *tenantDB) SQL() datapool.SQL { return d }
func (d *tenantDB) Release()          {}

func (d *tenantDB) Exec(_ context.Context, _ string, args ...any) (int64, error) {
	if d.execErr != nil {
		return 0, d.execErr
	}
	delete(d.grants, args[0].(string))
	return 1, nil
}

func (d *tenantDB) QueryRow(_ context.Context, _ string, args ...any) datapool.Row {
	if d.rowErr != nil {
		return fakeRow{err: d.rowErr}
	}
	if len(args) == 7 { // the upsert
		g := Grant{
			ID: args[0].(string), MemberID: args[1].(string), AgentName: args[2].(string),
			ToolClasses: args[3].([]string), HarnessCalls: args[4].([]string), Grantor: args[5].(string),
			GrantedAt: args[6].(time.Time),
		}
		d.grants[g.MemberID] = g
		return fakeRow{values: d.row(g)}
	}
	g, ok := d.grants[args[0].(string)]
	if !ok {
		return fakeRow{err: datapool.ErrNoRows}
	}
	return fakeRow{values: d.row(g)}
}

func (d *tenantDB) Query(_ context.Context, _ string, args ...any) (datapool.Rows, error) {
	if d.queryErr != nil {
		return nil, d.queryErr
	}
	// The paging arguments are hasAfter, after and limit.
	hasAfter, after, limit := args[0].(bool), args[1].(string), args[2].(int)
	rows := &fakeRows{err: d.rowsErr, scanBad: d.scanBad}
	for _, name := range []string{"m-a", "m-b", "m-c"} {
		if hasAfter && name <= after {
			continue
		}
		if g, ok := d.grants[name]; ok && len(rows.rows) < limit {
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
		ID: id, MemberID: "m-a", AgentName: "intake-agent", ToolClasses: []string{"ticket", "paging"},
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
	assert.Equal(t, "intake-agent", put.AgentName)

	got, err := s.Get(ctx, "tenant-a", "m-a")
	require.NoError(t, err)
	assert.Equal(t, []string{"ticket", "paging"}, got.ToolClasses)
	assert.Equal(t, "user:alice", got.Grantor)

	all, err := s.ListPage(ctx, "tenant-a", "", false, 10)
	require.NoError(t, err)
	assert.Len(t, all, 1)

	require.NoError(t, s.Delete(ctx, "tenant-a", "m-a"))
	require.NoError(t, s.Delete(ctx, "tenant-a", "m-a"), "a second delete is idempotent")
	_, err = s.Get(ctx, "tenant-a", "m-a")
	require.ErrorIs(t, err, ErrNotFound)
}

// A grant of tenant B is not visible to tenant A.
func TestGetIsPerTenant(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	_, err := s.Put(ctx, "tenant-b", sample("gB"))
	require.NoError(t, err)

	_, err = s.Get(ctx, "tenant-a", "m-a")
	require.ErrorIs(t, err, ErrNotFound)
	all, err := s.ListPage(ctx, "tenant-a", "", false, 10)
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestPutRefusesIncompleteGrant(t *testing.T) {
	s := newStore()
	for _, g := range []Grant{
		{MemberID: "m", AgentName: "a", Grantor: "u"}, {ID: "i", AgentName: "a", Grantor: "u"},
		{ID: "i", MemberID: "m", Grantor: "u"}, {ID: "i", MemberID: "m", AgentName: "a"},
	} {
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

func TestListPage_PagesByMemberIDWithAKeyset(t *testing.T) {
	s := newStore()
	ctx := context.Background()
	for _, name := range []string{"m-a", "m-b", "m-c"} {
		g := sample("g-" + name)
		g.MemberID = name
		_, err := s.Put(ctx, "t", g)
		require.NoError(t, err)
	}
	first, err := s.ListPage(ctx, "t", "", false, 2)
	require.NoError(t, err)
	require.Len(t, first, 2)
	second, err := s.ListPage(ctx, "t", first[1].MemberID, true, 2)
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, "m-c", second[0].MemberID)
}

// Each method wraps the failure of the connection, of the statement and of the
// scan, and none of them returns a partial result.
func TestStoreFailuresAreWrapped(t *testing.T) {
	boom := errors.New("boom")
	ctx := context.Background()
	fail := func(mut func(*tenantDB)) *postgresStore {
		s := newStore()
		db := &tenantDB{grants: map[string]Grant{"m-a": sample("g1")}}
		mut(db)
		s.conns.(*fakeConns).dbs["t"] = db
		return s
	}
	t.Run("put", func(t *testing.T) {
		_, err := fail(func(d *tenantDB) { d.rowErr = boom }).Put(ctx, "t", sample("g2"))
		require.ErrorIs(t, err, boom)
	})
	t.Run("get", func(t *testing.T) {
		_, err := fail(func(d *tenantDB) { d.rowErr = boom }).Get(ctx, "t", "m-a")
		require.ErrorIs(t, err, boom)
		assert.NotErrorIs(t, err, ErrNotFound)
	})
	t.Run("delete", func(t *testing.T) {
		require.ErrorIs(t, fail(func(d *tenantDB) { d.execErr = boom }).Delete(ctx, "t", "m-a"), boom)
	})
	t.Run("list query", func(t *testing.T) {
		_, err := fail(func(d *tenantDB) { d.queryErr = boom }).ListPage(ctx, "t", "", false, 5)
		require.ErrorIs(t, err, boom)
	})
	t.Run("list scan", func(t *testing.T) {
		_, err := fail(func(d *tenantDB) { d.scanBad = true }).ListPage(ctx, "t", "", false, 5)
		require.Error(t, err)
	})
	t.Run("list rows", func(t *testing.T) {
		_, err := fail(func(d *tenantDB) { d.rowsErr = boom }).ListPage(ctx, "t", "", false, 5)
		require.ErrorIs(t, err, boom)
	})
	t.Run("connection", func(t *testing.T) {
		s := &postgresStore{conns: &fakeConns{err: boom}}
		_, err := s.Put(ctx, "t", sample("g"))
		require.ErrorIs(t, err, boom)
		_, err = s.ListPage(ctx, "t", "", false, 1)
		require.ErrorIs(t, err, boom)
		require.ErrorIs(t, s.Delete(ctx, "t", "a"), boom)
	})
}

func TestPoolConnsRefusesABadTenantAndAMissingPool(t *testing.T) {
	_, err := poolConns{}.For(context.Background(), "Bad Tenant")
	require.Error(t, err)
	assert.Panics(t, func() { NewPostgresStore(nil) })
}
