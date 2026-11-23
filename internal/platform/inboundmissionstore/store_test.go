// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package inboundmissionstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	lockKeys []string
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
func (d *fakeDB) Exec(_ context.Context, sql string, args ...any) (int64, error) {
	d.seen = append(d.seen, sql)
	if strings.Contains(sql, "pg_advisory_xact_lock") && len(args) > 0 {
		d.lockKeys = append(d.lockKeys, fmt.Sprint(args[0]))
	}
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
	hashes, _ := json.Marshal(e.TargetHashes)
	return []any{e.Agent, "pub-1", e.DefinitionID, e.DefinitionHash, targets, string(hashes), e.PublishedBy, created}
}

func sample() Entry {
	return Entry{
		Agent: "recon", DefinitionID: "def-1", DefinitionHash: "h-def", TargetIDs: []string{"t1", "t2"},
		TargetHashes: map[string]string{"t1": "h1", "t2": "h2"}, PublishedBy: "user:ana",
	}
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
		{"no agent", Entry{DefinitionID: "d", DefinitionHash: "h", TargetIDs: []string{"t"}}, &fakeDB{}, "needs an agent", nil},
		{"no definition", Entry{Agent: "a", DefinitionHash: "h", TargetIDs: []string{"t"}}, &fakeDB{}, "needs an agent", nil},
		{"no definition hash", Entry{Agent: "a", DefinitionID: "d", TargetIDs: []string{"t"}}, &fakeDB{}, "needs an agent", nil},
		{"no target", Entry{Agent: "a", DefinitionID: "d", DefinitionHash: "h"}, &fakeDB{}, "needs an agent", nil},
		{"no hash of a target", Entry{Agent: "a", DefinitionID: "d", DefinitionHash: "h", TargetIDs: []string{"t"}},
			&fakeDB{}, "needs the hash of target t", nil},
		{"no conn", e, &fakeDB{forErr: errBoom}, "boom", errBoom},
		{"insert fails", e, &fakeDB{exec: func(sql string) (int64, error) {
			if strings.HasPrefix(sql, "INSERT") {
				return 0, errBoom
			}
			return 1, nil
		}}, "insert", errBoom},
		{"the lock fails", e, &fakeDB{exec: func(string) (int64, error) { return 0, errBoom }}, "lock the agent", errBoom},
		{"read back fails", e, &fakeDB{exec: okExec,
			queryRow: func(string) datapool.Row { return fakeRow{err: errBoom} }}, "scan inbound mission row", errBoom},
		{"the agent holds another definition", otherDef, &fakeDB{exec: okExec, queryRow: stored}, "recon", ErrConflict},
		{"the agent holds other targets", otherTargets, &fakeDB{exec: okExec, queryRow: stored}, "recon", ErrConflict},
		{"the stored targets are not JSON", e, &fakeDB{exec: okExec, queryRow: func(string) datapool.Row {
			return fakeRow{values: []any{"recon", "pub-1", "def-1", "h", "not json", "{}", "", created}}
		}}, "decode the targets", nil},
		{"the stored hashes are not JSON", e, &fakeDB{exec: okExec, queryRow: func(string) datapool.Row {
			return fakeRow{values: []any{"recon", "pub-1", "def-1", "h", `["t1"]`, "nope", "", created}}
		}}, "decode the target hashes", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newStore(tt.db).Publish(context.Background(), "acme", tt.entry, nil)
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

// The same agent, definition and targets with new hashes saves the new pin, so an
// admin can publish again after the definition or a target changed.
func TestPublish_ANewPinReplacesTheOldPin(t *testing.T) {
	stored := sample()
	want := sample()
	want.DefinitionHash = "h-def-2"
	want.TargetHashes = map[string]string{"t1": "h1", "t2": "h2-new"}
	db := &fakeDB{exec: okExec, queryRow: func(sql string) datapool.Row {
		assert.Contains(t, sql, "FOR UPDATE", "the row is locked while the pin changes")
		return fakeRow{values: rowOf(stored)}
	}}

	got, err := newStore(db).Publish(context.Background(), "acme", want, nil)

	require.NoError(t, err)
	assert.Equal(t, "h-def-2", got.DefinitionHash)
	assert.Equal(t, "h2-new", got.TargetHashes["t2"])
	assert.Contains(t, strings.Join(db.seen, "\n"), "UPDATE inbound_missions SET definition_hash")

	failing := &fakeDB{queryRow: func(string) datapool.Row { return fakeRow{values: rowOf(stored)} },
		exec: func(sql string) (int64, error) {
			if strings.HasPrefix(sql, "UPDATE") {
				return 0, errBoom
			}
			return 1, nil
		}}
	_, err = newStore(failing).Publish(context.Background(), "acme", want, nil)
	require.ErrorIs(t, err, errBoom)
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

// Reserve writes the task row from the row of the publication in one statement.
// There is no count, so a publication with many open tasks takes one more.
func TestReserve_RecordsTheTaskWithNoCount(t *testing.T) {
	db := &fakeDB{exec: okExec}

	slot, err := newStore(db).Reserve(context.Background(), "acme", "recon", "agent_principal:9", "m-new")

	require.NoError(t, err)
	assert.NotEmpty(t, slot)
	assert.Equal(t, 1, db.released)
	require.Len(t, db.seen, 1, "one statement and no count")
	assert.Contains(t, db.seen[0], "INSERT INTO inbound_tasks")
	assert.Contains(t, db.seen[0], "FROM inbound_missions WHERE agent = $2", "the task names the live publication")
	assert.NotContains(t, db.seen[0], "count(")
}

func TestReserve_Failures(t *testing.T) {
	_, err := newStore(&fakeDB{exec: func(string) (int64, error) { return 0, nil }}).
		Reserve(context.Background(), "acme", "recon", "o", "m")
	require.ErrorIs(t, err, ErrNotFound, "no row of the publication means the agent is not published")

	_, err = newStore(&fakeDB{exec: func(string) (int64, error) { return 0, errBoom }}).
		Reserve(context.Background(), "acme", "recon", "o", "m")
	require.ErrorIs(t, err, errBoom)

	_, err = newStore(&fakeDB{forErr: errBoom}).Reserve(context.Background(), "acme", "recon", "o", "m")
	require.ErrorIs(t, err, errBoom)
}

func TestReleaseOwner(t *testing.T) {
	ok := &fakeDB{exec: okExec, queryRow: func(string) datapool.Row { return fakeRow{values: []any{"agent_principal:9", "recon"}} }}
	require.NoError(t, newStore(ok).Release(context.Background(), "acme", "slot"))
	owner, agent, err := newStore(ok).Owner(context.Background(), "acme", "m-1")
	require.NoError(t, err)
	assert.Equal(t, "agent_principal:9", owner)
	assert.Equal(t, "recon", agent)
	assert.NotContains(t, ok.seen[len(ok.seen)-1], "<> ''", "the owner query needs no filter of its own")

	none := &fakeDB{queryRow: func(string) datapool.Row { return fakeRow{err: datapool.ErrNoRows} }}
	_, _, err = newStore(none).Owner(context.Background(), "acme", "m-1")
	require.ErrorIs(t, err, ErrNotFound)

	bad := &fakeDB{exec: func(string) (int64, error) { return 0, errBoom },
		queryRow: func(string) datapool.Row { return fakeRow{err: errBoom} }}
	require.ErrorIs(t, newStore(bad).Release(context.Background(), "acme", "s"), errBoom)
	_, _, err = newStore(bad).Owner(context.Background(), "acme", "m")
	require.ErrorIs(t, err, errBoom)

	gone := &fakeDB{forErr: errBoom}
	require.ErrorIs(t, newStore(gone).Release(context.Background(), "acme", "s"), errBoom)
	_, _, err = newStore(gone).Owner(context.Background(), "acme", "m")
	require.ErrorIs(t, err, errBoom)
}

func TestWithIdentityLock_RunsTheFunctionUnderAnAdvisoryLockOfTheIdentity(t *testing.T) {
	db := &fakeDB{exec: okExec}
	ran := false

	err := newStore(db).WithIdentityLock(context.Background(), "acme", "agent_principal:9", func(Reader) error { ran = true; return nil })

	require.NoError(t, err)
	assert.True(t, ran)
	assert.Contains(t, db.seen[0], "pg_advisory_xact_lock", "the lock comes before the function")

	err = newStore(db).WithIdentityLock(context.Background(), "acme", "x", func(Reader) error { return errBoom })
	require.ErrorIs(t, err, errBoom)
	fail := &fakeDB{exec: func(string) (int64, error) { return 0, errBoom }}
	ran = false
	err = newStore(fail).WithIdentityLock(context.Background(), "acme", "x", func(Reader) error { ran = true; return nil })
	require.ErrorIs(t, err, errBoom)
	assert.False(t, ran, "the function does not run without the lock")
	require.ErrorIs(t, newStore(&fakeDB{forErr: errBoom}).WithIdentityLock(context.Background(), "acme", "x",
		func(Reader) error { return nil }), errBoom)
}

// Two publishes of one name run one after the other, because each takes a lock on
// the name before it reads or writes the row. The hook for a new row runs only when
// this call inserted the row, so a call that finds the row never deletes what a
// later grant wrote.
func TestPublish_TheHookRunsOnlyForANewRowUnderTheLockOfTheName(t *testing.T) {
	e := sample()
	stored := func(string) datapool.Row { return fakeRow{values: rowOf(e)} }
	for _, tt := range []struct {
		name     string
		inserted int64
		wantRuns int
	}{{"a new row", 1, 1}, {"an existing row", 0, 0}} {
		t.Run(tt.name, func(t *testing.T) {
			db := &fakeDB{queryRow: stored, exec: func(sql string) (int64, error) {
				if strings.HasPrefix(sql, "INSERT") {
					return tt.inserted, nil
				}
				return 1, nil
			}}
			runs := 0
			_, err := newStore(db).Publish(context.Background(), "acme", e, func(context.Context) error { runs++; return nil })

			require.NoError(t, err)
			assert.Equal(t, tt.wantRuns, runs)
			require.NotEmpty(t, db.seen)
			assert.Contains(t, db.seen[0], "pg_advisory_xact_lock", "the lock comes before the first read or write")
		})
	}

	failed := &fakeDB{queryRow: stored, exec: okExec}
	_, err := newStore(failed).Publish(context.Background(), "acme", e, func(context.Context) error { return errBoom })
	require.ErrorIs(t, err, errBoom, "a failed hook fails the publish, and the transaction undoes the insert")
}

// The function of the lock reads through the reader of the transaction. It takes no
// second connection from the pool.
func TestWithIdentityLock_TheReaderRunsInTheSameTransaction(t *testing.T) {
	e := sample()
	db := &fakeDB{exec: okExec, queryRow: func(string) datapool.Row { return fakeRow{values: rowOf(e)} }}

	var got *Entry
	err := newStore(db).WithIdentityLock(context.Background(), "acme", "agent_principal:9", func(r Reader) error {
		var gerr error
		got, gerr = r.Get(context.Background(), "recon")
		if gerr != nil {
			return fmt.Errorf("get: %w", gerr)
		}
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, "recon", got.Agent)
	assert.Equal(t, 1, db.released, "the lock and the read share one connection")
}

// Publish and an unpublish of one agent name take the same lock key, so they run one
// after the other. The unpublish deletes in the transaction that holds the lock.
func TestWithAgentLock_TakesTheLockOfPublishAndDeletesInTheSameTransaction(t *testing.T) {
	db := &fakeDB{exec: okExec, queryRow: func(string) datapool.Row { return fakeRow{values: rowOf(sample())} }}
	_, err := newStore(db).Publish(context.Background(), "acme", sample(), nil)
	require.NoError(t, err)
	publishKey := db.lockKeys[0]

	db2 := &fakeDB{exec: okExec}
	err = newStore(db2).WithAgentLock(context.Background(), "acme", "recon", func(tx AgentTx) error {
		return tx.Delete(context.Background(), "recon")
	})

	require.NoError(t, err)
	require.Len(t, db2.lockKeys, 1)
	assert.Equal(t, publishKey, db2.lockKeys[0], "the same lock key as Publish")
	assert.Contains(t, db2.seen[0], "pg_advisory_xact_lock", "the lock comes first")
	assert.Contains(t, strings.Join(db2.seen, "\n"), "DELETE FROM inbound_missions")
	assert.Equal(t, 1, db2.released, "one connection")

	none := &fakeDB{exec: func(sql string) (int64, error) {
		if strings.HasPrefix(sql, "DELETE") {
			return 0, nil
		}
		return 1, nil
	}}
	err = newStore(none).WithAgentLock(context.Background(), "acme", "recon", func(tx AgentTx) error {
		return tx.Delete(context.Background(), "recon")
	})
	require.ErrorIs(t, err, ErrNotFound)
}

func TestClaimMessage(t *testing.T) {
	ctx := context.Background()

	fresh := &fakeDB{exec: okExec}
	got, err := newStore(fresh).ClaimMessage(ctx, "acme", "5:recon:webhook:okta:e1", "m-1")
	require.NoError(t, err)
	assert.Equal(t, ClaimNew, got)
	assert.Contains(t, fresh.seen[1], "INSERT INTO inbound_messages")
	assert.Contains(t, fresh.seen[1], "inbound_messages.state = 'pending' AND inbound_messages.lease_until < now()",
		"only a pending claim whose lease ended can be taken over")

	exists := func(state string, expired, reserved bool) *fakeDB {
		return &fakeDB{
			exec:     func(string) (int64, error) { return 0, nil },
			queryRow: func(string) datapool.Row { return fakeRow{values: []any{state, expired, reserved}} },
		}
	}
	got, err = newStore(exists("started", false, true)).ClaimMessage(ctx, "acme", "k", "m-2")
	require.NoError(t, err)
	assert.Equal(t, ClaimDuplicate, got, "a started key is a duplicate")
	got, err = newStore(exists("pending", false, true)).ClaimMessage(ctx, "acme", "k", "m-2")
	require.NoError(t, err)
	assert.Equal(t, ClaimInFlight, got, "a pending key with a live lease is in work")
	got, err = newStore(exists("pending", true, true)).ClaimMessage(ctx, "acme", "k", "m-2")
	require.NoError(t, err)
	assert.Equal(t, ClaimDuplicate, got, "an expired lease with a task row is a duplicate: the mission may run")
	got, err = newStore(exists("pending", true, false)).ClaimMessage(ctx, "acme", "k", "m-2")
	require.NoError(t, err)
	assert.Equal(t, ClaimInFlight, got, "an expired lease with no task row that lost the race is in work")
	assert.Contains(t, fresh.seen[1], "NOT EXISTS (SELECT 1 FROM inbound_tasks WHERE inbound_tasks.mission_id = inbound_messages.mission_id)",
		"a lease is taken over only when no task row exists for the old mission")
}

func TestClaimMessage_Failures(t *testing.T) {
	ctx := context.Background()
	_, err := newStore(&fakeDB{forErr: errBoom}).ClaimMessage(ctx, "acme", "k", "m")
	require.ErrorIs(t, err, errBoom)

	deleteFails := &fakeDB{exec: func(string) (int64, error) { return 0, errBoom }}
	_, err = newStore(deleteFails).ClaimMessage(ctx, "acme", "k", "m")
	require.ErrorIs(t, err, errBoom, "the delete of old keys fails")

	insertFails := &fakeDB{exec: func(sql string) (int64, error) {
		if strings.HasPrefix(sql, "INSERT") {
			return 0, errBoom
		}
		return 0, nil
	}}
	_, err = newStore(insertFails).ClaimMessage(ctx, "acme", "k", "m")
	require.ErrorIs(t, err, errBoom, "the insert fails")

	conflict := func(row func(string) datapool.Row) *fakeDB {
		return &fakeDB{exec: func(string) (int64, error) { return 0, nil }, queryRow: row}
	}
	_, err = newStore(conflict(func(string) datapool.Row { return fakeRow{err: datapool.ErrNoRows} })).ClaimMessage(ctx, "acme", "k", "m")
	require.ErrorIs(t, err, ErrNotFound, "the row vanished between the two statements")
	_, err = newStore(conflict(func(string) datapool.Row { return fakeRow{err: errBoom} })).ClaimMessage(ctx, "acme", "k", "m")
	require.ErrorIs(t, err, errBoom, "the read of the state fails")
}

func TestClaimMessage_ReadsTheDatabaseOfTheTenant(t *testing.T) {
	var tenants []string
	db := &tenantRecordingDB{fakeDB: fakeDB{exec: okExec}, tenants: &tenants}
	s := &postgresStore{conns: db}
	_, err := s.ClaimMessage(context.Background(), "globex", "k", "m")
	require.NoError(t, err)
	require.NoError(t, s.ConfirmMessage(context.Background(), "acme", "k", "m"))
	require.NoError(t, s.ForgetMessage(context.Background(), "initech", "k", "m"))
	assert.Equal(t, []string{"globex", "acme", "initech"}, tenants, "each call uses the database of its own tenant")
}

type tenantRecordingDB struct {
	fakeDB
	tenants *[]string
}

func (d *tenantRecordingDB) For(_ context.Context, tenant string) (conn, error) {
	*d.tenants = append(*d.tenants, tenant)
	return &d.fakeDB, nil
}

func TestConfirmAndForgetMessage(t *testing.T) {
	ctx := context.Background()
	db := &fakeDB{exec: okExec}
	require.NoError(t, newStore(db).ConfirmMessage(ctx, "acme", "k", "m"))
	assert.Contains(t, db.seen[0], "SET state = 'started'")
	require.NoError(t, newStore(db).ForgetMessage(ctx, "acme", "k", "m"))
	assert.Contains(t, db.seen[1], "AND state = 'pending'", "a confirmed key is never deleted")

	gone := &fakeDB{exec: func(string) (int64, error) { return 0, nil }}
	require.ErrorIs(t, newStore(gone).ConfirmMessage(ctx, "acme", "k", "m"), ErrNotFound)
	boom := &fakeDB{exec: func(string) (int64, error) { return 0, errBoom }}
	require.ErrorIs(t, newStore(boom).ConfirmMessage(ctx, "acme", "k", "m"), errBoom)
	require.ErrorIs(t, newStore(boom).ForgetMessage(ctx, "acme", "k", "m"), errBoom)
	require.ErrorIs(t, newStore(&fakeDB{forErr: errBoom}).ConfirmMessage(ctx, "acme", "k", "m"), errBoom)
	require.ErrorIs(t, newStore(&fakeDB{forErr: errBoom}).ForgetMessage(ctx, "acme", "k", "m"), errBoom)
}
