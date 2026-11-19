// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pgstore

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/sdk/auth"
)

// The scripted fake answers each statement with a fixed reply. A test sets the
// reply that it needs. The fake also records each statement and its arguments.

var errScript = errors.New("scripted failure")

type scriptRows struct {
	rows    [][]any
	scanErr error
	err     error
	pos     int
	closed  bool
}

func (r *scriptRows) Next() bool { r.pos++; return r.pos <= len(r.rows) }

func (r *scriptRows) Scan(dest ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	for i, v := range r.rows[r.pos-1] {
		target := reflect.ValueOf(dest[i]).Elem()
		if v == nil {
			target.Set(reflect.Zero(target.Type()))
			continue
		}
		target.Set(reflect.ValueOf(v))
	}
	return nil
}

func (r *scriptRows) Err() error { return r.err }
func (r *scriptRows) Close()     { r.closed = true }

type scriptRow struct {
	values []any
	err    error
}

func (r scriptRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	for i, v := range r.values {
		reflect.ValueOf(dest[i]).Elem().Set(reflect.ValueOf(v))
	}
	return nil
}

type statement struct {
	sql  string
	args []any
}

// scriptDB is conns, conn and datapool.SQL in one value.
type scriptDB struct {
	forErr   error
	queryRow func(sql string) datapool.Row
	query    func(sql string) (datapool.Rows, error)
	log      []statement
	released int
}

func (d *scriptDB) For(_ context.Context, _ string) (conn, error) {
	if d.forErr != nil {
		return nil, d.forErr
	}
	return d, nil
}
func (d *scriptDB) SQL() datapool.SQL { return d }
func (d *scriptDB) Release()          { d.released++ }
func (d *scriptDB) InTx(_ context.Context, fn func(datapool.SQL) error) error {
	return fn(d)
}
func (d *scriptDB) Exec(_ context.Context, sql string, args ...any) (int64, error) {
	d.log = append(d.log, statement{sql, args})
	return 1, nil
}
func (d *scriptDB) QueryRow(_ context.Context, sql string, args ...any) datapool.Row {
	d.log = append(d.log, statement{sql, args})
	return d.queryRow(sql)
}
func (d *scriptDB) Query(_ context.Context, sql string, args ...any) (datapool.Rows, error) {
	d.log = append(d.log, statement{sql, args})
	return d.query(sql)
}

// byTable answers a statement on the finding_evidence table with ev and each
// other statement with main.
func byTable(main, ev func() (datapool.Rows, error)) func(string) (datapool.Rows, error) {
	return func(sql string) (datapool.Rows, error) {
		if strings.Contains(sql, "FROM finding_evidence") {
			return ev()
		}
		return main()
	}
}

func rowsOf(rows ...[]any) func() (datapool.Rows, error) {
	return func() (datapool.Rows, error) { return &scriptRows{rows: rows}, nil }
}

func docOf(t *testing.T, f finding.EnhancedFinding) []byte {
	t.Helper()
	doc, err := json.Marshal(f)
	require.NoError(t, err)
	return doc
}

func scriptFinding(title string) finding.EnhancedFinding {
	return newFinding(types.NewID(), title, agent.SeverityHigh, time.Now())
}

func TestFind_ReturnsThePageAndTheTotal(t *testing.T) {
	a, b := scriptFinding("one"), scriptFinding("two")
	db := &scriptDB{
		queryRow: func(string) datapool.Row { return scriptRow{values: []any{7}} },
		query:    byTable(rowsOf([]any{docOf(t, a)}, []any{docOf(t, b)}), nil),
	}
	mission := types.NewID()

	got, total, err := newScriptStore(db).Find(context.Background(), "acme",
		Query{MissionID: mission, Limit: 2, Offset: 4})

	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, got, 2)
	assert.Equal(t, a.ID, got[0].ID)
	assert.Equal(t, b.ID, got[1].ID)
	assert.Equal(t, 1, db.released)
	require.Len(t, db.log, 2)
	assert.Contains(t, db.log[0].sql, "SELECT count(*) FROM findings WHERE mission_id = $1")
	assert.Contains(t, db.log[1].sql, "ORDER BY created_at DESC, id LIMIT $2 OFFSET $3")
	assert.Equal(t, []any{mission.String(), 2, 4}, db.log[1].args)
}

func oneRow(v any) func(string) datapool.Row {
	return func(string) datapool.Row { return scriptRow{values: []any{v}} }
}

func newScriptStore(db *scriptDB) *Store { return &Store{conns: db} }

func TestFind_Failures(t *testing.T) {
	good := docOf(t, scriptFinding("one"))
	count := func(string) datapool.Row { return scriptRow{values: []any{1}} }
	tests := []struct {
		name  string
		db    *scriptDB
		query Query
		want  string
	}{
		{"bad query", &scriptDB{}, Query{MissionID: "nope"}, "mission ID"},
		{"no conn", &scriptDB{forErr: errScript}, Query{}, "scripted failure"},
		{"count fails", &scriptDB{queryRow: func(string) datapool.Row { return scriptRow{err: errScript} }},
			Query{}, "count findings"},
		{"list fails", &scriptDB{queryRow: count,
			query: func(string) (datapool.Rows, error) { return nil, errScript }}, Query{}, "list findings"},
		{"scan fails", &scriptDB{queryRow: count,
			query: func(string) (datapool.Rows, error) {
				return &scriptRows{rows: [][]any{{good}}, scanErr: errScript}, nil
			}}, Query{}, "scan finding"},
		{"document is not JSON", &scriptDB{queryRow: count, query: byTable(rowsOf([]any{[]byte("{")}), nil)},
			Query{}, "decode finding"},
		{"rows fail", &scriptDB{queryRow: count,
			query: func(string) (datapool.Rows, error) { return &scriptRows{err: errScript}, nil }},
			Query{}, "list findings"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, total, err := newScriptStore(tt.db).Find(context.Background(), "acme", tt.query)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
			assert.Zero(t, total)
		})
	}
}

func TestFind_NoFilterHasNoWhere(t *testing.T) {
	db := &scriptDB{
		queryRow: func(string) datapool.Row { return scriptRow{values: []any{0}} },
		query:    byTable(rowsOf(), nil),
	}
	got, total, err := newScriptStore(db).Find(context.Background(), "acme", Query{})
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.NotNil(t, got, "an empty page is a list, not nil")
	assert.Zero(t, total)
	assert.Equal(t, "SELECT count(*) FROM findings", db.log[0].sql)
	assert.Equal(t, []any{100, 0}, db.log[1].args)
}

func evidenceRowFor(id string, tier int16, call *string, typeName, title, meta string) []any {
	return []any{id, tier, call, typeName, title, "content of " + title, []byte(meta)}
}

func TestFindWithEvidence_AttachesEvidenceToItsFinding(t *testing.T) {
	a, b := scriptFinding("one"), scriptFinding("two")
	call := "call-1"
	db := &scriptDB{
		queryRow: func(string) datapool.Row { return scriptRow{values: []any{2}} },
		query: byTable(
			rowsOf([]any{docOf(t, a)}, []any{docOf(t, b)}),
			rowsOf(
				evidenceRowFor(a.ID.String(), 1, &call, "EVIDENCE_TYPE_LOG", "first", `{"k":"v"}`),
				evidenceRowFor(a.ID.String(), 2, nil, "EVIDENCE_TYPE_LOG", "second", `{}`),
				evidenceRowFor(b.ID.String(), 2, nil, "EVIDENCE_TYPE_LOG", "other", `{}`),
			)),
	}

	got, total, err := newScriptStore(db).FindWithEvidence(context.Background(), "acme", Query{})

	require.NoError(t, err)
	assert.Equal(t, 2, total)
	require.Len(t, got, 2)
	require.Len(t, got[0].Evidence, 2)
	assert.Equal(t, "first", got[0].Evidence[0].GetTitle())
	assert.Equal(t, "call-1", got[0].Evidence[0].GetToolCallId())
	assert.Equal(t, map[string]string{"k": "v"}, got[0].Evidence[0].GetMetadata())
	assert.Equal(t, "second", got[0].Evidence[1].GetTitle())
	assert.Nil(t, got[0].Evidence[1].GetMetadata(), "empty metadata is nil")
	require.Len(t, got[1].Evidence, 1)
	assert.Equal(t, "other", got[1].Evidence[0].GetTitle())
	assert.Equal(t, 1, db.released)
}

func TestFindWithEvidence_EmptyPageSkipsTheEvidenceRead(t *testing.T) {
	db := &scriptDB{
		queryRow: func(string) datapool.Row { return scriptRow{values: []any{0}} },
		query:    byTable(rowsOf(), nil),
	}
	got, total, err := newScriptStore(db).FindWithEvidence(context.Background(), "acme", Query{})
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.Zero(t, total)
	assert.Len(t, db.log, 2, "a count and a page, and no evidence read")
}

func TestFindWithEvidence_Failures(t *testing.T) {
	f := scriptFinding("one")
	page := rowsOf([]any{docOf(t, f)})
	count := func(string) datapool.Row { return scriptRow{values: []any{1}} }
	good := evidenceRowFor(f.ID.String(), 2, nil, "EVIDENCE_TYPE_LOG", "t", `{}`)
	tests := []struct {
		name  string
		db    *scriptDB
		query Query
		want  string
	}{
		{"bad query", &scriptDB{}, Query{IDs: []types.ID{"x"}}, "finding ID"},
		{"no conn", &scriptDB{forErr: errScript}, Query{}, "scripted failure"},
		{"page fails", &scriptDB{queryRow: func(string) datapool.Row { return scriptRow{err: errScript} }},
			Query{}, "count findings"},
		{"evidence query fails", &scriptDB{queryRow: count, query: byTable(page,
			func() (datapool.Rows, error) { return nil, errScript })}, Query{}, "read evidence"},
		{"evidence scan fails", &scriptDB{queryRow: count, query: byTable(page,
			func() (datapool.Rows, error) {
				return &scriptRows{rows: [][]any{good}, scanErr: errScript}, nil
			})}, Query{}, "scan evidence"},
		{"metadata is not JSON", &scriptDB{queryRow: count, query: byTable(page, rowsOf(
			evidenceRowFor(f.ID.String(), 2, nil, "EVIDENCE_TYPE_LOG", "t", `[`)))}, Query{}, "evidence metadata"},
		{"evidence rows fail", &scriptDB{queryRow: count, query: byTable(page,
			func() (datapool.Rows, error) { return &scriptRows{err: errScript}, nil })}, Query{}, "read evidence"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, total, err := newScriptStore(tt.db).FindWithEvidence(context.Background(), "acme", tt.query)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
			assert.Zero(t, total)
		})
	}
}

func TestCountBy(t *testing.T) {
	tests := []struct {
		name     string
		by       string
		window   time.Duration
		wantSQL  string
		wantArgs []any
	}{
		{"severity", "severity", 0, "coalesce(nullif(severity, ''), 'unknown')", nil},
		{"category in a window", "category", 90 * time.Second, "document->>'category'", []any{90.0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &scriptDB{query: rowsOfQuery(rowsOf([]any{"high", int64(3)}, []any{"unknown", int64(1)}))}

			got, err := newScriptStore(db).CountBy(context.Background(), "acme", tt.by, tt.window)

			require.NoError(t, err)
			assert.Equal(t, []Bucket{{"high", 3}, {"unknown", 1}}, got)
			assert.Contains(t, db.log[0].sql, tt.wantSQL)
			assert.Equal(t, tt.window > 0, strings.Contains(db.log[0].sql, "make_interval(secs => $1)"))
			assert.Equal(t, tt.wantArgs, db.log[0].args)
			assert.Equal(t, 1, db.released)
		})
	}
}

func rowsOfQuery(f func() (datapool.Rows, error)) func(string) (datapool.Rows, error) {
	return func(string) (datapool.Rows, error) { return f() }
}

func TestCountBy_Failures(t *testing.T) {
	tests := []struct {
		name string
		by   string
		db   *scriptDB
		want string
	}{
		{"unknown label source", "color", &scriptDB{}, `cannot count by "color"`},
		{"no conn", "severity", &scriptDB{forErr: errScript}, "scripted failure"},
		{"query fails", "severity", &scriptDB{query: func(string) (datapool.Rows, error) { return nil, errScript }},
			"count findings"},
		{"scan fails", "severity", &scriptDB{query: func(string) (datapool.Rows, error) {
			return &scriptRows{rows: [][]any{{"high", int64(1)}}, scanErr: errScript}, nil
		}}, "scan count"},
		{"rows fail", "severity", &scriptDB{query: func(string) (datapool.Rows, error) {
			return &scriptRows{err: errScript}, nil
		}}, "count findings"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newScriptStore(tt.db).CountBy(context.Background(), "acme", tt.by, 0)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
		})
	}
}

func TestDailyCounts(t *testing.T) {
	db := &scriptDB{query: rowsOfQuery(rowsOf([]any{"2026-11-01", int64(2)}, []any{"2026-11-02", int64(5)}))}

	got, err := newScriptStore(db).DailyCounts(context.Background(), "acme", 30)

	require.NoError(t, err)
	assert.Equal(t, map[string]uint64{"2026-11-01": 2, "2026-11-02": 5}, got)
	assert.Equal(t, []any{30}, db.log[0].args)
	assert.Equal(t, 1, db.released)
}

func TestDailyCounts_Failures(t *testing.T) {
	tests := []struct {
		name string
		db   *scriptDB
		want string
	}{
		{"no conn", &scriptDB{forErr: errScript}, "scripted failure"},
		{"query fails", &scriptDB{query: func(string) (datapool.Rows, error) { return nil, errScript }}, "by day"},
		{"scan fails", &scriptDB{query: func(string) (datapool.Rows, error) {
			return &scriptRows{rows: [][]any{{"d", int64(1)}}, scanErr: errScript}, nil
		}}, "scan day count"},
		{"rows fail", &scriptDB{query: func(string) (datapool.Rows, error) {
			return &scriptRows{err: errScript}, nil
		}}, "by day"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newScriptStore(tt.db).DailyCounts(context.Background(), "acme", 7)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
		})
	}
}

func TestGet(t *testing.T) {
	f := scriptFinding("one")
	id := f.ID
	tests := []struct {
		name    string
		id      types.ID
		db      *scriptDB
		wantErr string
		is      error
	}{
		{"found", id, &scriptDB{queryRow: oneRow(docOf(t, f))}, "", nil},
		{"bad ID", "x", &scriptDB{}, "finding ID", nil},
		{"no conn", id, &scriptDB{forErr: errScript}, "scripted failure", errScript},
		{"no row", id, &scriptDB{queryRow: func(string) datapool.Row { return scriptRow{err: datapool.ErrNoRows} }},
			"", finding.ErrNotFound},
		{"read fails", id, &scriptDB{queryRow: func(string) datapool.Row { return scriptRow{err: errScript} }},
			"read finding", errScript},
		{"bad document", id, &scriptDB{queryRow: oneRow([]byte("{"))},
			"decode finding", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newScriptStore(tt.db).Get(context.Background(), "acme", tt.id)
			if tt.wantErr == "" && tt.is == nil {
				require.NoError(t, err)
				assert.Equal(t, id, got.ID)
				return
			}
			require.Error(t, err)
			assert.Nil(t, got)
			if tt.wantErr != "" {
				assert.Contains(t, err.Error(), tt.wantErr)
			}
			if tt.is != nil {
				assert.ErrorIs(t, err, tt.is)
			}
		})
	}
}

func TestGetWithEvidence(t *testing.T) {
	f := scriptFinding("one")
	call := "call-9"
	doc := func(string) datapool.Row { return scriptRow{values: []any{docOf(t, f)}} }
	evRow := func(meta string) []any {
		return []any{int16(1), &call, "EVIDENCE_TYPE_LOG", "t", "c", []byte(meta)}
	}
	evidence := func(rows ...[]any) func(string) (datapool.Rows, error) {
		return func(string) (datapool.Rows, error) { return &scriptRows{rows: rows}, nil }
	}
	failing := func(r *scriptRows) func(string) (datapool.Rows, error) {
		return func(string) (datapool.Rows, error) { return r, nil }
	}

	t.Run("found with evidence", func(t *testing.T) {
		db := &scriptDB{queryRow: doc, query: evidence(evRow(`{"a":"b"}`))}
		got, err := newScriptStore(db).GetWithEvidence(context.Background(), "acme", f.ID)
		require.NoError(t, err)
		require.Len(t, got.Evidence, 1)
		assert.Equal(t, "call-9", got.Evidence[0].GetToolCallId())
		assert.Equal(t, "b", got.Evidence[0].GetMetadata()["a"])
	})

	failures := []struct {
		name string
		id   types.ID
		db   *scriptDB
		want string
		is   error
	}{
		{"bad ID", "x", &scriptDB{}, "finding ID", nil},
		{"no conn", f.ID, &scriptDB{forErr: errScript}, "scripted failure", errScript},
		{"no row", f.ID, &scriptDB{queryRow: func(string) datapool.Row { return scriptRow{err: datapool.ErrNoRows} }},
			"", finding.ErrNotFound},
		{"read fails", f.ID, &scriptDB{queryRow: func(string) datapool.Row { return scriptRow{err: errScript} }},
			"read finding", errScript},
		{"bad document", f.ID, &scriptDB{queryRow: oneRow([]byte("{"))},
			"decode finding", nil},
		{"evidence query fails", f.ID, &scriptDB{queryRow: doc,
			query: func(string) (datapool.Rows, error) { return nil, errScript }}, "read evidence of finding", errScript},
		{"evidence scan fails", f.ID, &scriptDB{queryRow: doc,
			query: failing(&scriptRows{rows: [][]any{evRow(`{}`)}, scanErr: errScript})}, "scan evidence", errScript},
		{"bad metadata", f.ID, &scriptDB{queryRow: doc, query: evidence(evRow(`[`))}, "evidence metadata", nil},
		{"rows fail", f.ID, &scriptDB{queryRow: doc, query: failing(&scriptRows{err: errScript})},
			"read evidence of finding", errScript},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newScriptStore(tt.db).GetWithEvidence(context.Background(), "acme", tt.id)
			require.Error(t, err)
			assert.Nil(t, got)
			if tt.want != "" {
				assert.Contains(t, err.Error(), tt.want)
			}
			if tt.is != nil {
				assert.ErrorIs(t, err, tt.is)
			}
		})
	}
}

func TestListAndListBySeverity(t *testing.T) {
	a := scriptFinding("one")
	b := scriptFinding("two")
	b.Severity = agent.SeverityLow
	db := &scriptDB{query: rowsOfQuery(rowsOf([]any{docOf(t, a)}, []any{docOf(t, b)}))}
	s := newScriptStore(db)
	mission := types.NewID()

	all, err := s.List(context.Background(), "acme", mission, nil)
	require.NoError(t, err)
	assert.Len(t, all, 2)
	assert.Equal(t, []any{mission.String()}, db.log[0].args)

	low := agent.SeverityLow
	only, err := s.List(context.Background(), "acme", mission, &finding.FindingFilter{Severity: &low})
	require.NoError(t, err)
	require.Len(t, only, 1)
	assert.Equal(t, b.ID, only[0].ID)

	bySev, err := s.ListBySeverity(context.Background(), "acme", agent.SeverityHigh)
	require.NoError(t, err)
	assert.Len(t, bySev, 2)
	assert.Equal(t, []any{"high"}, db.log[2].args)
}

func TestList_Failures(t *testing.T) {
	_, err := newScriptStore(&scriptDB{}).List(context.Background(), "acme", "x", nil)
	require.ErrorContains(t, err, "mission ID")

	tests := []struct {
		name string
		db   *scriptDB
		want string
	}{
		{"no conn", &scriptDB{forErr: errScript}, "scripted failure"},
		{"query fails", &scriptDB{query: func(string) (datapool.Rows, error) { return nil, errScript }}, "list findings"},
		{"scan fails", &scriptDB{query: func(string) (datapool.Rows, error) {
			return &scriptRows{rows: [][]any{{[]byte("{}")}}, scanErr: errScript}, nil
		}}, "scan finding"},
		{"bad document", &scriptDB{query: rowsOfQuery(rowsOf([]any{[]byte("{")}))}, "decode finding"},
		{"rows fail", &scriptDB{query: func(string) (datapool.Rows, error) {
			return &scriptRows{err: errScript}, nil
		}}, "list findings"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newScriptStore(tt.db).ListBySeverity(context.Background(), "acme", agent.SeverityHigh)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, got)
		})
	}
}

// fakePool is a data pool that only answers For.
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
	ready := func(p datapool.Pool) PoolFunc { return func() datapool.Pool { return p } }
	tests := []struct {
		name   string
		pool   PoolFunc
		tenant string
		want   string
	}{
		{"no pool func", nil, "acme", "data pool is not ready"},
		{"pool not started", ready(nil), "acme", "data pool is not ready"},
		{"bad tenant", ready(fakePool{}), "Not A Tenant!", "invalid tenant"},
		{"pool refuses", ready(fakePool{err: errScript}), "acme", "acquire conn for acme"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := poolConns{pool: tt.pool}.For(context.Background(), tt.tenant)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Nil(t, c)
		})
	}

	c, err := poolConns{pool: ready(fakePool{})}.For(context.Background(), "acme")
	require.NoError(t, err)
	assert.NotNil(t, c)
}

func TestNewFindingRow_Failures(t *testing.T) {
	f := scriptFinding("one")
	f.ID = "nope"
	_, err := newFindingRow(f)
	require.ErrorContains(t, err, "finding ID")

	f = scriptFinding("one")
	f.MissionID = "nope"
	_, err = newFindingRow(f)
	require.ErrorContains(t, err, "mission ID")

	f = scriptFinding("one")
	f.CreatedAt, f.UpdatedAt = time.Time{}, time.Time{}
	row, err := newFindingRow(f)
	require.NoError(t, err)
	assert.False(t, row.createdAt.IsZero(), "a zero creation time becomes now")
	assert.Equal(t, row.createdAt, row.updatedAt, "a zero update time follows the creation time")
}

func TestStore_RejectsABadFindingBeforeTheConn(t *testing.T) {
	db := &scriptDB{}
	f := scriptFinding("one")
	f.ID = "nope"
	err := newScriptStore(db).Store(context.Background(), "acme", f)
	require.Error(t, err)
	assert.Empty(t, db.log)
	assert.Zero(t, db.released)
}
