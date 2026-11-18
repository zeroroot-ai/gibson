// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pgstore

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// fakeDB is an in-memory findings table. It answers the statements that the
// store sends and nothing else. The SQL itself needs a real Postgres, and the
// integration test covers that.
type fakeDB struct {
	rows     map[string]fakeRow
	execErr  error
	released int
}

type fakeRow struct {
	missionID *string
	severity  string
	title     string
	document  []byte
	createdAt time.Time
}

func newFakeDB() *fakeDB { return &fakeDB{rows: map[string]fakeRow{}} }

func (d *fakeDB) For(_ context.Context, _ string) (conn, error) { return d, nil }
func (d *fakeDB) SQL() datapool.SQL                              { return d }
func (d *fakeDB) Release()                                       { d.released++ }
func (d *fakeDB) InTx(_ context.Context, fn func(datapool.SQL) error) error {
	return fn(d)
}

func (d *fakeDB) Exec(_ context.Context, _ string, args ...any) (int64, error) {
	if d.execErr != nil {
		return 0, d.execErr
	}
	id := args[0].(string)
	d.rows[id] = fakeRow{
		missionID: args[1].(*string),
		severity:  args[2].(string),
		title:     args[3].(string),
		document:  args[4].([]byte),
		createdAt: args[5].(time.Time),
	}
	return 1, nil
}

type fakeScanRow struct {
	doc []byte
	err error
}

func (r fakeScanRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*[]byte)) = r.doc
	return nil
}

func (d *fakeDB) QueryRow(_ context.Context, _ string, args ...any) datapool.Row {
	row, ok := d.rows[args[0].(string)]
	if !ok {
		return fakeScanRow{err: datapool.ErrNoRows}
	}
	return fakeScanRow{doc: row.document}
}

type fakeRows struct {
	docs [][]byte
	pos  int
}

func (r *fakeRows) Next() bool { r.pos++; return r.pos <= len(r.docs) }
func (r *fakeRows) Scan(dest ...any) error {
	*(dest[0].(*[]byte)) = r.docs[r.pos-1]
	return nil
}
func (r *fakeRows) Err() error { return nil }
func (r *fakeRows) Close()     {}

// Query answers the two list statements: by mission and by severity.
func (d *fakeDB) Query(_ context.Context, sql string, args ...any) (datapool.Rows, error) {
	want := args[0].(string)
	var ids []string
	for id, row := range d.rows {
		switch {
		case contains(sql, "mission_id = $1"):
			if row.missionID != nil && *row.missionID == want {
				ids = append(ids, id)
			}
		case contains(sql, "severity = $1"):
			if row.severity == want {
				ids = append(ids, id)
			}
		}
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := d.rows[ids[i]], d.rows[ids[j]]
		if !a.createdAt.Equal(b.createdAt) {
			return a.createdAt.Before(b.createdAt)
		}
		return ids[i] < ids[j]
	})
	out := &fakeRows{}
	for _, id := range ids {
		out.docs = append(out.docs, d.rows[id].document)
	}
	return out, nil
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func newTestStore(db *fakeDB) *Store { return &Store{conns: db} }

func newFinding(missionID types.ID, title string, sev agent.FindingSeverity, created time.Time) finding.EnhancedFinding {
	f := finding.NewEnhancedFinding(agent.NewFinding(title, "description of "+title, sev), missionID, "recon")
	f.CreatedAt = created
	return f
}

func TestStore_StoreWritesOneRow(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	mission := types.NewID()
	f := newFinding(mission, "open port", agent.SeverityHigh, time.Now())

	require.NoError(t, s.Store(context.Background(), "acme", f))

	require.Len(t, db.rows, 1)
	row := db.rows[f.ID.String()]
	assert.Equal(t, "high", row.severity)
	assert.Equal(t, "open port", row.title)
	require.NotNil(t, row.missionID)
	assert.Equal(t, mission.String(), *row.missionID)
	assert.Equal(t, 1, db.released, "the store releases the conn")
}

func TestStore_StoreTwiceReplacesTheRow(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
	require.NoError(t, s.Store(context.Background(), "acme", f))
	f.Title = "open port 22"
	require.NoError(t, s.Store(context.Background(), "acme", f))

	assert.Len(t, db.rows, 1)
	assert.Equal(t, "open port 22", db.rows[f.ID.String()].title)
}

func TestStore_FindingWithNoMissionHasNullMissionID(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	f := newFinding("", "no mission", agent.SeverityLow, time.Now())
	require.NoError(t, s.Store(context.Background(), "acme", f))
	assert.Nil(t, db.rows[f.ID.String()].missionID)
}

func TestStore_StoreRefusesABadID(t *testing.T) {
	s := newTestStore(newFakeDB())
	f := newFinding(types.NewID(), "x", agent.SeverityLow, time.Now())
	f.ID = "not-a-uuid"
	require.Error(t, s.Store(context.Background(), "acme", f))

	f = newFinding("not-a-uuid", "x", agent.SeverityLow, time.Now())
	require.Error(t, s.Store(context.Background(), "acme", f))
}

func TestStore_StoreWrapsADatabaseError(t *testing.T) {
	db := newFakeDB()
	boom := errors.New("boom")
	db.execErr = boom
	err := newTestStore(db).Store(context.Background(), "acme",
		newFinding(types.NewID(), "x", agent.SeverityLow, time.Now()))
	require.ErrorIs(t, err, boom)
	assert.Equal(t, 1, db.released)
}

func TestStore_GetRoundTripsAndReportsNotFound(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
	f.RiskScore = 7.5
	require.NoError(t, s.Store(context.Background(), "acme", f))

	got, err := s.Get(context.Background(), "acme", f.ID)
	require.NoError(t, err)
	assert.Equal(t, f.ID, got.ID)
	assert.Equal(t, f.MissionID, got.MissionID)
	assert.Equal(t, 7.5, got.RiskScore)
	assert.Equal(t, "recon", got.AgentName)

	_, err = s.Get(context.Background(), "acme", types.NewID())
	require.ErrorIs(t, err, finding.ErrNotFound)
}

func TestStore_ListByMissionAndSeverity(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	ctx := context.Background()
	m1, m2 := types.NewID(), types.NewID()
	now := time.Now()
	a := newFinding(m1, "a", agent.SeverityHigh, now)
	b := newFinding(m1, "b", agent.SeverityLow, now.Add(time.Second))
	c := newFinding(m2, "c", agent.SeverityHigh, now.Add(2*time.Second))
	for _, f := range []finding.EnhancedFinding{a, b, c} {
		require.NoError(t, s.Store(ctx, "acme", f))
	}

	byMission, err := s.List(ctx, "acme", m1, nil)
	require.NoError(t, err)
	require.Len(t, byMission, 2)
	assert.Equal(t, []string{"a", "b"}, []string{byMission[0].Title, byMission[1].Title})

	high := agent.SeverityHigh
	filtered, err := s.List(ctx, "acme", m1, &finding.FindingFilter{Severity: &high})
	require.NoError(t, err)
	require.Len(t, filtered, 1)
	assert.Equal(t, "a", filtered[0].Title)

	text := "C"
	searched, err := s.List(ctx, "acme", m2, &finding.FindingFilter{SearchText: &text})
	require.NoError(t, err)
	assert.Len(t, searched, 1)

	bySeverity, err := s.ListBySeverity(ctx, "acme", agent.SeverityHigh)
	require.NoError(t, err)
	require.Len(t, bySeverity, 2)
	assert.Equal(t, []string{"a", "c"}, []string{bySeverity[0].Title, bySeverity[1].Title})

	none, err := s.List(ctx, "acme", types.NewID(), nil)
	require.NoError(t, err)
	assert.Empty(t, none)
}

func TestStore_PoolNotReady(t *testing.T) {
	s := New(func() datapool.Pool { return nil })
	err := s.Store(context.Background(), "acme", newFinding(types.NewID(), "x", agent.SeverityLow, time.Now()))
	require.Error(t, err)
}
