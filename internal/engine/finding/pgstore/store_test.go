// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package pgstore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	typespb "github.com/zeroroot-ai/sdk/api/gen/gibson/types/v1"
)

// fakeDB is an in-memory findings table. It answers the statements that the
// store sends and nothing else. The SQL itself needs a real Postgres, and the
// integration test covers that.
type fakeDB struct {
	rows     map[string]fakeRow
	evidence map[string][]fakeEvidence
	execErr  error
	// failOn makes an Exec fail when its statement holds this text.
	failOn   string
	released int
	// readEvidence counts the reads of the evidence table.
	readEvidence int
}

type fakeEvidence struct {
	position   int
	tier       int16
	toolCallID *string
	typeName   string
	title      string
	content    string
	sha256     []byte
	metadata   []byte
}

type fakeRow struct {
	missionID *string
	severity  string
	title     string
	document  []byte
	createdAt time.Time
}

func newFakeDB() *fakeDB {
	return &fakeDB{rows: map[string]fakeRow{}, evidence: map[string][]fakeEvidence{}}
}

func (d *fakeDB) For(_ context.Context, _ string) (conn, error) { return d, nil }
func (d *fakeDB) SQL() datapool.SQL                             { return d }
func (d *fakeDB) Release()                                      { d.released++ }

// InTx runs fn and undoes each write if fn fails, as a transaction does.
func (d *fakeDB) InTx(_ context.Context, fn func(datapool.SQL) error) error {
	rows := make(map[string]fakeRow, len(d.rows))
	for k, v := range d.rows {
		rows[k] = v
	}
	evidence := make(map[string][]fakeEvidence, len(d.evidence))
	for k, v := range d.evidence {
		evidence[k] = append([]fakeEvidence(nil), v...)
	}
	if err := fn(d); err != nil {
		d.rows, d.evidence = rows, evidence
		return err
	}
	return nil
}

func (d *fakeDB) Exec(_ context.Context, sql string, args ...any) (int64, error) {
	if d.execErr != nil {
		return 0, d.execErr
	}
	if d.failOn != "" && contains(sql, d.failOn) {
		return 0, errors.New("injected failure")
	}
	switch {
	case contains(sql, "DELETE FROM finding_evidence"):
		delete(d.evidence, args[0].(string))
		return 1, nil
	case contains(sql, "INSERT INTO finding_evidence"):
		id := args[0].(string)
		if _, ok := d.rows[id]; !ok {
			return 0, errors.New("foreign key violation")
		}
		d.evidence[id] = append(d.evidence[id], fakeEvidence{
			position:   args[1].(int),
			tier:       args[2].(int16),
			toolCallID: args[3].(*string),
			typeName:   args[4].(string),
			title:      args[5].(string),
			content:    args[6].(string),
			sha256:     args[7].([]byte),
			metadata:   args[8].([]byte),
		})
		return 1, nil
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

func (d *fakeDB) QueryRow(_ context.Context, sql string, args ...any) datapool.Row {
	if contains(sql, "finding_evidence") {
		d.readEvidence++
	}
	row, ok := d.rows[args[0].(string)]
	if !ok {
		return fakeScanRow{err: datapool.ErrNoRows}
	}
	return fakeScanRow{doc: row.document}
}

type fakeRows struct {
	rows [][]any
	pos  int
}

func (r *fakeRows) Next() bool { r.pos++; return r.pos <= len(r.rows) }
func (r *fakeRows) Scan(dest ...any) error {
	for i, v := range r.rows[r.pos-1] {
		switch d := dest[i].(type) {
		case *[]byte:
			*d = v.([]byte)
		case *int16:
			*d = v.(int16)
		case **string:
			*d = v.(*string)
		case *string:
			*d = v.(string)
		default:
			return fmt.Errorf("fakeRows: no case for %T", dest[i])
		}
	}
	return nil
}
func (r *fakeRows) Err() error { return nil }
func (r *fakeRows) Close()     {}

// Query answers the two list statements: by mission and by severity.
func (d *fakeDB) Query(_ context.Context, sql string, args ...any) (datapool.Rows, error) {
	if contains(sql, "finding_evidence") {
		d.readEvidence++
	}
	want := args[0].(string)
	if contains(sql, "FROM finding_evidence") {
		out := &fakeRows{}
		for _, e := range d.evidence[want] {
			out.rows = append(out.rows, []any{e.tier, e.toolCallID, e.typeName, e.title, e.content, e.metadata})
		}
		return out, nil
	}
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
		out.rows = append(out.rows, []any{d.rows[id].document})
	}
	return out, nil
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

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

func tier1(id, content string) *typespb.Evidence {
	return &typespb.Evidence{
		Title: "tool call httpx (" + id + ")", Type: typespb.EvidenceType_EVIDENCE_TYPE_LOG, Content: content,
		Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, ToolCallId: id,
		Metadata: map[string]string{"tool_name": "httpx"},
	}
}

func tier2(title, content string) *typespb.Evidence {
	return &typespb.Evidence{
		Title: title, Type: typespb.EvidenceType_EVIDENCE_TYPE_CONVERSATION, Content: content,
		Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED,
	}
}

func TestStore_EvidenceRowsAndHash(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
	f.Evidence = []*typespb.Evidence{tier1("call-1", "recorded"), tier2("dialogue", "hello")}

	require.NoError(t, s.Store(context.Background(), "acme", f))

	rows := db.evidence[f.ID.String()]
	require.Len(t, rows, 2)
	assert.Equal(t, int16(1), rows[0].tier)
	require.NotNil(t, rows[0].toolCallID)
	assert.Equal(t, "call-1", *rows[0].toolCallID)
	assert.Equal(t, "recorded", rows[0].content)
	sum := sha256.Sum256([]byte("recorded"))
	assert.Equal(t, sum[:], rows[0].sha256)
	assert.Equal(t, "EVIDENCE_TYPE_LOG", rows[0].typeName)
	assert.JSONEq(t, `{"tool_name":"httpx"}`, string(rows[0].metadata))
	assert.Equal(t, int16(2), rows[1].tier)
	assert.Nil(t, rows[1].toolCallID)
	assert.Equal(t, 1, rows[1].position)
	assert.JSONEq(t, `{}`, string(rows[1].metadata))
}

// TestStore_DocumentHoldsNoEvidence proves that the evidence is in the table
// only, and that Get and List never read the table.
func TestStore_DocumentHoldsNoEvidence(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	ctx := context.Background()
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
	f.Evidence = []*typespb.Evidence{tier1("call-1", "recorded")}
	require.NoError(t, s.Store(ctx, "acme", f))

	assert.NotContains(t, string(db.rows[f.ID.String()].document), "recorded")

	got, err := s.Get(ctx, "acme", f.ID)
	require.NoError(t, err)
	assert.Empty(t, got.Evidence)
	list, err := s.List(ctx, "acme", f.MissionID, nil)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Empty(t, list[0].Evidence)
	_, err = s.ListBySeverity(ctx, "acme", agent.SeverityHigh)
	require.NoError(t, err)
	assert.Zero(t, db.readEvidence, "a read of a finding must not read the evidence table")
}

// TestStore_AFailedEvidenceWriteLeavesNoFindingRow is the failing fixture for
// the transaction rule.
func TestStore_AFailedEvidenceWriteLeavesNoFindingRow(t *testing.T) {
	db := newFakeDB()
	db.failOn = "INSERT INTO finding_evidence"
	s := newTestStore(db)
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
	f.Evidence = []*typespb.Evidence{tier1("call-1", "recorded")}

	err := s.Store(context.Background(), "acme", f)

	require.Error(t, err)
	assert.Empty(t, db.rows, "no finding row")
	assert.Empty(t, db.evidence, "no evidence row")
	assert.Equal(t, 1, db.released)
}

func TestStore_AFailedReplaceKeepsTheOldFinding(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	ctx := context.Background()
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
	f.Evidence = []*typespb.Evidence{tier1("call-1", "old")}
	require.NoError(t, s.Store(ctx, "acme", f))

	db.failOn = "INSERT INTO finding_evidence"
	f.Title = "new title"
	f.Evidence = []*typespb.Evidence{tier1("call-2", "new")}
	require.Error(t, s.Store(ctx, "acme", f))

	assert.Equal(t, "open port", db.rows[f.ID.String()].title)
	require.Len(t, db.evidence[f.ID.String()], 1)
	assert.Equal(t, "old", db.evidence[f.ID.String()][0].content)
}

func TestStore_StoreTwiceReplacesTheEvidence(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	ctx := context.Background()
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
	f.Evidence = []*typespb.Evidence{tier1("call-1", "a"), tier2("b", "b")}
	require.NoError(t, s.Store(ctx, "acme", f))
	f.Evidence = []*typespb.Evidence{tier2("c", "c")}
	require.NoError(t, s.Store(ctx, "acme", f))

	require.Len(t, db.evidence[f.ID.String()], 1)
	assert.Equal(t, "c", db.evidence[f.ID.String()][0].content)
}

// TestStore_EvidenceOverTheLimitFailsTheSubmit is the failing fixture for the
// size rule. The store never truncates, and it writes nothing.
func TestStore_EvidenceOverTheLimitFailsTheSubmit(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())

	f.Evidence = []*typespb.Evidence{tier2("ok", "fine"), tier1("call-1", strings.Repeat("x", finding.MaxEvidenceContentBytes+1))}
	err := s.Store(context.Background(), "acme", f)
	require.ErrorIs(t, err, finding.ErrEvidenceTooLarge)
	assert.Empty(t, db.rows)
	assert.Empty(t, db.evidence)
	assert.Zero(t, db.released, "the store never opened a conn")

	f.Evidence = []*typespb.Evidence{tier1("call-1", strings.Repeat("x", finding.MaxEvidenceContentBytes))}
	require.NoError(t, s.Store(context.Background(), "acme", f), "an item at the limit is stored whole")
	assert.Len(t, db.evidence[f.ID.String()][0].content, finding.MaxEvidenceContentBytes)
}

func TestStore_RefusesAnInvalidTierAndToolCallPair(t *testing.T) {
	tests := []struct {
		name string
		item *typespb.Evidence
	}{
		{"nil item", nil},
		{"no tier", &typespb.Evidence{Content: "x"}},
		{"tier 1 with no tool call", &typespb.Evidence{Content: "x", Tier: typespb.EvidenceTier_EVIDENCE_TIER_RECORDED}},
		{"tier 2 with a tool call", &typespb.Evidence{
			Content: "x", Tier: typespb.EvidenceTier_EVIDENCE_TIER_TYPED, ToolCallId: "call-1",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newFakeDB()
			f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
			f.Evidence = []*typespb.Evidence{tt.item}

			err := newTestStore(db).Store(context.Background(), "acme", f)

			require.ErrorIs(t, err, finding.ErrInvalidEvidence)
			assert.Empty(t, db.rows)
		})
	}
}

func TestStore_GetWithEvidenceReturnsEveryItemAsStored(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	ctx := context.Background()
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
	recorded := tier1("call-1", `{"status_code":200}`)
	typed := tier2("dialogue", "hello")
	empty := tier2("empty", "")
	f.Evidence = []*typespb.Evidence{typed, recorded, empty}
	require.NoError(t, s.Store(ctx, "acme", f))

	got, err := s.GetWithEvidence(ctx, "acme", f.ID)

	require.NoError(t, err)
	assert.Equal(t, "open port", got.Title)
	require.Len(t, got.Evidence, 3)
	for i, want := range f.Evidence {
		assert.True(t, proto.Equal(want, got.Evidence[i]), "item %d: want %v, got %v", i, want, got.Evidence[i])
	}
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_TYPED, got.Evidence[0].GetTier())
	assert.Equal(t, typespb.EvidenceTier_EVIDENCE_TIER_RECORDED, got.Evidence[1].GetTier())
	assert.Equal(t, "call-1", got.Evidence[1].GetToolCallId())
	assert.Equal(t, 1, db.readEvidence, "one read of the evidence table")
}

func TestStore_GetWithEvidenceOfAFindingWithNoEvidence(t *testing.T) {
	db := newFakeDB()
	s := newTestStore(db)
	f := newFinding(types.NewID(), "open port", agent.SeverityHigh, time.Now())
	require.NoError(t, s.Store(context.Background(), "acme", f))

	got, err := s.GetWithEvidence(context.Background(), "acme", f.ID)

	require.NoError(t, err)
	assert.Empty(t, got.Evidence)
}

func TestStore_GetWithEvidenceNotFound(t *testing.T) {
	_, err := newTestStore(newFakeDB()).GetWithEvidence(context.Background(), "acme", types.NewID())
	require.ErrorIs(t, err, finding.ErrNotFound)
}
