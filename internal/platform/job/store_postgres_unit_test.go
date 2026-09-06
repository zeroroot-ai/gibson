// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package job

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// A scripted database, the same shape the bank store's tests use.
//
// What a reader has to trust here is the queue's ordering, the state machine
// and what a member may report — none of which needs a real Postgres to check.
// The container test keeps the one job only a real database can do.

type scriptedSQL struct {
	rows     map[string][][]any
	errs     map[string]error
	affected map[string]int64
	seen     []string
}

func newScript() *scriptedSQL {
	return &scriptedSQL{rows: map[string][][]any{}, errs: map[string]error{}, affected: map[string]int64{}}
}

// match returns the entry whose key appears in the statement, preferring the
// longest key. Map iteration is random, so without that a statement matching
// two fragments would answer differently from run to run.
func match[T any](m map[string]T, sql string) (T, bool) {
	best, found := "", false
	for frag := range m {
		if strings.Contains(sql, frag) && len(frag) > len(best) {
			best, found = frag, true
		}
	}
	if !found {
		var zero T
		return zero, false
	}
	return m[best], true
}

func (s *scriptedSQL) Exec(_ context.Context, sql string, _ ...any) (int64, error) {
	s.seen = append(s.seen, sql)
	if err, ok := match(s.errs, sql); ok {
		return 0, err
	}
	if n, ok := match(s.affected, sql); ok {
		return n, nil
	}
	return 1, nil
}

func (s *scriptedSQL) QueryRow(_ context.Context, sql string, _ ...any) datapool.Row {
	s.seen = append(s.seen, sql)
	if err, ok := match(s.errs, sql); ok {
		return scriptedRow{err: err}
	}
	rows, ok := match(s.rows, sql)
	if !ok || len(rows) == 0 {
		return scriptedRow{err: datapool.ErrNoRows}
	}
	return scriptedRow{values: rows[0]}
}

func (s *scriptedSQL) Query(_ context.Context, sql string, _ ...any) (datapool.Rows, error) {
	s.seen = append(s.seen, sql)
	if err, ok := match(s.errs, sql); ok {
		return nil, err
	}
	rows, _ := match(s.rows, sql)
	return &scriptedRows{values: rows}, nil
}

// ran reports whether any statement contained the fragment.
func (s *scriptedSQL) ran(fragment string) bool {
	for _, sql := range s.seen {
		if strings.Contains(sql, fragment) {
			return true
		}
	}
	return false
}

type scriptedRow struct {
	values []any
	err    error
}

func (r scriptedRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	return assign(dest, r.values)
}

type scriptedRows struct {
	values [][]any
	i      int
}

func (r *scriptedRows) Next() bool { r.i++; return r.i <= len(r.values) }
func (r *scriptedRows) Scan(dest ...any) error {
	if r.i == 0 || r.i > len(r.values) {
		return errors.New("scriptedRows: Scan without Next")
	}
	return assign(dest, r.values[r.i-1])
}
func (r *scriptedRows) Err() error { return nil }
func (r *scriptedRows) Close()     {}

func assign(dest, values []any) error {
	if len(dest) != len(values) {
		return errors.New("scripted row: column count does not match the scan")
	}
	for i, d := range dest {
		switch p := d.(type) {
		case *string:
			*p = values[i].(string)
		case *int32:
			*p = values[i].(int32)
		case *int64:
			*p = values[i].(int64)
		case *float64:
			*p = values[i].(float64)
		case *bool:
			*p = values[i].(bool)
		case *[]byte:
			*p = values[i].([]byte)
		case *time.Time:
			*p = values[i].(time.Time)
		case **time.Time:
			switch v := values[i].(type) {
			case nil:
				*p = nil
			case *time.Time:
				*p = v
			case time.Time:
				at := v
				*p = &at
			default:
				return errors.New("scripted row: a nullable timestamp needs a time value")
			}
		default:
			return errors.New("scripted row: unsupported scan target")
		}
	}
	return nil
}

type scriptedConn struct {
	sql      *scriptedSQL
	released bool
}

func (c *scriptedConn) SQL() datapool.SQL { return c.sql }
func (c *scriptedConn) InTx(_ context.Context, fn func(datapool.SQL) error) error {
	return fn(c.sql)
}
func (c *scriptedConn) Release() { c.released = true }

type scriptedConns struct {
	conn *scriptedConn
	err  error
}

func (c scriptedConns) For(context.Context, string) (conn, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.conn, nil
}

// scriptedStore returns the concrete store, so a test that returns an error
// from one of its methods is not returning an unwrapped interface error.
func scriptedStore(t *testing.T, script *scriptedSQL) (*postgresStore, *scriptedConn) {
	t.Helper()
	c := &scriptedConn{sql: script}
	return &postgresStore{conns: scriptedConns{conn: c}}, c
}

var unitNow = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

func specJSON(t *testing.T) []byte {
	t.Helper()
	b, err := protojson.Marshal(validSpec())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// jobRow is a stored job in column order.
func jobRow(t *testing.T, id, memberID string, state State) []any {
	t.Helper()
	return []any{
		id, "bank-1", memberID, string(state), specJSON(t), "sess-1",
		"user", "alice", unitNow, unitNow, (*time.Time)(nil),
		"", 0.0, []byte(`[]`), int32(0), false,
	}
}

func inputRow(id, jobID string, seq int64, kind InputKind, acked *time.Time) []any {
	return []any{id, jobID, seq, string(kind), "go on", "user", "alice", unitNow, acked}
}

func eventRow(jobID string, seq int64, kind EventKind, payload []byte) []any {
	return []any{jobID, seq, string(kind), unitNow, string(StateOpen), "", 0.0, "", payload}
}

func openInput() OpenInput {
	return OpenInput{BankID: "bank-1", Spec: validSpec(), OpenedBy: Principal{Kind: PrincipalUser, ID: "alice"}}
}

func TestPostgresStore_OpenRecordsTheJobAndItsEvent(t *testing.T) {
	script := newScript()
	store, c := scriptedStore(t, script)

	j, err := store.Open(context.Background(), "acme", openInput())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if j.State != StateOpen || j.BankID != "bank-1" {
		t.Fatalf("job = %+v", j)
	}
	if !script.ran("INSERT INTO jobs") || !script.ran("INSERT INTO job_events") {
		t.Fatalf("statements = %v, want the job and its opening event", script.seen)
	}
	if script.ran("FROM bank_members") {
		t.Error("an unpinned job asks about no member: it waits in the queue")
	}
	if !c.released {
		t.Error("the connection must be released")
	}
}

func TestPostgresStore_OpenPinnedToAMemberChecksItsFreeSlot(t *testing.T) {
	script := newScript()
	script.rows["FROM bank_members"] = [][]any{{int32(0), int32(1)}}
	store, _ := scriptedStore(t, script)

	in := openInput()
	in.MemberID = "m-1"
	if _, err := store.Open(context.Background(), "acme", in); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !script.ran("FOR UPDATE") {
		t.Error("the free-slot read must lock, or two opens both take the last slot")
	}

	full := newScript()
	full.rows["FROM bank_members"] = [][]any{{int32(1), int32(1)}}
	store, _ = scriptedStore(t, full)
	if _, err := store.Open(context.Background(), "acme", in); !errors.Is(err, ErrNoFreeSlot) {
		t.Fatalf("err = %v, want ErrNoFreeSlot", err)
	}

	missing := newScript()
	store, _ = scriptedStore(t, missing)
	if _, err := store.Open(context.Background(), "acme", in); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for a member that does not exist", err)
	}
}

func TestPostgresStore_OpenRefusesBeforeTouchingTheDatabase(t *testing.T) {
	script := newScript()
	store, _ := scriptedStore(t, script)
	in := openInput()
	in.Spec = &jobpb.JobSpec{}
	if _, err := store.Open(context.Background(), "acme", in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if len(script.seen) != 0 {
		t.Fatalf("a refused input runs no statement, ran %v", script.seen)
	}
}

func TestPostgresStore_GetReadsTheSpecBackWhole(t *testing.T) {
	script := newScript()
	script.rows["SELECT id, bank_id, member_id"] = [][]any{jobRow(t, "job-1", "m-1", StateWorking)}
	store, _ := scriptedStore(t, script)

	j, err := store.Get(context.Background(), "acme", "job-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if j.State != StateWorking || j.MemberID != "m-1" {
		t.Fatalf("job = %+v", j)
	}
	if j.Spec.GetGoal() != "fix the CVE" || len(j.Spec.GetRepositories()) != 1 {
		t.Fatalf("the spec must come back exactly as the opener declared it: %+v", j.Spec)
	}
	if j.Spec.GetRepositories()[0].GetConnectorRef() != "connector/gitlab" {
		t.Error("the repository's connector must survive the round trip")
	}
}

func TestPostgresStore_GetMapsNoRowsToNotFound(t *testing.T) {
	store, _ := scriptedStore(t, newScript())
	if _, err := store.Get(context.Background(), "acme", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestPostgresStore_SendPutsAWaitingJobBackToWork(t *testing.T) {
	script := newScript()
	script.rows["SELECT state FROM jobs"] = [][]any{{string(StateWaiting)}}
	script.rows["RETURNING seq"] = [][]any{{int64(3)}}
	store, _ := scriptedStore(t, script)

	in, err := store.Send(context.Background(), "acme", SendInput{
		JobID: "job-1", Message: "the verifier says", Sender: Principal{Kind: PrincipalUser, ID: "alice"},
	})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if in.Seq != 3 || in.Kind != InputTurn {
		t.Fatalf("input = %+v", in)
	}
	if !script.ran("UPDATE jobs SET state") {
		t.Error("an input puts the job back to work")
	}
}

func TestPostgresStore_SendToAClosedJobIsRefusedExceptTheWrapUp(t *testing.T) {
	closed := func() *scriptedSQL {
		s := newScript()
		s.rows["SELECT state FROM jobs"] = [][]any{{string(StateClosed)}}
		s.rows["RETURNING seq"] = [][]any{{int64(9)}}
		return s
	}
	store, _ := scriptedStore(t, closed())
	_, err := store.Send(context.Background(), "acme", SendInput{
		JobID: "job-1", Message: "one more", Sender: Principal{Kind: PrincipalUser, ID: "alice"},
	})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}

	script := closed()
	store, _ = scriptedStore(t, script)
	if _, err := store.Send(context.Background(), "acme", SendInput{
		JobID: "job-1", Kind: InputWrapUp, Message: "wrap up",
		Sender: Principal{Kind: PrincipalUser, ID: "alice"},
	}); err != nil {
		t.Fatalf("the wrap-up is the one input a closed job accepts: %v", err)
	}
	if script.ran("UPDATE jobs SET state") {
		t.Error("a wrap-up turn is not a state change: a closed job stays closed")
	}
}

func TestPostgresStore_SendToAnUnknownJobIsNotFound(t *testing.T) {
	store, _ := scriptedStore(t, newScript())
	_, err := store.Send(context.Background(), "acme", SendInput{
		JobID: "nope", Message: "x", Sender: Principal{Kind: PrincipalUser, ID: "alice"},
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestPostgresStore_CloseRecordsTheVerdictAndTheWrapUp(t *testing.T) {
	script := newScript()
	script.rows["SELECT state FROM jobs"] = [][]any{{string(StateWorking)}}
	script.rows["RETURNING seq"] = [][]any{{int64(4)}}
	script.rows["SELECT id, bank_id, member_id"] = [][]any{jobRow(t, "job-1", "m-1", StateClosed)}
	store, _ := scriptedStore(t, script)

	j, err := store.Close(context.Background(), "acme", CloseInput{
		JobID: "job-1", Verdict: VerdictAccomplished, Score: 0.9,
		Closer: Principal{Kind: PrincipalUser, ID: "alice"},
	})
	if err != nil {
		t.Fatalf("Close: %v", err)
	}
	if j.State != StateClosed {
		t.Fatalf("job = %+v", j)
	}
	if !script.ran("SET state = $2, verdict") {
		t.Error("the verdict must be recorded")
	}
	if !script.ran("INSERT INTO job_inputs") {
		t.Error("a close appends the wrap-up turn: that is what performs the deliverables")
	}
}

func TestPostgresStore_CloseTwiceIsRefused(t *testing.T) {
	script := newScript()
	script.rows["SELECT state FROM jobs"] = [][]any{{string(StateClosed)}}
	store, _ := scriptedStore(t, script)
	_, err := store.Close(context.Background(), "acme", CloseInput{
		JobID: "job-1", Verdict: VerdictFailed, Closer: Principal{Kind: PrincipalUser, ID: "alice"},
	})
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed: one job, one verdict", err)
	}
}

func TestPostgresStore_ClaimTakesTheOldestQueuedJob(t *testing.T) {
	script := newScript()
	script.rows["FROM bank_members"] = [][]any{{int32(0), int32(1)}}
	script.rows["SELECT id FROM jobs"] = [][]any{{"job-1"}}
	script.rows["SELECT id, bank_id, member_id"] = [][]any{jobRow(t, "job-1", "m-1", StateOpen)}
	store, _ := scriptedStore(t, script)

	j, err := store.Claim(context.Background(), "acme", "bank-1", "m-1")
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if j == nil || j.ID != "job-1" {
		t.Fatalf("job = %+v", j)
	}
	if !script.ran("SKIP LOCKED") {
		t.Error("the queue read must skip a locked row, or two members block on one job")
	}
	if !script.ran("ORDER BY opened_at ASC") {
		t.Error("the queue is first in, first out")
	}
}

func TestPostgresStore_ClaimOnAnEmptyQueueIsNotAnError(t *testing.T) {
	script := newScript()
	script.rows["FROM bank_members"] = [][]any{{int32(0), int32(1)}}
	store, _ := scriptedStore(t, script)

	j, err := store.Claim(context.Background(), "acme", "bank-1", "m-1")
	if err != nil {
		t.Fatalf("an empty queue is the ordinary case: %v", err)
	}
	if j != nil {
		t.Fatalf("job = %+v, want nil", j)
	}
}

func TestPostgresStore_ClaimRefusesAFullMember(t *testing.T) {
	script := newScript()
	script.rows["FROM bank_members"] = [][]any{{int32(1), int32(1)}}
	store, _ := scriptedStore(t, script)
	if _, err := store.Claim(context.Background(), "acme", "bank-1", "m-1"); !errors.Is(err, ErrNoFreeSlot) {
		t.Fatalf("err = %v, want ErrNoFreeSlot", err)
	}
	if script.ran("SKIP LOCKED") {
		t.Error("a member with no room must not take a job off the queue")
	}
}

func TestPostgresStore_PendingInputsReadsTheUnacknowledged(t *testing.T) {
	script := newScript()
	script.rows["FROM job_inputs i JOIN jobs j"] = [][]any{
		inputRow("in-1", "job-1", 1, InputTurn, nil),
		inputRow("in-2", "job-1", 2, InputAnswer, nil),
	}
	store, _ := scriptedStore(t, script)

	pending, err := store.PendingInputs(context.Background(), "acme", "m-1", 10)
	if err != nil {
		t.Fatalf("PendingInputs: %v", err)
	}
	if len(pending) != 2 || pending[0].ID != "in-1" {
		t.Fatalf("pending = %+v", pending)
	}
	if !script.ran("acknowledged_at IS NULL") {
		t.Error("only unacknowledged inputs are redelivered")
	}
}

func TestPostgresStore_AcknowledgeIsIdempotent(t *testing.T) {
	script := newScript()
	script.affected["UPDATE job_inputs SET acknowledged_at"] = 1
	store, _ := scriptedStore(t, script)
	if err := store.Acknowledge(context.Background(), "acme", "in-1"); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if !script.ran("acknowledged_at IS NULL") {
		t.Error("only the first acknowledgement wins, or a redelivery window reopens")
	}

	second := newScript()
	second.affected["UPDATE job_inputs SET acknowledged_at"] = 0
	store, _ = scriptedStore(t, second)
	if err := store.Acknowledge(context.Background(), "acme", "in-1"); err != nil {
		t.Fatalf("a second acknowledgement is a no-op, not a failure: %v", err)
	}
}

func TestPostgresStore_SetStateRefusesWhatOnlyAScorerMayDo(t *testing.T) {
	store, _ := scriptedStore(t, newScript())
	if _, err := store.SetState(context.Background(), "acme", "job-1", StateClosed, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid: a job is closed by a scorer, never by a reported state", err)
	}
	if _, err := store.SetState(context.Background(), "acme", "job-1", "paused", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid for an unknown state", err)
	}
}

func TestPostgresStore_SetStateKeepsASessionItWasNotGiven(t *testing.T) {
	script := newScript()
	script.rows["SELECT state FROM jobs"] = [][]any{{string(StateWorking)}}
	script.rows["SELECT id, bank_id, member_id"] = [][]any{jobRow(t, "job-1", "m-1", StateWaiting)}
	store, _ := scriptedStore(t, script)

	j, err := store.SetState(context.Background(), "acme", "job-1", StateWaiting, "")
	if err != nil {
		t.Fatalf("SetState: %v", err)
	}
	if j.ClaudeSessionID != "sess-1" {
		t.Errorf("session = %q, want the one already recorded", j.ClaudeSessionID)
	}
	if !script.ran("CASE WHEN $3 = ''") {
		t.Error("an empty session id must keep the recorded one")
	}
}

func TestPostgresStore_SetStateOnAClosedJobIsRefused(t *testing.T) {
	script := newScript()
	script.rows["SELECT state FROM jobs"] = [][]any{{string(StateClosed)}}
	store, _ := scriptedStore(t, script)
	if _, err := store.SetState(context.Background(), "acme", "job-1", StateWorking, ""); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v, want ErrClosed", err)
	}
}

func TestPostgresStore_AddDeliverable(t *testing.T) {
	script := newScript()
	script.affected["UPDATE jobs SET deliverables"] = 1
	script.rows["SELECT id, bank_id, member_id"] = [][]any{jobRow(t, "job-1", "m-1", StateWorking)}
	store, _ := scriptedStore(t, script)

	if _, err := store.AddDeliverable(context.Background(), "acme", "job-1", &jobpb.Deliverable{
		Kind: jobpb.DeliverableKind_DELIVERABLE_KIND_MERGE_REQUEST, Ref: "mr-1",
	}); err != nil {
		t.Fatalf("AddDeliverable: %v", err)
	}
	if !script.ran("INSERT INTO job_events") {
		t.Error("a deliverable is an event on the job")
	}

	missing := newScript()
	missing.affected["UPDATE jobs SET deliverables"] = 0
	store, _ = scriptedStore(t, missing)
	if _, err := store.AddDeliverable(context.Background(), "acme", "nope", &jobpb.Deliverable{Ref: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	store, _ = scriptedStore(t, newScript())
	if _, err := store.AddDeliverable(context.Background(), "acme", "job-1", nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid for no deliverable", err)
	}
}

func TestPostgresStore_EventsDecodeTheirPayload(t *testing.T) {
	script := newScript()
	script.rows["FROM job_events"] = [][]any{
		eventRow("job-1", 1, EventOpened, nil),
		eventRow("job-1", 2, EventDeliverable, []byte(`{"kind":"DELIVERABLE_KIND_PUSH_BRANCH","ref":"job/1"}`)),
	}
	store, _ := scriptedStore(t, script)

	events, err := store.Events(context.Background(), "acme", "job-1", 0, 100)
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("events = %d", len(events))
	}
	if events[1].Deliverable == nil || events[1].Deliverable.GetRef() != "job/1" {
		t.Fatalf("a deliverable event must carry its deliverable: %+v", events[1])
	}
	if events[0].Deliverable != nil {
		t.Error("an event that is not a deliverable carries none")
	}
	if !script.ran("seq > $2") {
		t.Error("resuming reads only what came after the sequence")
	}
}

func TestPostgresStore_StaleNeedsALimit(t *testing.T) {
	script := newScript()
	store, _ := scriptedStore(t, script)
	jobs, err := store.Stale(context.Background(), "acme", "bank-1", 0, 10)
	if err != nil || jobs != nil {
		t.Fatalf("no limit means nothing is stale: %v %v", jobs, err)
	}
	if len(script.seen) != 0 {
		t.Fatal("no limit must run no query: closing every open job of a bank is the opposite of what its owner asked")
	}

	with := newScript()
	with.rows["SELECT id, bank_id, member_id"] = [][]any{jobRow(t, "job-1", "", StateOpen)}
	store, _ = scriptedStore(t, with)
	jobs, err = store.Stale(context.Background(), "acme", "bank-1", 3600, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("stale = %v %v", jobs, err)
	}
	if !with.ran("make_interval") {
		t.Error("the stale window is the bank's limit")
	}
}

func TestPostgresStore_ListFiltersAndPages(t *testing.T) {
	script := newScript()
	script.rows["SELECT id, bank_id, member_id"] = [][]any{
		jobRow(t, "job-3", "", StateOpen), jobRow(t, "job-2", "", StateOpen), jobRow(t, "job-1", "", StateOpen),
	}
	store, _ := scriptedStore(t, script)

	page, next, err := store.List(context.Background(), "acme", ListFilter{BankID: "bank-1"}, Page{Size: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page) != 2 || next == "" {
		t.Fatalf("page = %d next = %q", len(page), next)
	}
	if !script.ran("ORDER BY opened_at DESC") {
		t.Error("jobs list newest first")
	}

	bad := newScript()
	store, _ = scriptedStore(t, bad)
	if _, _, err := store.List(context.Background(), "acme", ListFilter{}, Page{Token: "!!!"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if len(bad.seen) != 0 {
		t.Fatal("an unreadable token runs no query")
	}
}

func TestPostgresStore_AnUnreachableTenantIsReported(t *testing.T) {
	store := &postgresStore{conns: scriptedConns{err: errors.New("tenant not provisioned")}}
	ctx := context.Background()
	if _, err := store.Open(ctx, "acme", openInput()); err == nil {
		t.Error("Open must report an unreachable tenant")
	}
	if _, err := store.Get(ctx, "acme", "job-1"); err == nil {
		t.Error("Get must report an unreachable tenant")
	}
	if _, _, err := store.List(ctx, "acme", ListFilter{}, Page{}); err == nil {
		t.Error("List must report an unreachable tenant")
	}
	if _, err := store.Send(ctx, "acme", SendInput{JobID: "j", Message: "x", Sender: Principal{Kind: PrincipalUser, ID: "a"}}); err == nil {
		t.Error("Send must report an unreachable tenant")
	}
	if _, err := store.Close(ctx, "acme", CloseInput{JobID: "j", Verdict: VerdictFailed, Closer: Principal{Kind: PrincipalUser, ID: "a"}}); err == nil {
		t.Error("Close must report an unreachable tenant")
	}
	if _, err := store.Claim(ctx, "acme", "bank-1", "m-1"); err == nil {
		t.Error("Claim must report an unreachable tenant")
	}
	if _, err := store.PendingInputs(ctx, "acme", "m-1", 10); err == nil {
		t.Error("PendingInputs must report an unreachable tenant")
	}
	if err := store.Acknowledge(ctx, "acme", "in-1"); err == nil {
		t.Error("Acknowledge must report an unreachable tenant")
	}
	if _, err := store.SetState(ctx, "acme", "j", StateWorking, ""); err == nil {
		t.Error("SetState must report an unreachable tenant")
	}
	if _, err := store.AddDeliverable(ctx, "acme", "j", &jobpb.Deliverable{Ref: "x"}); err == nil {
		t.Error("AddDeliverable must report an unreachable tenant")
	}
	if _, err := store.Events(ctx, "acme", "j", 0, 10); err == nil {
		t.Error("Events must report an unreachable tenant")
	}
	if _, err := store.Stale(ctx, "acme", "bank-1", 3600, 10); err == nil {
		t.Error("Stale must report an unreachable tenant")
	}
}

func TestPoolConns_RefusesAnInvalidTenant(t *testing.T) {
	if _, err := (poolConns{}).For(context.Background(), "NOT A TENANT"); err == nil {
		t.Fatal("an unparseable tenant must be refused before the pool is asked")
	}
}

// TestPostgresStore_ADriverErrorIsWrappedNotSwallowed asserts that a failure
// the database reports on any statement reaches the caller wrapped, and is
// never mistaken for a domain outcome such as "not found" or "closed".
func TestPostgresStore_ADriverErrorIsWrappedNotSwallowed(t *testing.T) {
	boom := errors.New("connection reset")
	script := newScript()
	for _, frag := range []string{"INSERT", "SELECT", "UPDATE", "DELETE", "WITH"} {
		script.errs[frag] = boom
	}
	store, _ := scriptedStore(t, script)
	ctx := context.Background()
	sender := Principal{Kind: PrincipalUser, ID: "alice"}

	checks := map[string]func() error{
		"Open": func() error { _, err := store.Open(ctx, "acme", openInput()); return err },
		"Get":  func() error { _, err := store.Get(ctx, "acme", "job-1"); return err },
		"List": func() error { _, _, err := store.List(ctx, "acme", ListFilter{}, Page{}); return err },
		"Send": func() error {
			_, err := store.Send(ctx, "acme", SendInput{JobID: "j", Message: "x", Sender: sender})
			return err
		},
		"Close": func() error {
			_, err := store.Close(ctx, "acme", CloseInput{JobID: "j", Verdict: VerdictFailed, Closer: sender})
			return err
		},
		"Claim":  func() error { _, err := store.Claim(ctx, "acme", "bank-1", "m-1"); return err },
		"Ack":    func() error { return store.Acknowledge(ctx, "acme", "in-1") },
		"Inputs": func() error { _, err := store.PendingInputs(ctx, "acme", "m-1", 10); return err },
		"State":  func() error { _, err := store.SetState(ctx, "acme", "j", StateWorking, ""); return err },
		"Deliv": func() error {
			_, err := store.AddDeliverable(ctx, "acme", "j", &jobpb.Deliverable{Ref: "x"})
			return err
		},
		"Events": func() error { _, err := store.Events(ctx, "acme", "j", 0, 10); return err },
		"Stale":  func() error { _, err := store.Stale(ctx, "acme", "bank-1", 3600, 10); return err },
	}
	for name, call := range checks {
		err := call()
		if !errors.Is(err, boom) {
			t.Errorf("%s: err = %v, want the driver error wrapped", name, err)
		}
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrClosed) {
			t.Errorf("%s: a driver error must not be reported as a domain outcome: %v", name, err)
		}
	}
}

// TestNewPostgresStore_RefusesANilPool asserts the constructor panics rather
// than build a store that fails on first use.
func TestNewPostgresStore_RefusesANilPool(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a nil pool must panic")
		}
	}()
	NewPostgresStore(nil)
}

// TestPostgresStore_ReleaseMemberHandsOpenJobsBack asserts that a dead
// member's open jobs lose their member and keep everything else, that the
// count comes back, and that an empty member is refused without a statement.
func TestPostgresStore_ReleaseMemberHandsOpenJobsBack(t *testing.T) {
	script := newScript()
	script.affected["UPDATE jobs SET member_id = ''"] = 2
	store, c := scriptedStore(t, script)

	n, err := store.ReleaseMember(context.Background(), "acme", "m-1")
	if err != nil {
		t.Fatalf("ReleaseMember: %v", err)
	}
	if n != 2 {
		t.Fatalf("released = %d, want 2", n)
	}
	if !c.released {
		t.Error("the connection must be released")
	}
	if len(script.seen) != 1 || !strings.Contains(script.seen[0], "state <>") {
		t.Fatalf("a release must leave closed jobs alone, ran %v", script.seen)
	}

	seen := len(script.seen)
	if _, err := store.ReleaseMember(context.Background(), "acme", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if len(script.seen) != seen {
		t.Error("an empty member must not reach the database")
	}
}
