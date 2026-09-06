// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package bank

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
)

// A scripted database.
//
// The store's own logic — what it validates, what it refuses, how it pages, and
// which statement it runs — is what a reader has to trust, and a
// container-backed test exercises it only on a machine that has Docker. This
// fake answers the statements the store issues, so that logic is checked in the
// ordinary test lane and the container test is left to prove the one thing only
// a real database can: that the shipped migration and these statements agree.

// scriptedSQL answers each statement from a table keyed by a substring of the
// SQL, so a test says what a query returns without repeating the whole
// statement.
type scriptedSQL struct {
	// rows maps a SQL fragment to the rows a matching query returns.
	rows map[string][][]any
	// errs maps a SQL fragment to the error a matching statement returns.
	errs map[string]error
	// affected maps a SQL fragment to the row count an Exec reports.
	affected map[string]int64
	// seen records every statement, in order, so a test can assert what ran.
	seen []string
}

func newScript() *scriptedSQL {
	return &scriptedSQL{
		rows: map[string][][]any{}, errs: map[string]error{}, affected: map[string]int64{},
	}
}

// match returns the scripted entry whose key appears in the statement,
// preferring the longest key. Map iteration is random, so without that a
// statement matching two fragments would answer differently from run to run.
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
	err    error
}

func (r *scriptedRows) Next() bool { r.i++; return r.i <= len(r.values) }
func (r *scriptedRows) Scan(dest ...any) error {
	if r.i == 0 || r.i > len(r.values) {
		return errors.New("scriptedRows: Scan without Next")
	}
	return assign(dest, r.values[r.i-1])
}
func (r *scriptedRows) Err() error { return r.err }
func (r *scriptedRows) Close()     {}

// assign copies scripted values into the scan destinations, by type. It covers
// exactly the column types the bank tables use.
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
		case *bool:
			*p = values[i].(bool)
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
		case *[]string:
			*p = values[i].([]string)
		default:
			return errors.New("scripted row: unsupported scan target")
		}
	}
	return nil
}

// scriptedConn hands the same scripted SQL to statements and transactions, so
// a transaction's statements are recorded in the same order they ran.
type scriptedConn struct {
	sql      *scriptedSQL
	txErr    error
	released bool
}

func (c *scriptedConn) SQL() datapool.SQL { return c.sql }
func (c *scriptedConn) InTx(_ context.Context, fn func(datapool.SQL) error) error {
	if c.txErr != nil {
		return c.txErr
	}
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

// bankRow is a stored bank in column order.
func bankRow(id, name string, desired int32) []any {
	return []any{
		id, name, "user", "alice", desired, "api_key",
		"tenant-anthropic", "claude", "", int32(1),
		int64(3600), "queue", unitNow, unitNow,
	}
}

// memberRow is a stored member in column order.
func memberRow(id, bankID string, state MemberState) []any {
	beat := unitNow
	return []any{
		id, bankID, "m", "run", "agent", "sbx",
		string(state), int32(0), int32(1), []string{}, "2.0.1",
		&beat, unitNow, unitNow,
	}
}

func TestPostgresStore_CreateReturnsTheStoredBankAndReleases(t *testing.T) {
	script := newScript()
	store, c := scriptedStore(t, script)

	b, err := store.Create(context.Background(), "acme", validCreate())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if b.ID == "" || b.Name != "nightly" {
		t.Fatalf("bank = %+v", b)
	}
	if b.AgentName != DefaultAgentName || b.StaleLimit != DefaultStaleLimit {
		t.Errorf("the defaults must be filled before the insert: %+v", b)
	}
	if len(script.seen) != 1 || !strings.Contains(script.seen[0], "INSERT INTO banks") {
		t.Fatalf("statements = %v, want one insert", script.seen)
	}
	if !c.released {
		t.Error("the connection must be released")
	}
}

func TestPostgresStore_CreateMapsAUniqueViolation(t *testing.T) {
	script := newScript()
	script.errs["INSERT INTO banks"] = datapool.ErrUniqueViolation
	store, _ := scriptedStore(t, script)

	_, err := store.Create(context.Background(), "acme", validCreate())
	if !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestPostgresStore_CreateRefusesBeforeTouchingTheDatabase(t *testing.T) {
	script := newScript()
	store, _ := scriptedStore(t, script)
	in := validCreate()
	in.LoginShape = "oauth"

	if _, err := store.Create(context.Background(), "acme", in); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if len(script.seen) != 0 {
		t.Fatalf("a refused input must run no statement, ran %v", script.seen)
	}
}

func TestPostgresStore_GetReadsBackEveryField(t *testing.T) {
	script := newScript()
	script.rows["FROM banks WHERE id"] = [][]any{bankRow("bank-1", "nightly", 3)}
	store, _ := scriptedStore(t, script)

	b, err := store.Get(context.Background(), "acme", "bank-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if b.Name != "nightly" || b.DesiredCount != 3 {
		t.Fatalf("bank = %+v", b)
	}
	if b.LoginShape != LoginShapeAPIKey || b.SpillPolicy != SpillQueue {
		t.Errorf("enum columns must map back: %+v", b)
	}
	if b.StaleLimit != time.Hour {
		t.Errorf("stale limit = %s, want the seconds column read back as a duration", b.StaleLimit)
	}
	if b.OwnerKind != OwnerUser || b.OwnerID != "alice" {
		t.Errorf("owner = %s/%s", b.OwnerKind, b.OwnerID)
	}
}

func TestPostgresStore_GetMapsNoRowsToNotFound(t *testing.T) {
	store, _ := scriptedStore(t, newScript())
	if _, err := store.Get(context.Background(), "acme", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestPostgresStore_ListPagesAndCarriesAToken(t *testing.T) {
	script := newScript()
	// Three rows for a page of two: the store asks for size+1 to know there is
	// more without a second count query.
	script.rows["FROM banks"] = [][]any{
		bankRow("bank-3", "three", 1), bankRow("bank-2", "two", 1), bankRow("bank-1", "one", 1),
	}
	store, _ := scriptedStore(t, script)

	page, next, err := store.List(context.Background(), "acme", Page{Size: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page) != 2 || next == "" {
		t.Fatalf("page = %d next = %q, want two rows and a token", len(page), next)
	}
	c, err := decodeToken(next)
	if err != nil || c.id != "bank-2" {
		t.Fatalf("token points at %+v, want the last row of the page", c)
	}
}

func TestPostgresStore_ListRefusesAnUnreadableToken(t *testing.T) {
	script := newScript()
	store, _ := scriptedStore(t, script)
	if _, _, err := store.List(context.Background(), "acme", Page{Token: "!!!"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if len(script.seen) != 0 {
		t.Fatal("an unreadable token must run no query")
	}
}

func TestPostgresStore_UpdateReadsBackTheChangedBank(t *testing.T) {
	script := newScript()
	script.rows["UPDATE banks SET"] = [][]any{bankRow("bank-1", "nightly", 4)}
	store, _ := scriptedStore(t, script)

	four := int32(4)
	b, err := store.Update(context.Background(), "acme", "bank-1", UpdateInput{DesiredCount: &four})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if b.DesiredCount != 4 {
		t.Fatalf("bank = %+v", b)
	}
	if !strings.Contains(script.seen[0], "COALESCE") {
		t.Error("an absent field must keep its value through COALESCE, not a read-modify-write")
	}
}

func TestPostgresStore_UpdateMapsNoRowsToNotFound(t *testing.T) {
	store, _ := scriptedStore(t, newScript())
	one := int32(1)
	_, err := store.Update(context.Background(), "acme", "nope", UpdateInput{DesiredCount: &one})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestPostgresStore_UpdateRefusesBeforeTouchingTheDatabase(t *testing.T) {
	script := newScript()
	store, _ := scriptedStore(t, script)
	neg := int32(-1)
	if err := errFromUpdate(store, UpdateInput{DesiredCount: &neg}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if len(script.seen) != 0 {
		t.Fatal("a refused update must run no statement")
	}
}

func errFromUpdate(store Store, in UpdateInput) error {
	_, err := store.Update(context.Background(), "acme", "bank-1", in)
	if err != nil {
		return fmt.Errorf("update: %w", err)
	}
	return nil
}

func TestPostgresStore_DeleteReportsWhetherARowWent(t *testing.T) {
	script := newScript()
	script.affected["DELETE FROM banks"] = 1
	store, _ := scriptedStore(t, script)
	if err := store.Delete(context.Background(), "acme", "bank-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	gone := newScript()
	gone.affected["DELETE FROM banks"] = 0
	store, _ = scriptedStore(t, gone)
	if err := store.Delete(context.Background(), "acme", "bank-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestPostgresStore_ListMembersReadsTheReportedStatus(t *testing.T) {
	script := newScript()
	script.rows["FROM bank_members"] = [][]any{
		memberRow("m-1", "bank-1", MemberIdle), memberRow("m-2", "bank-1", MemberBusy),
	}
	store, _ := scriptedStore(t, script)

	members, next, err := store.ListMembers(context.Background(), "acme", "bank-1", Page{})
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	if len(members) != 2 || next != "" {
		t.Fatalf("members = %d next = %q", len(members), next)
	}
	if members[0].State != MemberIdle || members[1].State != MemberBusy {
		t.Errorf("states = %q,%q", members[0].State, members[1].State)
	}
	if members[0].JobCap != 1 || members[0].ClaudeVersion != "2.0.1" {
		t.Errorf("member = %+v", members[0])
	}
	if members[0].LastHeartbeat.IsZero() {
		t.Error("a member that reported must carry its heartbeat time")
	}
	if !strings.Contains(script.seen[0], "ORDER BY created_at ASC") {
		t.Error("members list oldest first: the order they were launched")
	}
}

func TestPostgresStore_AnUnreachableTenantIsReported(t *testing.T) {
	store := &postgresStore{conns: scriptedConns{err: errors.New("tenant not provisioned")}}
	ctx := context.Background()
	if _, err := store.Get(ctx, "acme", "bank-1"); err == nil {
		t.Error("Get must report an unreachable tenant")
	}
	if _, err := store.Create(ctx, "acme", validCreate()); err == nil {
		t.Error("Create must report an unreachable tenant")
	}
	if _, _, err := store.List(ctx, "acme", Page{}); err == nil {
		t.Error("List must report an unreachable tenant")
	}
	if err := store.Delete(ctx, "acme", "bank-1"); err == nil {
		t.Error("Delete must report an unreachable tenant")
	}
	if _, _, err := store.ListMembers(ctx, "acme", "bank-1", Page{}); err == nil {
		t.Error("ListMembers must report an unreachable tenant")
	}
	one := int32(1)
	if _, err := store.Update(ctx, "acme", "bank-1", UpdateInput{DesiredCount: &one}); err == nil {
		t.Error("Update must report an unreachable tenant")
	}
}

func TestPoolConns_RefusesAnInvalidTenant(t *testing.T) {
	if _, err := (poolConns{}).For(context.Background(), "NOT A TENANT"); err == nil {
		t.Fatal("an unparseable tenant must be refused before the pool is asked")
	}
}

// TestPostgresStore_ADriverErrorIsWrappedNotSwallowed asserts that a failure
// the database reports on any statement reaches the caller wrapped, and is
// never mistaken for "not found" or "already exists".
func TestPostgresStore_ADriverErrorIsWrappedNotSwallowed(t *testing.T) {
	boom := errors.New("connection reset")
	script := newScript()
	for _, frag := range []string{"INSERT INTO banks", "SELECT", "UPDATE banks", "DELETE FROM banks",
		"INSERT INTO bank_members", "UPDATE bank_members", "DELETE FROM bank_members"} {
		script.errs[frag] = boom
	}
	store, _ := scriptedStore(t, script)
	ctx := context.Background()
	one := int32(1)

	checks := map[string]func() error{
		"Create": func() error { _, err := store.Create(ctx, "acme", validCreate()); return err },
		"Get":    func() error { _, err := store.Get(ctx, "acme", "bank-1"); return err },
		"List":   func() error { _, _, err := store.List(ctx, "acme", Page{}); return err },
		"Update": func() error {
			_, err := store.Update(ctx, "acme", "bank-1", UpdateInput{DesiredCount: &one})
			return err
		},
		"Delete":      func() error { return store.Delete(ctx, "acme", "bank-1") },
		"ListMembers": func() error { _, _, err := store.ListMembers(ctx, "acme", "bank-1", Page{}); return err },
		"ListAll":     func() error { _, err := store.ListAll(ctx, "acme"); return err },
		"MemberByRun": func() error { _, err := store.MemberByRun(ctx, "acme", "run-1"); return err },
		"AddMember": func() error {
			return store.AddMember(ctx, "acme", &Member{ID: "m-1", BankID: "bank-1"})
		},
		"UpdateMemberStatus": func() error {
			_, err := store.UpdateMemberStatus(ctx, "acme", "m-1", MemberStatus{State: MemberIdle})
			return err
		},
		"SetMemberState": func() error { _, err := store.SetMemberState(ctx, "acme", "m-1", MemberDead); return err },
		"RemoveMember":   func() error { return store.RemoveMember(ctx, "acme", "m-1") },
	}
	for name, call := range checks {
		err := call()
		if !errors.Is(err, boom) {
			t.Errorf("%s: err = %v, want the driver error wrapped", name, err)
		}
		if errors.Is(err, ErrNotFound) || errors.Is(err, ErrAlreadyExists) {
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

// TestPostgresStore_MemberByRunResolvesTheCallingMember asserts that a run
// resolves to exactly the member it backs, that a run backing no member is
// not found, and that an empty run is refused without a query: an empty run
// must never match the row of a member that has not been given one.
func TestPostgresStore_MemberByRunResolvesTheCallingMember(t *testing.T) {
	script := newScript()
	script.rows["WHERE mission_run_id"] = [][]any{memberRow("m-1", "bank-1", MemberIdle)}
	store, c := scriptedStore(t, script)

	m, err := store.MemberByRun(context.Background(), "acme", "run")
	if err != nil {
		t.Fatalf("MemberByRun: %v", err)
	}
	if m.ID != "m-1" || m.BankID != "bank-1" {
		t.Fatalf("member = %+v", m)
	}
	if !c.released {
		t.Error("the connection must be released")
	}

	script.rows["WHERE mission_run_id"] = nil
	if _, err := store.MemberByRun(context.Background(), "acme", "run-gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}

	seen := len(script.seen)
	if _, err := store.MemberByRun(context.Background(), "acme", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if len(script.seen) != seen {
		t.Error("an empty run must not reach the database")
	}
}

// TestPostgresStore_ReconcilerReadsAndWrites covers what the reconciler needs
// of the store: every bank unpaged, a member recorded, its reported status
// stamped with a heartbeat, a daemon-decided state set, and its row removed.
func TestPostgresStore_ReconcilerReadsAndWrites(t *testing.T) {
	script := newScript()
	script.rows["FROM banks ORDER BY created_at ASC"] = [][]any{bankRow("bank-1", "nightly", 2), bankRow("bank-2", "weekly", 1)}
	script.rows["RETURNING"] = [][]any{memberRow("m-1", "bank-1", MemberBusy)}
	script.affected["DELETE FROM bank_members"] = 1
	store, _ := scriptedStore(t, script)
	ctx := context.Background()

	banks, err := store.ListAll(ctx, "acme")
	if err != nil || len(banks) != 2 {
		t.Fatalf("ListAll = %d banks, %v", len(banks), err)
	}

	if err := store.AddMember(ctx, "acme", &Member{ID: "m-1", BankID: "bank-1", State: MemberLaunching, JobCap: 1}); err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if err := store.AddMember(ctx, "acme", &Member{ID: "", BankID: "bank-1"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a member with no id must be refused, got %v", err)
	}

	m, err := store.UpdateMemberStatus(ctx, "acme", "m-1", MemberStatus{State: MemberBusy, JobsInFlight: 1, JobCap: 1})
	if err != nil || m.State != MemberBusy {
		t.Fatalf("UpdateMemberStatus = %+v, %v", m, err)
	}
	if _, err := store.UpdateMemberStatus(ctx, "acme", "m-1", MemberStatus{State: MemberDead}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a member may not report itself dead, got %v", err)
	}

	if _, err := store.SetMemberState(ctx, "acme", "m-1", MemberDraining); err != nil {
		t.Fatalf("SetMemberState: %v", err)
	}
	if _, err := store.SetMemberState(ctx, "acme", "m-1", MemberState("sleepy")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an unknown state must be refused, got %v", err)
	}

	if err := store.RemoveMember(ctx, "acme", "m-1"); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}
	script.affected["DELETE FROM bank_members"] = 0
	if err := store.RemoveMember(ctx, "acme", "m-gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removing a missing member is not found, got %v", err)
	}
}

// TestPostgresStore_ReconcilerWritesMapNoRowsAndDuplicates asserts the
// not-found and already-exists outcomes of the member writes.
func TestPostgresStore_ReconcilerWritesMapNoRowsAndDuplicates(t *testing.T) {
	script := newScript()
	script.errs["INSERT INTO bank_members"] = datapool.ErrUniqueViolation
	store, _ := scriptedStore(t, script)
	ctx := context.Background()

	if err := store.AddMember(ctx, "acme", &Member{ID: "m-1", BankID: "bank-1"}); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("a duplicate member is already-exists, got %v", err)
	}
	if _, err := store.UpdateMemberStatus(ctx, "acme", "m-gone", MemberStatus{State: MemberIdle}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("status of a missing member is not found, got %v", err)
	}
	if _, err := store.SetMemberState(ctx, "acme", "m-gone", MemberDead); !errors.Is(err, ErrNotFound) {
		t.Fatalf("state of a missing member is not found, got %v", err)
	}
	if _, err := store.ListAll(ctx, "acme"); err != nil {
		t.Fatalf("ListAll on an empty tenant: %v", err)
	}
}

// TestPostgresStore_GetMemberReadsOneRow asserts a member reads back by id,
// a missing one is not found, and an empty id is refused without a query.
func TestPostgresStore_GetMemberReadsOneRow(t *testing.T) {
	script := newScript()
	script.rows["FROM bank_members WHERE id"] = [][]any{memberRow("m-1", "bank-1", MemberBusy)}
	store, _ := scriptedStore(t, script)
	ctx := context.Background()

	m, err := store.GetMember(ctx, "acme", "m-1")
	if err != nil || m.ID != "m-1" || m.State != MemberBusy {
		t.Fatalf("GetMember = %+v, %v", m, err)
	}
	script.rows["FROM bank_members WHERE id"] = nil
	if _, err := store.GetMember(ctx, "acme", "m-9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	seen := len(script.seen)
	if _, err := store.GetMember(ctx, "acme", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if len(script.seen) != seen {
		t.Error("an empty id must not reach the database")
	}
}
