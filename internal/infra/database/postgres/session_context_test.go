// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool/envelope"
)

// ---------------------------------------------------------------------------
// sessionContextAAD binding
// ---------------------------------------------------------------------------

func TestSessionContextAAD(t *testing.T) {
	aad := sessionContextAAD("sess-1")
	if string(aad) != "session_context:sess-1" {
		t.Errorf("sessionContextAAD: want %q, got %q", "session_context:sess-1", string(aad))
	}
	// Distinct sessions must produce distinct AADs — the AAD is what stops a
	// row from being re-pointed at another session.
	if string(sessionContextAAD("sess-2")) == string(aad) {
		t.Error("sessionContextAAD must differ per session")
	}
	// And the namespace must not collide with the secrets AAD space.
	if string(secretAAD("x")) == string(sessionContextAAD("x")) {
		t.Error("session-context AAD must not collide with the tenant-secret AAD namespace")
	}
}

// ---------------------------------------------------------------------------
// Sentinels
// ---------------------------------------------------------------------------

func TestErrSessionContextConflictSentinel(t *testing.T) {
	wrapped := fmt.Errorf("session context %q: %w", "s", ErrSessionContextConflict)
	if !errors.Is(wrapped, ErrSessionContextConflict) {
		t.Error("wrapped ErrSessionContextConflict: errors.Is must find it")
	}
}

func TestErrSessionContextTooLargeSentinel(t *testing.T) {
	wrapped := fmt.Errorf("cap: %w", ErrSessionContextTooLarge)
	if !errors.Is(wrapped, ErrSessionContextTooLarge) {
		t.Error("wrapped ErrSessionContextTooLarge: errors.Is must find it")
	}
}

// ---------------------------------------------------------------------------
// Input validation (no DB required)
// ---------------------------------------------------------------------------

func TestSessionContextOps_PutValidation(t *testing.T) {
	o := NewSessionContextOps(nil, make([]byte, 32), "tenant-a")

	if _, err := o.Put(t.Context(), "", []byte("x"), ""); err == nil {
		t.Error("Put with empty session_id must fail")
	}
	if _, err := o.Put(t.Context(), "s", nil, ""); err == nil {
		t.Error("Put with empty data must fail")
	}
	_, err := o.Put(t.Context(), "s", make([]byte, MaxSessionContextBytes+1), "")
	if !errors.Is(err, ErrSessionContextTooLarge) {
		t.Errorf("Put beyond the size cap must return ErrSessionContextTooLarge, got %v", err)
	}
}

func TestSessionContextOps_GetDeleteValidation(t *testing.T) {
	o := NewSessionContextOps(nil, make([]byte, 32), "tenant-a")

	if _, _, err := o.Get(t.Context(), ""); err == nil {
		t.Error("Get with empty session_id must fail")
	}
	if err := o.Delete(t.Context(), ""); err == nil {
		t.Error("Delete with empty session_id must fail")
	}
}

// ---------------------------------------------------------------------------
// Query-path tests against a fake SessionContextQuerier (no live Postgres):
// CAS semantics, envelope round-trip, absent-is-not-an-error, reap piggyback.
// ---------------------------------------------------------------------------

// fakeSessionRow implements pgx.Row.
type fakeSessionRow struct {
	env  []byte
	etag string
	err  error
}

func (r *fakeSessionRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*[]byte)) = r.env
	*(dest[1].(*string)) = r.etag
	return nil
}

// fakeSessionQuerier scripts Exec results in order and records every SQL
// statement it sees.
type fakeSessionQuerier struct {
	execTags []pgconn.CommandTag
	execErrs []error
	execSQL  []string
	execArgs [][]any
	row      pgx.Row
}

func (q *fakeSessionQuerier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	q.execSQL = append(q.execSQL, sql)
	q.execArgs = append(q.execArgs, args)
	i := len(q.execSQL) - 1
	var tag pgconn.CommandTag
	var err error
	if i < len(q.execTags) {
		tag = q.execTags[i]
	}
	if i < len(q.execErrs) {
		err = q.execErrs[i]
	}
	return tag, err
}

func (q *fakeSessionQuerier) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	q.execSQL = append(q.execSQL, sql)
	return q.row
}

func testKEK(t *testing.T) []byte {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	return kek
}

func TestSessionContextOps_PutCreateSucceedsAndReaps(t *testing.T) {
	q := &fakeSessionQuerier{
		execTags: []pgconn.CommandTag{pgconn.NewCommandTag("INSERT 0 1"), pgconn.NewCommandTag("DELETE 0")},
	}
	o := NewSessionContextOps(q, testKEK(t), "tenant-a")

	etag, err := o.Put(t.Context(), "sess-1", []byte("blob"), "")
	if err != nil {
		t.Fatalf("Put create: %v", err)
	}
	if etag == "" {
		t.Error("Put must return the etag of the version it produced")
	}
	if len(q.execSQL) != 2 {
		t.Fatalf("expected create + opportunistic reap (2 Execs), got %d: %v", len(q.execSQL), q.execSQL)
	}
	if !strings.Contains(q.execSQL[0], "INSERT INTO session_context") ||
		!strings.Contains(q.execSQL[0], "expires_at <= now()") {
		t.Errorf("create must be the expired-row-aware upsert, got: %s", q.execSQL[0])
	}
	if !strings.Contains(q.execSQL[1], "DELETE FROM session_context WHERE expires_at <= now()") {
		t.Errorf("second Exec must be the expired-row reap, got: %s", q.execSQL[1])
	}
	// The stored envelope must not be the plaintext.
	if string(q.execArgs[0][1].([]byte)) == "blob" {
		t.Error("the blob must be envelope-encrypted before it reaches Postgres")
	}
}

func TestSessionContextOps_PutCreateConflictWhenLiveRowExists(t *testing.T) {
	q := &fakeSessionQuerier{execTags: []pgconn.CommandTag{pgconn.NewCommandTag("INSERT 0 0")}}
	o := NewSessionContextOps(q, testKEK(t), "tenant-a")

	_, err := o.Put(t.Context(), "sess-1", []byte("blob"), "")
	if !errors.Is(err, ErrSessionContextConflict) {
		t.Fatalf("create over a live row must be ErrSessionContextConflict, got %v", err)
	}
}

func TestSessionContextOps_PutUpdateIsEtagCAS(t *testing.T) {
	q := &fakeSessionQuerier{
		execTags: []pgconn.CommandTag{pgconn.NewCommandTag("UPDATE 1"), pgconn.NewCommandTag("DELETE 0")},
	}
	o := NewSessionContextOps(q, testKEK(t), "tenant-a")

	etag, err := o.Put(t.Context(), "sess-1", []byte("blob2"), "prev-etag")
	if err != nil {
		t.Fatalf("Put update: %v", err)
	}
	if etag == "" || etag == "prev-etag" {
		t.Errorf("update must mint a NEW etag, got %q", etag)
	}
	if !strings.Contains(q.execSQL[0], "UPDATE session_context") ||
		!strings.Contains(q.execSQL[0], "etag = $5") ||
		!strings.Contains(q.execSQL[0], "expires_at > now()") {
		t.Errorf("update must CAS on the stored etag over a live row, got: %s", q.execSQL[0])
	}
	if got := q.execArgs[0][4].(string); got != "prev-etag" {
		t.Errorf("ifMatch must be the CAS operand, got %q", got)
	}
}

func TestSessionContextOps_PutUpdateStaleEtagConflicts(t *testing.T) {
	q := &fakeSessionQuerier{execTags: []pgconn.CommandTag{pgconn.NewCommandTag("UPDATE 0")}}
	o := NewSessionContextOps(q, testKEK(t), "tenant-a")

	_, err := o.Put(t.Context(), "sess-1", []byte("blob"), "stale")
	if !errors.Is(err, ErrSessionContextConflict) {
		t.Fatalf("stale etag must be ErrSessionContextConflict, got %v", err)
	}
}

func TestSessionContextOps_PutExecErrorPropagates(t *testing.T) {
	boom := errors.New("pg down")
	q := &fakeSessionQuerier{execErrs: []error{boom}}
	o := NewSessionContextOps(q, testKEK(t), "tenant-a")

	_, err := o.Put(t.Context(), "sess-1", []byte("blob"), "")
	if !errors.Is(err, boom) {
		t.Fatalf("Exec error must propagate wrapped, got %v", err)
	}
}

func TestSessionContextOps_GetRoundtripsEnvelope(t *testing.T) {
	kek := testKEK(t)
	env, err := envelope.Encrypt(kek, []byte("checkpoint"), sessionContextAAD("sess-1"))
	if err != nil {
		t.Fatal(err)
	}
	q := &fakeSessionQuerier{row: &fakeSessionRow{env: env, etag: "v7"}}
	o := NewSessionContextOps(q, kek, "tenant-a")

	data, etag, err := o.Get(t.Context(), "sess-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(data) != "checkpoint" || etag != "v7" {
		t.Errorf("Get round-trip: got (%q, %q)", data, etag)
	}
	if !strings.Contains(q.execSQL[0], "expires_at > now()") {
		t.Errorf("Get must treat expired rows as absent, got: %s", q.execSQL[0])
	}
}

func TestSessionContextOps_GetAbsentIsNotAnError(t *testing.T) {
	q := &fakeSessionQuerier{row: &fakeSessionRow{err: pgx.ErrNoRows}}
	o := NewSessionContextOps(q, testKEK(t), "tenant-a")

	data, etag, err := o.Get(t.Context(), "never-written")
	if err != nil {
		t.Fatalf("a fresh session must not be an error, got %v", err)
	}
	if data != nil || etag != "" {
		t.Errorf("absent blob must be (nil, \"\"), got (%v, %q)", data, etag)
	}
}

func TestSessionContextOps_GetQueryErrorPropagates(t *testing.T) {
	boom := errors.New("pg down")
	q := &fakeSessionQuerier{row: &fakeSessionRow{err: boom}}
	o := NewSessionContextOps(q, testKEK(t), "tenant-a")

	if _, _, err := o.Get(t.Context(), "sess-1"); !errors.Is(err, boom) {
		t.Fatalf("query error must propagate wrapped, got %v", err)
	}
}

func TestSessionContextOps_GetKEKMismatchIsCrossTenant(t *testing.T) {
	otherKEK := testKEK(t)
	env, err := envelope.Encrypt(otherKEK, []byte("secret"), sessionContextAAD("sess-1"))
	if err != nil {
		t.Fatal(err)
	}
	q := &fakeSessionQuerier{row: &fakeSessionRow{env: env, etag: "v1"}}
	o := NewSessionContextOps(q, testKEK(t), "tenant-a")

	_, _, err = o.Get(t.Context(), "sess-1")
	if err == nil {
		t.Fatal("decrypting another tenant's envelope must fail")
	}
	if !IsCrossTenantSecretError(err) {
		t.Errorf("a KEK mismatch must surface as a cross-tenant error, got %v", err)
	}
}

func TestSessionContextOps_GetAADMismatchFailsDecryption(t *testing.T) {
	kek := testKEK(t)
	// Same KEK, wrong session in the AAD: a row re-pointed at another
	// session must fail to decrypt (that is what the AAD is for).
	env, err := envelope.Encrypt(kek, []byte("blob"), sessionContextAAD("other-session"))
	if err != nil {
		t.Fatal(err)
	}
	q := &fakeSessionQuerier{row: &fakeSessionRow{env: env, etag: "v1"}}
	o := NewSessionContextOps(q, kek, "tenant-a")

	if _, _, err := o.Get(t.Context(), "sess-1"); err == nil {
		t.Fatal("an AAD-mismatched envelope must not decrypt")
	}
}

func TestSessionContextOps_Delete(t *testing.T) {
	q := &fakeSessionQuerier{execTags: []pgconn.CommandTag{pgconn.NewCommandTag("DELETE 0")}}
	o := NewSessionContextOps(q, testKEK(t), "tenant-a")

	// Deleting a session with no blob is a no-op, not an error.
	if err := o.Delete(t.Context(), "sess-1"); err != nil {
		t.Fatalf("Delete of a missing blob must be a no-op, got %v", err)
	}

	boom := errors.New("pg down")
	q2 := &fakeSessionQuerier{execErrs: []error{boom}}
	o2 := NewSessionContextOps(q2, testKEK(t), "tenant-a")
	if err := o2.Delete(t.Context(), "sess-1"); !errors.Is(err, boom) {
		t.Fatalf("Exec error must propagate wrapped, got %v", err)
	}
}
