// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// signup_verification_store_test.go — pins the SQL that makes signup
// verification single-use and expiring.
//
// The handler tests run against an in-memory model of this store. That model is
// only trustworthy if the real statements carry the predicates it assumes, so
// these tests assert the statements themselves: redemption must be a
// compare-and-set that includes the current status and the expiry, session
// lookups must include the session expiry, and a zero-row result must surface
// as ErrSignupVerificationNotFound rather than as success.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	platformtoken "github.com/zeroroot-ai/gibson/internal/platform/token"
)

// newMockStore builds a store over a sqlmock connection with a frozen clock.
func newMockStore(t *testing.T) (*SignupVerificationStore, sqlmock.Sqlmock, time.Time) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	s := NewSignupVerificationStore(db)
	s.now = func() time.Time { return now }
	return s, mock, now
}

// closedDB returns a *sql.DB whose connection is already closed, so any
// statement fails. Used to drive error paths.
func closedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	mock.ExpectClose()
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return db
}

// TestRedeemToken_IsACompareAndSet is the core of the single-use guarantee.
//
// Redemption must be ONE statement whose WHERE clause includes the current
// status and the expiry. A read-then-write would let two concurrent clicks on
// the same link both observe 'pending' and both succeed; a predicate without
// the expiry would let a stale link work forever.
func TestRedeemToken_IsACompareAndSet(t *testing.T) {
	s, mock, now := newMockStore(t)
	raw := "deadbeef"

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
		WillReturnResult(sqlmock.NewResult(0, 0))

	// The statement must be an UPDATE ... WHERE token_hash = ... AND
	// status = 'pending' AND expires_at > ... — all three, in one statement.
	mock.ExpectQuery(`UPDATE signup_verification`).
		WithArgs(platformtoken.Hash(raw), sqlmock.AnyArg(), sqlmock.AnyArg(), now).
		WillReturnRows(sqlmock.NewRows([]string{
			"id", "attempt_id", "email", "workspace_name", "tier",
			"owner_first_name", "owner_last_name", "expires_at",
			"stripe_customer_id", "completion_attempts",
		}).AddRow("row-1", "attempt-1", "owner@example.com", "Acme", "team",
			"Ada", "Lovelace", now.Add(time.Hour), "", 0))

	row, session, err := s.RedeemToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("RedeemToken: %v", err)
	}
	if session == "" {
		t.Errorf("expected a session token back")
	}
	if row.Email != "owner@example.com" {
		t.Errorf("Email = %q", row.Email)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}

	// The statement's text carries the predicates the in-memory model assumes.
	assertStatementContains(t, redeemStatement,
		`status = 'pending'`,
		`expires_at > `,
		`token_hash = `,
	)
}

// TestRedeemToken_ZeroRowsIsNotRedeemable proves the failure mapping: a
// predicate that matched nothing — reused link, expired link, unknown token —
// becomes one opaque error, never a success and never a distinguishable cause.
func TestRedeemToken_ZeroRowsIsNotRedeemable(t *testing.T) {
	s, mock, _ := newMockStore(t)

	mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`UPDATE signup_verification`).WillReturnError(sql.ErrNoRows)

	if _, _, err := s.RedeemToken(context.Background(), "whatever"); !errors.Is(err, ErrSignupVerificationNotFound) {
		t.Fatalf("error = %v, want ErrSignupVerificationNotFound", err)
	}
}

// TestRedeemToken_EmptyTokenShortCircuits — an absent token is the same answer
// as a wrong one, and costs no database round trip.
func TestRedeemToken_EmptyTokenShortCircuits(t *testing.T) {
	s, mock, _ := newMockStore(t)
	if _, _, err := s.RedeemToken(context.Background(), ""); !errors.Is(err, ErrSignupVerificationNotFound) {
		t.Fatalf("error = %v, want ErrSignupVerificationNotFound", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an empty token reached the database: %v", err)
	}
}

// TestSessionLookupsCarryTheirExpiry proves the completion-session statements
// bound themselves on verified_session_expires_at, so a session that outlived
// its window is indistinguishable from one that never existed.
func TestSessionLookupsCarryTheirExpiry(t *testing.T) {
	assertStatementContains(t, getByVerifiedSessionStatement,
		`verified_session_hash = `,
		`status = 'verified'`,
		`verified_session_expires_at > `,
	)
	assertStatementContains(t, claimCompletionStatement,
		`verified_session_hash = `,
		`status = 'verified'`,
		`verified_session_expires_at > `,
		`completion_attempts < `,
	)
	assertStatementContains(t, markConsumedStatement,
		`verified_session_hash = `,
		`status = 'verified'`,
	)
}

// TestStoreFailsClosedWithoutADatabase — no platform Postgres means no way to
// record that an address was proven, so every method refuses.
func TestStoreFailsClosedWithoutADatabase(t *testing.T) {
	s := NewSignupVerificationStore(nil)
	ctx := context.Background()

	if _, _, err := s.Issue(ctx, IssueParams{Email: "a@b.c"}); !errors.Is(err, ErrSignupStoreUnavailable) {
		t.Errorf("Issue: %v", err)
	}
	if _, _, err := s.RedeemToken(ctx, "tok"); !errors.Is(err, ErrSignupStoreUnavailable) {
		t.Errorf("RedeemToken: %v", err)
	}
	if _, err := s.ClaimCompletion(ctx, "sess"); !errors.Is(err, ErrSignupStoreUnavailable) {
		t.Errorf("ClaimCompletion: %v", err)
	}
	if _, err := s.GetByVerifiedSession(ctx, "sess"); !errors.Is(err, ErrSignupStoreUnavailable) {
		t.Errorf("GetByVerifiedSession: %v", err)
	}
}

// TestIssuePersistsOnlyTheHash proves the raw token never reaches the database.
// A stored raw token would turn any read of this table into a set of usable
// signup links.
func TestIssuePersistsOnlyTheHash(t *testing.T) {
	s, mock, now := newMockStore(t)

	var persisted []driverArgs
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO signup_verification").
		WithArgs(
			sqlmock.AnyArg(), // id
			"11111111-2222-4333-8444-555555555555",
			"owner@example.com",
			"Acme", "team", "Ada", "Lovelace",
			argCapture{&persisted}, // token_hash
			now.Add(SignupVerificationTTL),
			"iphash",
			now,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, raw, err := s.Issue(context.Background(), IssueParams{
		AttemptID: "11111111-2222-4333-8444-555555555555", Email: "owner@example.com",
		WorkspaceName: "Acme", Tier: "team",
		OwnerFirstName: "Ada", OwnerLastName: "Lovelace", ClientIPHash: "iphash",
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if raw == "" {
		t.Fatalf("Issue returned no raw token")
	}
	if len(persisted) != 1 {
		t.Fatalf("token_hash argument not captured")
	}
	got := persisted[0].value
	if got == raw {
		t.Fatalf("the RAW token was persisted; only its hash may be stored")
	}
	if got != platformtoken.Hash(raw) {
		t.Errorf("persisted value is not the token hash: %q", got)
	}
}

// TestMarkSent_BumpsSendCountAndStampsLastSent records a successful send so
// the resend cooldown has a timestamp to read.
func TestMarkSent_BumpsSendCountAndStampsLastSent(t *testing.T) {
	s, mock, now := newMockStore(t)
	mock.ExpectExec("UPDATE signup_verification").
		WithArgs("row-1", now).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := s.MarkSent(context.Background(), "row-1"); err != nil {
		t.Fatalf("MarkSent: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

// TestMarkSent_WrapsTheUnderlyingError — a caller that logs this error must
// see the database failure, not just "something went wrong".
func TestMarkSent_WrapsTheUnderlyingError(t *testing.T) {
	s, mock, _ := newMockStore(t)
	dbErr := errors.New("connection reset")
	mock.ExpectExec("UPDATE signup_verification").WillReturnError(dbErr)

	err := s.MarkSent(context.Background(), "row-1")
	if !errors.Is(err, dbErr) {
		t.Errorf("MarkSent error = %v, want it to wrap %v", err, dbErr)
	}
}

// TestMarkSendFailed_RetiresAPendingRow retires a row whose email could not
// be delivered, so its token can never be redeemed.
func TestMarkSendFailed_RetiresAPendingRow(t *testing.T) {
	s, mock, now := newMockStore(t)
	mock.ExpectExec("UPDATE signup_verification").
		WithArgs("row-1", now).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := s.MarkSendFailed(context.Background(), "row-1"); err != nil {
		t.Fatalf("MarkSendFailed: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestMarkSendFailed_WrapsTheUnderlyingError(t *testing.T) {
	s, mock, _ := newMockStore(t)
	dbErr := errors.New("connection reset")
	mock.ExpectExec("UPDATE signup_verification").WillReturnError(dbErr)

	if err := s.MarkSendFailed(context.Background(), "row-1"); !errors.Is(err, dbErr) {
		t.Errorf("MarkSendFailed error = %v, want it to wrap %v", err, dbErr)
	}
}

// TestMarkConsumedByID_RetiresACollisionRow — the account-exists branch's
// cleanup: a token that was generated but never emailed must never redeem.
func TestMarkConsumedByID_RetiresACollisionRow(t *testing.T) {
	s, mock, now := newMockStore(t)
	mock.ExpectExec("UPDATE signup_verification").
		WithArgs("row-1", now).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := s.MarkConsumedByID(context.Background(), "row-1"); err != nil {
		t.Fatalf("MarkConsumedByID: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet expectations: %v", err)
	}
}

func TestMarkConsumedByID_WrapsTheUnderlyingError(t *testing.T) {
	s, mock, _ := newMockStore(t)
	dbErr := errors.New("connection reset")
	mock.ExpectExec("UPDATE signup_verification").WillReturnError(dbErr)

	if err := s.MarkConsumedByID(context.Background(), "row-1"); !errors.Is(err, dbErr) {
		t.Errorf("MarkConsumedByID error = %v, want it to wrap %v", err, dbErr)
	}
}

// TestLastSentAt covers the three shapes the resend cooldown reads: an address
// that has been sent to before, one that never has, and a broken database.
func TestLastSentAt(t *testing.T) {
	t.Run("previously sent", func(t *testing.T) {
		s, mock, now := newMockStore(t)
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`SELECT last_sent_at FROM signup_verification`).
			WithArgs("owner@example.com").
			WillReturnRows(sqlmock.NewRows([]string{"last_sent_at"}).AddRow(now))

		got, ok, err := s.LastSentAt(context.Background(), "owner@example.com")
		if err != nil {
			t.Fatalf("LastSentAt: %v", err)
		}
		if !ok {
			t.Fatal("ok = false, want true for a previously-sent address")
		}
		if !got.Equal(now) {
			t.Errorf("LastSentAt = %v, want %v", got, now)
		}
	})

	t.Run("never sent", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`SELECT last_sent_at FROM signup_verification`).
			WillReturnError(sql.ErrNoRows)

		_, ok, err := s.LastSentAt(context.Background(), "nobody@example.com")
		if err != nil {
			t.Fatalf("LastSentAt: %v", err)
		}
		if ok {
			t.Error("ok = true, want false for an address that was never sent to")
		}
	})

	t.Run("database unavailable", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		dbErr := errors.New("connection reset")
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`SELECT last_sent_at FROM signup_verification`).
			WillReturnError(dbErr)

		_, _, err := s.LastSentAt(context.Background(), "owner@example.com")
		if !errors.Is(err, dbErr) {
			t.Errorf("LastSentAt error = %v, want it to wrap %v", err, dbErr)
		}
	})
}

// TestGetByVerifiedSession covers the completion-status read: a live session,
// one that does not match (expired, spent, or unknown — all one answer), and a
// broken database.
func TestGetByVerifiedSession(t *testing.T) {
	t.Run("live session", func(t *testing.T) {
		s, mock, now := newMockStore(t)
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`SELECT id, attempt_id, email`).
			WithArgs(platformtoken.Hash("sess-raw"), now).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "attempt_id", "email", "workspace_name", "tier",
				"owner_first_name", "owner_last_name", "expires_at",
				"stripe_customer_id", "completion_attempts",
			}).AddRow("row-1", "attempt-1", "owner@example.com", "Acme", "team",
				"Ada", "Lovelace", now.Add(time.Hour), "cus_123", 1))

		row, err := s.GetByVerifiedSession(context.Background(), "sess-raw")
		if err != nil {
			t.Fatalf("GetByVerifiedSession: %v", err)
		}
		if row.Email != "owner@example.com" || row.StripeCustomerID != "cus_123" {
			t.Errorf("row = %+v", row)
		}
		if row.Status != signupStatusVerified {
			t.Errorf("Status = %q, want %q", row.Status, signupStatusVerified)
		}
	})

	t.Run("no match is not redeemable", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`SELECT id, attempt_id, email`).WillReturnError(sql.ErrNoRows)

		if _, err := s.GetByVerifiedSession(context.Background(), "sess-raw"); !errors.Is(err, ErrSignupVerificationNotFound) {
			t.Errorf("error = %v, want ErrSignupVerificationNotFound", err)
		}
	})

	t.Run("empty session short-circuits", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		if _, err := s.GetByVerifiedSession(context.Background(), ""); !errors.Is(err, ErrSignupVerificationNotFound) {
			t.Errorf("error = %v, want ErrSignupVerificationNotFound", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("an empty session reached the database: %v", err)
		}
	})

	t.Run("database unavailable", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		dbErr := errors.New("connection reset")
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`SELECT id, attempt_id, email`).WillReturnError(dbErr)

		if _, err := s.GetByVerifiedSession(context.Background(), "sess-raw"); !errors.Is(err, dbErr) {
			t.Errorf("error = %v, want it to wrap %v", err, dbErr)
		}
	})
}

// TestAttachStripeCustomer covers recording the billing customer against a
// live session: success, a session that does not match, missing arguments,
// and a broken database.
func TestAttachStripeCustomer(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, mock, now := newMockStore(t)
		mock.ExpectExec("UPDATE signup_verification").
			WithArgs(platformtoken.Hash("sess-raw"), "cus_123", now).
			WillReturnResult(sqlmock.NewResult(0, 1))

		if err := s.AttachStripeCustomer(context.Background(), "sess-raw", "cus_123"); err != nil {
			t.Fatalf("AttachStripeCustomer: %v", err)
		}
	})

	t.Run("no matching row is not redeemable", func(t *testing.T) {
		s, mock, now := newMockStore(t)
		mock.ExpectExec("UPDATE signup_verification").
			WithArgs(platformtoken.Hash("sess-raw"), "cus_123", now).
			WillReturnResult(sqlmock.NewResult(0, 0))

		if err := s.AttachStripeCustomer(context.Background(), "sess-raw", "cus_123"); !errors.Is(err, ErrSignupVerificationNotFound) {
			t.Errorf("error = %v, want ErrSignupVerificationNotFound", err)
		}
	})

	t.Run("missing arguments short-circuit", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		if err := s.AttachStripeCustomer(context.Background(), "", "cus_123"); !errors.Is(err, ErrSignupVerificationNotFound) {
			t.Errorf("empty session: error = %v, want ErrSignupVerificationNotFound", err)
		}
		if err := s.AttachStripeCustomer(context.Background(), "sess-raw", ""); !errors.Is(err, ErrSignupVerificationNotFound) {
			t.Errorf("empty customer id: error = %v, want ErrSignupVerificationNotFound", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("missing arguments reached the database: %v", err)
		}
	})

	t.Run("database unavailable", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		dbErr := errors.New("connection reset")
		mock.ExpectExec("UPDATE signup_verification").WillReturnError(dbErr)

		if err := s.AttachStripeCustomer(context.Background(), "sess-raw", "cus_123"); !errors.Is(err, dbErr) {
			t.Errorf("error = %v, want it to wrap %v", err, dbErr)
		}
	})
}

// TestClaimCompletion covers reserving one bounded completion attempt: a
// session under its cap, one that does not match (spent, expired, capped, or
// unknown — all one answer), an empty session, and a broken database.
func TestClaimCompletion(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, mock, now := newMockStore(t)
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`UPDATE signup_verification`).
			WithArgs(platformtoken.Hash("sess-raw"), now, SignupMaxCompletionAttempts).
			WillReturnRows(sqlmock.NewRows([]string{
				"id", "attempt_id", "email", "workspace_name", "tier",
				"owner_first_name", "owner_last_name", "expires_at",
				"stripe_customer_id", "completion_attempts",
			}).AddRow("row-1", "attempt-1", "owner@example.com", "Acme", "team",
				"Ada", "Lovelace", now.Add(time.Hour), "", 1))

		row, err := s.ClaimCompletion(context.Background(), "sess-raw")
		if err != nil {
			t.Fatalf("ClaimCompletion: %v", err)
		}
		if row.CompletionCount != 1 {
			t.Errorf("CompletionCount = %d, want 1", row.CompletionCount)
		}
	})

	t.Run("no match is not redeemable", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`UPDATE signup_verification`).WillReturnError(sql.ErrNoRows)

		if _, err := s.ClaimCompletion(context.Background(), "sess-raw"); !errors.Is(err, ErrSignupVerificationNotFound) {
			t.Errorf("error = %v, want ErrSignupVerificationNotFound", err)
		}
	})

	t.Run("empty session short-circuits", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		if _, err := s.ClaimCompletion(context.Background(), ""); !errors.Is(err, ErrSignupVerificationNotFound) {
			t.Errorf("error = %v, want ErrSignupVerificationNotFound", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("an empty session reached the database: %v", err)
		}
	})

	t.Run("database unavailable", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		dbErr := errors.New("connection reset")
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectQuery(`UPDATE signup_verification`).WillReturnError(dbErr)

		if _, err := s.ClaimCompletion(context.Background(), "sess-raw"); !errors.Is(err, dbErr) {
			t.Errorf("error = %v, want it to wrap %v", err, dbErr)
		}
	})
}

// TestMarkConsumed covers spending a verified session for good: success, a
// session that does not match, and a broken database.
func TestMarkConsumed(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, mock, now := newMockStore(t)
		mock.ExpectExec("UPDATE signup_verification").
			WithArgs(platformtoken.Hash("sess-raw"), now).
			WillReturnResult(sqlmock.NewResult(0, 1))

		if err := s.MarkConsumed(context.Background(), "sess-raw"); err != nil {
			t.Fatalf("MarkConsumed: %v", err)
		}
	})

	t.Run("no matching row is not redeemable", func(t *testing.T) {
		s, mock, now := newMockStore(t)
		mock.ExpectExec("UPDATE signup_verification").
			WithArgs(platformtoken.Hash("sess-raw"), now).
			WillReturnResult(sqlmock.NewResult(0, 0))

		if err := s.MarkConsumed(context.Background(), "sess-raw"); !errors.Is(err, ErrSignupVerificationNotFound) {
			t.Errorf("error = %v, want ErrSignupVerificationNotFound", err)
		}
	})

	t.Run("database unavailable", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		dbErr := errors.New("connection reset")
		mock.ExpectExec("UPDATE signup_verification").WillReturnError(dbErr)

		if err := s.MarkConsumed(context.Background(), "sess-raw"); !errors.Is(err, dbErr) {
			t.Errorf("error = %v, want it to wrap %v", err, dbErr)
		}
	})
}

// TestPurgeExpired covers the janitor's one sweep: rows aged out, rows
// deleted past retention, and a failure at each of the two steps.
func TestPurgeExpired(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		s, mock, now := newMockStore(t)
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`UPDATE signup_verification\s+SET status = 'expired'`).
			WithArgs(now).
			WillReturnResult(sqlmock.NewResult(0, 3))
		mock.ExpectExec(`DELETE FROM signup_verification`).
			WithArgs(now.Add(-SignupRowRetention)).
			WillReturnResult(sqlmock.NewResult(0, 2))

		expired, deleted, err := s.PurgeExpired(context.Background())
		if err != nil {
			t.Fatalf("PurgeExpired: %v", err)
		}
		if expired != 3 || deleted != 2 {
			t.Errorf("PurgeExpired = (%d, %d), want (3, 2)", expired, deleted)
		}
	})

	t.Run("expire step fails", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		dbErr := errors.New("connection reset")
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`UPDATE signup_verification\s+SET status = 'expired'`).WillReturnError(dbErr)

		_, _, err := s.PurgeExpired(context.Background())
		if !errors.Is(err, dbErr) {
			t.Errorf("error = %v, want it to wrap %v", err, dbErr)
		}
	})

	t.Run("delete step fails but still reports what was expired", func(t *testing.T) {
		s, mock, _ := newMockStore(t)
		dbErr := errors.New("connection reset")
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec(`UPDATE signup_verification\s+SET status = 'expired'`).
			WillReturnResult(sqlmock.NewResult(0, 3))
		mock.ExpectExec(`DELETE FROM signup_verification`).WillReturnError(dbErr)

		expired, _, err := s.PurgeExpired(context.Background())
		if !errors.Is(err, dbErr) {
			t.Errorf("error = %v, want it to wrap %v", err, dbErr)
		}
		if expired != 3 {
			t.Errorf("expired = %d, want 3 even though the delete step failed", expired)
		}
	})
}

// TestEnsureTable_WrapsTheUnderlyingError — a freshly-pointed database that
// cannot even create the table must report a real error, not succeed
// silently into a store with no table.
func TestEnsureTable_WrapsTheUnderlyingError(t *testing.T) {
	s, mock, _ := newMockStore(t)
	dbErr := errors.New("permission denied")
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS signup_verification").WillReturnError(dbErr)

	if _, _, err := s.LastSentAt(context.Background(), "owner@example.com"); !errors.Is(err, dbErr) {
		t.Errorf("error = %v, want it to wrap %v", err, dbErr)
	}
}

// TestClock_FallsBackToRealTimeWhenUnset — a store built with
// NewSignupVerificationStore (the production constructor) has no injected
// clock and must still tell time.
func TestClock_FallsBackToRealTimeWhenUnset(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer func() { _ = db.Close() }()

	s := NewSignupVerificationStore(db)
	before := time.Now().UTC()
	got := s.clock()
	after := time.Now().UTC()
	if got.Before(before) || got.After(after) {
		t.Errorf("clock() = %v, want between %v and %v", got, before, after)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// driverArgs records a captured statement argument.
type driverArgs struct{ value string }

// argCapture is a sqlmock argument matcher that accepts any string and records
// it, so a test can assert on what was actually bound.
type argCapture struct{ into *[]driverArgs }

func (a argCapture) Match(v driver.Value) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	*a.into = append(*a.into, driverArgs{value: s})
	return true
}

// assertStatementContains fails when a statement is missing a predicate the
// rest of the design depends on.
func assertStatementContains(t *testing.T, stmt string, needles ...string) {
	t.Helper()
	normalized := regexp.MustCompile(`\s+`).ReplaceAllString(stmt, " ")
	for _, n := range needles {
		want := regexp.MustCompile(`\s+`).ReplaceAllString(n, " ")
		if !containsSubstring(normalized, want) {
			t.Errorf("statement is missing %q:\n%s", want, normalized)
		}
	}
}

// TestAttachStripeCustomer_BindsTheCustomerToTheSession pins the two
// predicates that turn "record whatever the caller sent" into an ownership
// rule. The handler tests run against an in-memory model of this store, so the
// model is only trustworthy while the real statement carries them.
//
// The expectation is a regex over the statement itself: drop either predicate
// and the query no longer matches, so this fails rather than silently passing
// against a weaker UPDATE.
func TestAttachStripeCustomer_BindsTheCustomerToTheSession(t *testing.T) {
	s, mock, now := newMockStore(t)
	mock.ExpectExec(`(?s)UPDATE signup_verification.*`+
		// One customer per session: only an unset column, or the same id
		// again, may be written.
		`stripe_customer_id IN \('', \$2\).*`+
		// One session per customer: an id already recorded against a
		// different signup cannot be claimed.
		`NOT EXISTS.*other\.stripe_customer_id = \$2.*`+
		`other\.verified_session_hash IS DISTINCT FROM \$1`).
		WithArgs(platformtoken.Hash("sess-raw"), "cus_123", now).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if err := s.AttachStripeCustomer(context.Background(), "sess-raw", "cus_123"); err != nil {
		t.Fatalf("AttachStripeCustomer: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("statement did not carry the binding predicates: %v", err)
	}
}

// TestAttachStripeCustomer_RefusalIsIndistinguishable — a refused binding must
// look exactly like a dead session. Any other answer tells a caller which
// customer ids are already in use.
func TestAttachStripeCustomer_RefusalIsIndistinguishable(t *testing.T) {
	s, mock, now := newMockStore(t)
	mock.ExpectExec("UPDATE signup_verification").
		WithArgs(platformtoken.Hash("sess-raw"), "cus_taken", now).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := s.AttachStripeCustomer(context.Background(), "sess-raw", "cus_taken")
	if !errors.Is(err, ErrSignupVerificationNotFound) {
		t.Fatalf("error = %v, want ErrSignupVerificationNotFound", err)
	}
}
