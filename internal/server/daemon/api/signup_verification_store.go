// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — signup_verification_store.go
//
// SignupVerificationStore is the daemon-side persistence for proof of mailbox
// control during self-serve signup (platform Postgres, migration 021).
//
// It is the gate the whole signup path now hangs off. Before it existed, the
// first form submission created a Zitadel human user, a billing customer and a
// provisioning queue entry for whatever address was typed — none of which the
// typist had to control. Everything expensive now sits behind Redeem.
//
// Two invariants the type exists to hold:
//
//  1. Raw tokens are never persisted. The emailed token and the post-redemption
//     session token are both stored as sha256 hashes (internal/platform/token),
//     so reading this table yields nothing replayable.
//
//  2. Every state change that must happen once is a single-statement
//     compare-and-set with a status predicate, never read-then-write. Two
//     concurrent redemptions of the same link cannot both win, because the
//     second UPDATE matches zero rows.
package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	platformtoken "github.com/zeroroot-ai/gibson/internal/platform/token"
)

// Lifecycle constants. See the migration for the reasoning behind each value.
const (
	// SignupVerificationTTL bounds the emailed link.
	SignupVerificationTTL = 24 * time.Hour

	// SignupSessionTTL bounds the post-redemption completion window. Long
	// enough to choose a password and enter a card; short enough that a stolen
	// cookie is worth almost nothing.
	SignupSessionTTL = 30 * time.Minute

	// SignupResendCooldown is the minimum gap between two sends to one address.
	SignupResendCooldown = 60 * time.Second

	// SignupMaxCompletionAttempts caps how many times a single verified session
	// may be spent attempting to provision.
	SignupMaxCompletionAttempts = 3

	// SignupRowRetention is how long a terminal row is kept for forensics
	// before the janitor deletes it.
	SignupRowRetention = 7 * 24 * time.Hour
)

// Status values for signup_verification.status.
const (
	signupStatusPending    = "pending"
	signupStatusVerified   = "verified"
	signupStatusConsumed   = "consumed"
	signupStatusExpired    = "expired"
	signupStatusSendFailed = "send_failed"
)

// The four statements that carry the flow's safety predicates.
//
// They are package-level constants rather than inline literals so a test can
// assert on their text. The predicates are the guarantee: drop `status =
// 'pending'` from the redeem statement and a link becomes infinitely reusable;
// drop the expiry from a session statement and a stale cookie provisions
// forever. Those are silent failures at runtime, so they are pinned at build
// time instead.
const (
	// redeemStatement is the single-use compare-and-set. A second redemption of
	// the same token fails the status predicate and matches zero rows.
	redeemStatement = `
		UPDATE signup_verification
		   SET status = 'verified',
		       verified_session_hash = $2,
		       verified_session_expires_at = $3,
		       updated_at = $4
		 WHERE token_hash = $1
		   AND status = 'pending'
		   AND expires_at > $4
		RETURNING id, attempt_id, email, workspace_name, tier,
		          owner_first_name, owner_last_name, expires_at,
		          stripe_customer_id, completion_attempts
	`

	// getByVerifiedSessionStatement resolves a live completion session.
	getByVerifiedSessionStatement = `
		SELECT id, attempt_id, email, workspace_name, tier,
		       owner_first_name, owner_last_name, expires_at,
		       stripe_customer_id, completion_attempts
		  FROM signup_verification
		 WHERE verified_session_hash = $1
		   AND status = 'verified'
		   AND verified_session_expires_at > $2
	`

	// claimCompletionStatement reserves one bounded completion attempt.
	claimCompletionStatement = `
		UPDATE signup_verification
		   SET completion_attempts = completion_attempts + 1, updated_at = $2
		 WHERE verified_session_hash = $1
		   AND status = 'verified'
		   AND verified_session_expires_at > $2
		   AND completion_attempts < $3
		RETURNING id, attempt_id, email, workspace_name, tier,
		          owner_first_name, owner_last_name, expires_at,
		          stripe_customer_id, completion_attempts
	`

	// markConsumedStatement spends a session for good.
	markConsumedStatement = `
		UPDATE signup_verification
		   SET status = 'consumed', consumed_at = $2, updated_at = $2
		 WHERE verified_session_hash = $1 AND status = 'verified'
	`
)

// ErrSignupVerificationNotFound is returned whenever a presented token or
// session is not redeemable — unknown, expired, already spent, or malformed.
//
// One error for every cause, deliberately. Callers map it to a single opaque
// gRPC status so the caller cannot tell an expired link from a fabricated one,
// and cannot use redemption as an oracle for which addresses have pending
// signups.
var ErrSignupVerificationNotFound = errors.New("signup verification not redeemable")

// ErrSignupStoreUnavailable is returned when no platform Postgres is wired.
// Signup fails closed on it: without the store there is nowhere to record that
// an address was proven, so proceeding would mean provisioning unverified.
var ErrSignupStoreUnavailable = errors.New("signup verification store not configured")

// SignupVerification is a row as callers see it. It never carries token
// material — only hashes live in the database and neither is returned.
type SignupVerification struct {
	ID               string
	AttemptID        string
	Email            string
	WorkspaceName    string
	Tier             string
	OwnerFirstName   string
	OwnerLastName    string
	Status           string
	ExpiresAt        time.Time
	StripeCustomerID string
	CompletionCount  int
	SendCount        int
	LastSentAt       time.Time
}

// SignupVerificationStore persists signup verifications in platform Postgres.
// A nil db yields a store whose methods return ErrSignupStoreUnavailable, so a
// daemon booted without Postgres refuses signups rather than silently skipping
// the proof step.
type SignupVerificationStore struct {
	db *sql.DB

	// now is injectable so tests can drive expiry without sleeping. Nil means
	// time.Now.
	now func() time.Time
}

// NewSignupVerificationStore builds a store over the platform Postgres handle.
func NewSignupVerificationStore(db *sql.DB) *SignupVerificationStore {
	return &SignupVerificationStore{db: db}
}

func (s *SignupVerificationStore) clock() time.Time {
	if s == nil || s.now == nil {
		return time.Now().UTC()
	}
	return s.now().UTC()
}

func (s *SignupVerificationStore) handle() (*sql.DB, error) {
	if s == nil || s.db == nil {
		return nil, ErrSignupStoreUnavailable
	}
	return s.db, nil
}

// NormalizeSignupEmail lowercases and trims an address.
//
// Normalization happens once, here, and the normalized value is what is stored
// and what the completion path reads back. If the request path and the lookup
// path normalized differently, "already has an account" checks would miss and
// the duplicate-address branch would not fire.
func NormalizeSignupEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// IssueParams are the non-secret form fields parked across the verification
// round-trip. There is deliberately no password field: a credential for an
// address nobody has proven control of has no safe place to live, so the
// password is collected after redemption instead.
type IssueParams struct {
	AttemptID      string
	Email          string
	WorkspaceName  string
	Tier           string
	OwnerFirstName string
	OwnerLastName  string
	ClientIPHash   string
}

// Issue writes a pending verification row and returns the RAW token to email.
//
// The raw token is returned, never stored. The caller's only correct use of it
// is to build the link that goes in the message body; it must not be logged,
// echoed in an RPC response, or handed to the web tier.
func (s *SignupVerificationStore) Issue(ctx context.Context, p IssueParams) (row SignupVerification, rawToken string, err error) {
	db, err := s.handle()
	if err != nil {
		return SignupVerification{}, "", err
	}
	if err := s.ensureTable(ctx); err != nil {
		return SignupVerification{}, "", err
	}

	raw, hash, err := platformtoken.Generate()
	if err != nil {
		return SignupVerification{}, "", fmt.Errorf("generate verification token: %w", err)
	}

	now := s.clock()
	id := uuid.NewString()
	expires := now.Add(SignupVerificationTTL)

	const q = `
		INSERT INTO signup_verification
			(id, attempt_id, email, workspace_name, tier, owner_first_name, owner_last_name,
			 token_hash, status, expires_at, client_ip_hash, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, $10, $11, $11)
	`
	if _, err := db.ExecContext(ctx, q,
		id, p.AttemptID, p.Email, p.WorkspaceName, p.Tier,
		p.OwnerFirstName, p.OwnerLastName, hash, expires, p.ClientIPHash, now,
	); err != nil {
		return SignupVerification{}, "", fmt.Errorf("insert signup_verification: %w", err)
	}

	return SignupVerification{
		ID:            id,
		AttemptID:     p.AttemptID,
		Email:         p.Email,
		WorkspaceName: p.WorkspaceName,
		Tier:          p.Tier,
		Status:        signupStatusPending,
		ExpiresAt:     expires,
	}, raw, nil
}

// MarkSent records a successful send (bumps send_count, stamps last_sent_at).
func (s *SignupVerificationStore) MarkSent(ctx context.Context, id string) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	const q = `
		UPDATE signup_verification
		   SET send_count = send_count + 1, last_sent_at = $2, updated_at = $2
		 WHERE id = $1
	`
	if _, err = db.ExecContext(ctx, q, id, s.clock()); err != nil {
		return fmt.Errorf("mark verification sent: %w", err)
	}
	return nil
}

// MarkSendFailed retires a row whose email could not be delivered.
//
// A row in this state is unreachable: its token was never in anyone's mailbox,
// so leaving it pending would only widen the window for a guess.
func (s *SignupVerificationStore) MarkSendFailed(ctx context.Context, id string) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	const q = `
		UPDATE signup_verification
		   SET status = 'send_failed', updated_at = $2
		 WHERE id = $1 AND status = 'pending'
	`
	if _, err = db.ExecContext(ctx, q, id, s.clock()); err != nil {
		return fmt.Errorf("mark verification send_failed: %w", err)
	}
	return nil
}

// MarkConsumedByID retires a row without it ever becoming redeemable.
//
// Used by the account-exists branch: an address that already has an account
// gets a notice with no link, so the token that row holds must never be
// accepted even though it was generated.
func (s *SignupVerificationStore) MarkConsumedByID(ctx context.Context, id string) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	now := s.clock()
	const q = `
		UPDATE signup_verification
		   SET status = 'consumed', consumed_at = $2, updated_at = $2
		 WHERE id = $1 AND status = 'pending'
	`
	if _, err = db.ExecContext(ctx, q, id, now); err != nil {
		return fmt.Errorf("mark verification consumed by id: %w", err)
	}
	return nil
}

// LastSentAt returns when an address was last sent a verification message, for
// the resend cooldown. ok=false means never.
func (s *SignupVerificationStore) LastSentAt(ctx context.Context, email string) (t time.Time, ok bool, err error) {
	db, derr := s.handle()
	if derr != nil {
		return time.Time{}, false, derr
	}
	if err := s.ensureTable(ctx); err != nil {
		return time.Time{}, false, err
	}
	const q = `
		SELECT last_sent_at FROM signup_verification
		 WHERE email = $1 AND last_sent_at IS NOT NULL
		 ORDER BY last_sent_at DESC
		 LIMIT 1
	`
	var last sql.NullTime
	switch err := db.QueryRowContext(ctx, q, email).Scan(&last); {
	case errors.Is(err, sql.ErrNoRows):
		return time.Time{}, false, nil
	case err != nil:
		return time.Time{}, false, fmt.Errorf("query last_sent_at: %w", err)
	}
	if !last.Valid {
		return time.Time{}, false, nil
	}
	return last.Time.UTC(), true, nil
}

// RedeemToken exchanges a raw emailed token for a completion session.
//
// This is the single compare-and-set the whole flow turns on:
//
//	UPDATE ... SET status='verified', verified_session_hash=...
//	 WHERE token_hash=$1 AND status='pending' AND expires_at > now
//
// Because the predicate includes the current status, a second click on the
// same link matches zero rows and fails — the token is single-use by
// construction, not by a preceding SELECT that a concurrent request could
// interleave with. An expired link fails the same way, and both failures are
// reported as the same ErrSignupVerificationNotFound so the caller learns
// nothing about which one it was.
//
// Returns the RAW session token; only its hash is stored.
func (s *SignupVerificationStore) RedeemToken(ctx context.Context, rawToken string) (row SignupVerification, rawSession string, err error) {
	db, err := s.handle()
	if err != nil {
		return SignupVerification{}, "", err
	}
	if rawToken == "" {
		return SignupVerification{}, "", ErrSignupVerificationNotFound
	}
	if err := s.ensureTable(ctx); err != nil {
		return SignupVerification{}, "", err
	}

	session, sessionHash, err := platformtoken.Generate()
	if err != nil {
		return SignupVerification{}, "", fmt.Errorf("generate session token: %w", err)
	}

	now := s.clock()
	var out SignupVerification
	err = db.QueryRowContext(ctx, redeemStatement,
		platformtoken.Hash(rawToken), sessionHash, now.Add(SignupSessionTTL), now,
	).Scan(
		&out.ID, &out.AttemptID, &out.Email, &out.WorkspaceName, &out.Tier,
		&out.OwnerFirstName, &out.OwnerLastName, &out.ExpiresAt,
		&out.StripeCustomerID, &out.CompletionCount,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return SignupVerification{}, "", ErrSignupVerificationNotFound
	case err != nil:
		return SignupVerification{}, "", fmt.Errorf("redeem signup_verification: %w", err)
	}
	out.Status = signupStatusVerified
	return out, session, nil
}

// GetByVerifiedSession resolves a live completion session to its row.
//
// It enforces both the status and the session expiry in the WHERE clause, so a
// session that outlived its window is indistinguishable from one that never
// existed.
func (s *SignupVerificationStore) GetByVerifiedSession(ctx context.Context, rawSession string) (SignupVerification, error) {
	db, err := s.handle()
	if err != nil {
		return SignupVerification{}, err
	}
	if rawSession == "" {
		return SignupVerification{}, ErrSignupVerificationNotFound
	}
	if err := s.ensureTable(ctx); err != nil {
		return SignupVerification{}, err
	}
	var out SignupVerification
	err = db.QueryRowContext(ctx, getByVerifiedSessionStatement, platformtoken.Hash(rawSession), s.clock()).Scan(
		&out.ID, &out.AttemptID, &out.Email, &out.WorkspaceName, &out.Tier,
		&out.OwnerFirstName, &out.OwnerLastName, &out.ExpiresAt,
		&out.StripeCustomerID, &out.CompletionCount,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return SignupVerification{}, ErrSignupVerificationNotFound
	case err != nil:
		return SignupVerification{}, fmt.Errorf("lookup verified session: %w", err)
	}
	out.Status = signupStatusVerified
	return out, nil
}

// AttachStripeCustomer records the billing customer created for a verified
// session. Only reachable after redemption, which is why a customer object now
// always carries an address someone proved they control.
//
// The customer id is bound to the session, both ways, in the statement itself:
//
//   - One customer per session. Once a session names a customer, only that
//     same id may be written again (a card retry re-attaching is idempotent);
//     a different id is refused. Without this, a customer that completion
//     later reads could be swapped after the fact.
//   - One session per customer. A customer id already recorded against a
//     different signup cannot be claimed here. Without this, the id — which is
//     a plain caller-supplied string, and the thing resolveSignupPlan takes as
//     evidence that a paid plan has a billing customer behind it — could name
//     someone else's.
//
// Both are predicates on the UPDATE rather than a read-then-write, so two
// concurrent attaches cannot both pass. A refusal is zero rows affected and
// surfaces as ErrSignupVerificationNotFound, which the handler answers with
// the same denial as every other dead session — no oracle for which customer
// ids exist.
func (s *SignupVerificationStore) AttachStripeCustomer(ctx context.Context, rawSession, customerID string) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	if rawSession == "" || customerID == "" {
		return ErrSignupVerificationNotFound
	}
	now := s.clock()
	const q = `
		UPDATE signup_verification
		   SET stripe_customer_id = $2, updated_at = $3
		 WHERE verified_session_hash = $1
		   AND status = 'verified'
		   AND verified_session_expires_at > $3
		   AND stripe_customer_id IN ('', $2)
		   AND NOT EXISTS (
		         SELECT 1
		           FROM signup_verification other
		          WHERE other.stripe_customer_id = $2
		            AND other.verified_session_hash IS DISTINCT FROM $1
		       )
	`
	res, err := db.ExecContext(ctx, q, platformtoken.Hash(rawSession), customerID, now)
	if err != nil {
		return fmt.Errorf("attach stripe customer: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrSignupVerificationNotFound
	}
	return nil
}

// ClaimCompletion reserves one completion attempt against a verified session
// and returns the row.
//
// The increment is part of the same statement as the lookup and is bounded by
// SignupMaxCompletionAttempts, so a caller that keeps retrying a failing
// completion runs out rather than looping forever. A session past its cap is
// reported as not-redeemable, like every other dead end.
func (s *SignupVerificationStore) ClaimCompletion(ctx context.Context, rawSession string) (SignupVerification, error) {
	db, err := s.handle()
	if err != nil {
		return SignupVerification{}, err
	}
	if rawSession == "" {
		return SignupVerification{}, ErrSignupVerificationNotFound
	}
	if err := s.ensureTable(ctx); err != nil {
		return SignupVerification{}, err
	}
	now := s.clock()
	var out SignupVerification
	err = db.QueryRowContext(ctx, claimCompletionStatement, platformtoken.Hash(rawSession), now, SignupMaxCompletionAttempts).Scan(
		&out.ID, &out.AttemptID, &out.Email, &out.WorkspaceName, &out.Tier,
		&out.OwnerFirstName, &out.OwnerLastName, &out.ExpiresAt,
		&out.StripeCustomerID, &out.CompletionCount,
	)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return SignupVerification{}, ErrSignupVerificationNotFound
	case err != nil:
		return SignupVerification{}, fmt.Errorf("claim completion: %w", err)
	}
	out.Status = signupStatusVerified
	return out, nil
}

// MarkConsumed spends a verified session for good.
//
// Called once provisioning has been enqueued. After this, the cookie in the
// browser is inert: a copy of it cannot be replayed into a second tenant.
func (s *SignupVerificationStore) MarkConsumed(ctx context.Context, rawSession string) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	now := s.clock()
	res, err := db.ExecContext(ctx, markConsumedStatement, platformtoken.Hash(rawSession), now)
	if err != nil {
		return fmt.Errorf("consume signup_verification: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrSignupVerificationNotFound
	}
	return nil
}

// PurgeExpired ages out unredeemed rows and deletes terminal ones past
// retention. Returns how many rows each step touched.
//
// Nothing else accumulates before verification — that is the point of the
// ordering — so this one sweep is the whole cleanup story for abandoned
// attempts.
func (s *SignupVerificationStore) PurgeExpired(ctx context.Context) (expired, deleted int64, err error) {
	db, err := s.handle()
	if err != nil {
		return 0, 0, err
	}
	if err := s.ensureTable(ctx); err != nil {
		return 0, 0, err
	}
	now := s.clock()

	const expireQ = `
		UPDATE signup_verification
		   SET status = 'expired', updated_at = $1
		 WHERE status IN ('pending', 'verified') AND expires_at <= $1
	`
	res, err := db.ExecContext(ctx, expireQ, now)
	if err != nil {
		return 0, 0, fmt.Errorf("expire signup_verification: %w", err)
	}
	expired, _ = res.RowsAffected()

	const deleteQ = `
		DELETE FROM signup_verification
		 WHERE status IN ('consumed', 'expired', 'send_failed')
		   AND updated_at <= $1
	`
	res, err = db.ExecContext(ctx, deleteQ, now.Add(-SignupRowRetention))
	if err != nil {
		return expired, 0, fmt.Errorf("delete signup_verification: %w", err)
	}
	deleted, _ = res.RowsAffected()
	return expired, deleted, nil
}

// ensureTable creates signup_verification if it is absent. Mirrors
// ensurePendingTenantProvisioningTable: migration 021 is authoritative, this
// keeps a freshly-pointed database working before migrations run.
func (s *SignupVerificationStore) ensureTable(ctx context.Context) error {
	db, err := s.handle()
	if err != nil {
		return err
	}
	const create = `
		CREATE TABLE IF NOT EXISTS signup_verification (
			id                          UUID PRIMARY KEY,
			attempt_id                  UUID NOT NULL,
			email                       TEXT NOT NULL,
			workspace_name              TEXT NOT NULL,
			tier                        TEXT NOT NULL,
			owner_first_name            TEXT NOT NULL DEFAULT '',
			owner_last_name             TEXT NOT NULL DEFAULT '',
			token_hash                  TEXT NOT NULL UNIQUE,
			status                      TEXT NOT NULL DEFAULT 'pending'
				CONSTRAINT signup_verification_status_check
				CHECK (status IN ('pending', 'verified', 'consumed', 'expired', 'send_failed')),
			expires_at                  TIMESTAMPTZ NOT NULL,
			verified_session_hash       TEXT UNIQUE,
			verified_session_expires_at TIMESTAMPTZ,
			stripe_customer_id          TEXT NOT NULL DEFAULT '',
			completion_attempts         INT NOT NULL DEFAULT 0,
			send_count                  INT NOT NULL DEFAULT 0,
			last_sent_at                TIMESTAMPTZ,
			client_ip_hash              TEXT NOT NULL DEFAULT '',
			created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			consumed_at                 TIMESTAMPTZ
		)
	`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("create signup_verification: %w", err)
	}
	return nil
}
