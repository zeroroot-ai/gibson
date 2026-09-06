// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zeroroot-ai/gibson/internal/infra/datapool/envelope"
)

// SessionContextOps provides the encrypted, etag-guarded session-context blob
// store in the per-tenant Postgres database (gibson#1184, table
// session_context, migration 009).
//
// One row per session_id. The tenant half of the (tenant, session_id) key is
// implicit in which database the pool connects to — there is no tenant_id
// column (check-no-tenant-id), so cross-tenant access is unrepresentable at
// this layer, exactly as in TenantSecretsOps.
//
// Each blob is wrapped under the per-tenant KEK via envelope encryption
// (AES Key Wrap DEK + AES-256-GCM), AAD-bound to
// "session_context:<session_id>" so a row cannot be re-keyed to a different
// session without decryption failing. A KEK mismatch surfaces through the
// same cross-tenant detection path TenantSecretsOps uses.
//
// Concurrency: every write is a compare-and-swap on the stored etag. An empty
// ifMatch means "create" — it succeeds only when no live blob exists. A
// non-empty ifMatch succeeds only when it names the current version. Either
// mismatch returns ErrSessionContextConflict, so a stale writer learns it
// lost the race instead of clobbering the winner.
//
// TTL: expires_at is refreshed to now()+SessionContextTTL on every
// successful Put (sliding expiry). Expired rows are treated as absent by
// every operation and reaped opportunistically on write.
type SessionContextOps struct {
	pg     SessionContextQuerier
	kek    []byte
	tenant string // used for metric labels; not a security boundary
}

// SessionContextQuerier is the narrow slice of *pgxpool.Pool these ops use.
// Production always passes the Conn's pgxpool.Pool (conn_sessioncontext.go);
// the seam exists so the CAS/TTL/reap query logic is unit-testable without a
// live Postgres.
type SessionContextQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var _ SessionContextQuerier = (*pgxpool.Pool)(nil)

// SessionContextTTL is the sliding server-side lifetime of a session-context
// blob. A session untouched for this long is treated as abandoned and its
// blob expires (the resolved design mandates a TTL; the store is a
// checkpoint home, not an archive). Refreshed on every successful Put.
const SessionContextTTL = 30 * 24 * time.Hour

// MaxSessionContextBytes is the server-enforced cap on the plaintext blob
// (~8 MB per the resolved design — larger working state belongs in the
// session Devbox, not in the trusted store).
const MaxSessionContextBytes = 8 << 20 // 8 MiB

// ErrSessionContextConflict is returned by Put when the compare-and-swap
// fails: either ifMatch was empty ("create") and a live blob already exists,
// or ifMatch named a version that is no longer current.
var ErrSessionContextConflict = errors.New("session context: etag conflict")

// ErrSessionContextTooLarge is returned by Put when the plaintext exceeds
// MaxSessionContextBytes.
var ErrSessionContextTooLarge = errors.New("session context: blob too large")

// NewSessionContextOps constructs a SessionContextOps bound to the given
// Postgres pool, per-tenant KEK, and tenant label. The caller is responsible
// for zeroing kek after use (the Conn.Release path does this automatically
// when constructed from a Conn).
func NewSessionContextOps(pool SessionContextQuerier, kek []byte, tenant string) *SessionContextOps {
	return &SessionContextOps{pg: pool, kek: kek, tenant: tenant}
}

// sessionContextAAD ties the ciphertext to the session identity so rows
// cannot be re-pointed at another session without decryption failing.
func sessionContextAAD(sessionID string) []byte {
	return []byte("session_context:" + sessionID)
}

// Put stores data as the session's context blob under compare-and-swap
// semantics (see the type comment) and returns the etag naming the version
// this write produced.
func (o *SessionContextOps) Put(ctx context.Context, sessionID string, data []byte, ifMatch string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("session context: session_id must not be empty")
	}
	if len(data) == 0 {
		return "", fmt.Errorf("session context: data must not be empty")
	}
	if len(data) > MaxSessionContextBytes {
		return "", fmt.Errorf("session context: %d bytes exceeds the %d-byte cap: %w",
			len(data), MaxSessionContextBytes, ErrSessionContextTooLarge)
	}

	env, err := envelope.Encrypt(o.kek, data, sessionContextAAD(sessionID))
	if err != nil {
		return "", fmt.Errorf("session context: encrypt %q: %w", sessionID, err)
	}
	etag := uuid.NewString()

	var tag pgconn.CommandTag
	if ifMatch == "" {
		// Create: succeeds only when no LIVE row exists. An expired row is
		// absent for CAS purposes, so the upsert overwrites it; a live row
		// makes the DO UPDATE's WHERE clause match nothing → 0 rows → conflict.
		tag, err = o.pg.Exec(ctx,
			`INSERT INTO session_context (session_id, envelope, etag, created_at, updated_at, expires_at)
			 VALUES ($1, $2, $3, now(), now(), now() + make_interval(secs => $4))
			 ON CONFLICT (session_id) DO UPDATE
			   SET envelope   = EXCLUDED.envelope,
			       etag       = EXCLUDED.etag,
			       created_at = now(),
			       updated_at = now(),
			       expires_at = EXCLUDED.expires_at
			   WHERE session_context.expires_at <= now()`,
			sessionID, env, etag, SessionContextTTL.Seconds(),
		)
	} else {
		// Update: succeeds only when ifMatch names the current live version.
		tag, err = o.pg.Exec(ctx,
			`UPDATE session_context
			    SET envelope   = $2,
			        etag       = $3,
			        updated_at = now(),
			        expires_at = now() + make_interval(secs => $4)
			  WHERE session_id = $1
			    AND etag = $5
			    AND expires_at > now()`,
			sessionID, env, etag, SessionContextTTL.Seconds(), ifMatch,
		)
	}
	if err != nil {
		return "", fmt.Errorf("session context: write %q: %w", sessionID, err)
	}
	if tag.RowsAffected() == 0 {
		return "", fmt.Errorf("session context %q: %w", sessionID, ErrSessionContextConflict)
	}

	// Opportunistic reap: writes are the store's only mutation traffic, so
	// piggyback expired-row cleanup here instead of running a background
	// sweeper per tenant database. Best-effort — a failure never fails the Put.
	_, _ = o.pg.Exec(ctx, `DELETE FROM session_context WHERE expires_at <= now()`)

	return etag, nil
}

// Get returns the session's blob and its etag. A missing or expired blob is
// NOT an error: it returns (nil, "", nil), matching the wire contract ("a
// fresh session is not an error").
func (o *SessionContextOps) Get(ctx context.Context, sessionID string) ([]byte, string, error) {
	if sessionID == "" {
		return nil, "", fmt.Errorf("session context: session_id must not be empty")
	}

	var env []byte
	var etag string
	err := o.pg.QueryRow(ctx,
		`SELECT envelope, etag FROM session_context
		  WHERE session_id = $1 AND expires_at > now()`,
		sessionID,
	).Scan(&env, &etag)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("session context: query %q: %w", sessionID, err)
	}

	plaintext, err := envelope.Decrypt(o.kek, env, sessionContextAAD(sessionID))
	if err != nil {
		if envelope.IsCrossTenantDecryptError(err) {
			// Same detection + metric co-location as TenantSecretsOps.Get:
			// the tenant label is the caller's own tenant.
			recordXTenantDecryptAttempt(o.tenant)
			return nil, "", &crossTenantSecretError{name: "session_context/" + sessionID, cause: err}
		}
		return nil, "", fmt.Errorf("session context: decrypt %q: %w", sessionID, err)
	}
	return plaintext, etag, nil
}

// Delete removes the session's blob. Deleting a session that has no blob is
// a no-op, not an error (wire contract).
func (o *SessionContextOps) Delete(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("session context: session_id must not be empty")
	}
	if _, err := o.pg.Exec(ctx,
		`DELETE FROM session_context WHERE session_id = $1`, sessionID,
	); err != nil {
		return fmt.Errorf("session context: delete %q: %w", sessionID, err)
	}
	return nil
}
