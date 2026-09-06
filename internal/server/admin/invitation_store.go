// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — invitation_store.go
//
// InvitationStore is the daemon-side persistence for the member-invitation
// lifecycle (gibson#626). It is a deep module over the platform-Postgres
// `tenant_invitations` table (migration 007): the raw token is never stored —
// only its sha256 hash. MembershipService.InviteMember issues a pending
// invitation; ListMembers surfaces pending invitations as "invited" members;
// AcceptInvitation (a later slice) redeems by token hash; Resend/Cancel/expiry
// mutate status.
package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	platformtoken "github.com/zeroroot-ai/gibson/internal/platform/token"
)

// InvitationTTL is how long a pending invitation remains acceptable.
const InvitationTTL = 7 * 24 * time.Hour

// PendingInvitation is a pending (not-yet-accepted) invitation as surfaced to
// callers (e.g. ListMembers). It carries no token material.
type PendingInvitation struct {
	ID        string
	Email     string
	Role      string
	InvitedBy string
	ExpiresAt time.Time
}

// InvitationStore persists invitations in platform Postgres.
type InvitationStore struct {
	db *sql.DB
}

// NewInvitationStore builds a store over the platform Postgres handle. A nil db
// yields a store whose methods are safe no-ops/errors, so callers can treat
// invitations as unconfigured in dev clusters without a DB.
func NewInvitationStore(db *sql.DB) *InvitationStore {
	return &InvitationStore{db: db}
}

// GenerateInvitationToken returns a random URL-safe token and its sha256 hash.
// Only the hash is persisted; the raw token rides the emailed accept link.
//
// Delegates to internal/platform/token, the shared emailed-link token
// primitive. Behaviour is unchanged (32 random bytes, hex, sha256 hash) — the
// signup verification token uses the same primitive, so there is one shape to
// audit rather than two copies that can drift.
func GenerateInvitationToken() (token, hash string, err error) {
	token, hash, err = platformtoken.Generate()
	if err != nil {
		return "", "", fmt.Errorf("generate invitation token: %w", err)
	}
	return token, hash, nil
}

// HashInvitationToken returns the sha256 hash of a raw token (for lookup on
// accept).
func HashInvitationToken(token string) string {
	return platformtoken.Hash(token)
}

// ensureTable lazily creates tenant_invitations (mirrors ensureTenantQuotasTable
// for stamped legacy DBs; migration 007 is authoritative).
func (s *InvitationStore) ensureTable(ctx context.Context) error {
	const q = `
		CREATE TABLE IF NOT EXISTS tenant_invitations (
			id            TEXT PRIMARY KEY,
			tenant_id     TEXT NOT NULL,
			email         TEXT NOT NULL,
			role          TEXT NOT NULL DEFAULT 'member',
			token_hash    TEXT NOT NULL,
			status        TEXT NOT NULL DEFAULT 'pending',
			invited_by    TEXT NOT NULL DEFAULT '',
			expires_at    TIMESTAMPTZ NOT NULL,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`
	if _, err := s.db.ExecContext(ctx, q); err != nil {
		return fmt.Errorf("ensure tenant_invitations: %w", err)
	}
	const idx = `CREATE UNIQUE INDEX IF NOT EXISTS tenant_invitations_tenant_email_idx ON tenant_invitations (tenant_id, email)`
	if _, err := s.db.ExecContext(ctx, idx); err != nil {
		return fmt.Errorf("ensure tenant_invitations index: %w", err)
	}
	return nil
}

// Issue creates or refreshes a pending invitation for (tenant, email),
// resetting the token hash, role, TTL, and status to pending. Idempotent on the
// (tenant, email) unique key. Returns the invitation id + expiry.
func (s *InvitationStore) Issue(ctx context.Context, tenantID, email, role, tokenHash, invitedBy string) (id string, expiresAt time.Time, err error) {
	if s == nil || s.db == nil {
		return "", time.Time{}, errors.New("invitation store not configured")
	}
	if err := s.ensureTable(ctx); err != nil {
		return "", time.Time{}, err
	}
	id = uuid.NewString()
	expiresAt = time.Now().Add(InvitationTTL).UTC()
	const q = `
		INSERT INTO tenant_invitations (id, tenant_id, email, role, token_hash, status, invited_by, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, NOW(), NOW())
		ON CONFLICT (tenant_id, email) DO UPDATE SET
			role = EXCLUDED.role,
			token_hash = EXCLUDED.token_hash,
			status = 'pending',
			invited_by = EXCLUDED.invited_by,
			expires_at = EXCLUDED.expires_at,
			updated_at = NOW()
		RETURNING id, expires_at`
	if err := s.db.QueryRowContext(ctx, q, id, tenantID, email, role, tokenHash, invitedBy, expiresAt).
		Scan(&id, &expiresAt); err != nil {
		return "", time.Time{}, fmt.Errorf("issue invitation: %w", err)
	}
	return id, expiresAt, nil
}

// InvitationRecord is a full invitation row (used by accept/resend/cancel).
type InvitationRecord struct {
	ID        string
	TenantID  string
	Email     string
	Role      string
	Status    string
	ExpiresAt time.Time
}

// ErrInvitationNotFound is returned when no invitation matches a lookup.
var ErrInvitationNotFound = errors.New("invitation not found")

// GetByTokenHash returns the invitation whose token hash matches, or
// ErrInvitationNotFound. It does NOT filter on status/expiry — the caller
// decides how to treat a cancelled/expired/accepted invitation.
//
// This is the one invitation lookup with no tenant predicate, and that is
// deliberate: AcceptInvitation is unauthenticated, so the caller cannot name a
// tenant. The 256-bit token is the sole capability and its sha256 is the lookup
// key — the row it matches is what tells the caller which tenant it joined.
// Every other method takes a tenantID, and none of them may be relaxed to this
// shape.
func (s *InvitationStore) GetByTokenHash(ctx context.Context, tokenHash string) (*InvitationRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("invitation store not configured")
	}
	if err := s.ensureTable(ctx); err != nil {
		return nil, err
	}
	const q = `
		SELECT id, tenant_id, email, role, status, expires_at
		FROM tenant_invitations WHERE token_hash = $1`
	var r InvitationRecord
	switch err := s.db.QueryRowContext(ctx, q, tokenHash).
		Scan(&r.ID, &r.TenantID, &r.Email, &r.Role, &r.Status, &r.ExpiresAt); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrInvitationNotFound
	case err != nil:
		return nil, fmt.Errorf("get invitation by token: %w", err)
	default:
		return &r, nil
	}
}

// SetStatus transitions an invitation's status (e.g. accepted, cancelled)
// within a single tenant.
//
// tenantID is a mandatory predicate, not a convenience. tenant_invitations is a
// shared table with a UUID primary key and no row-level security, so an id-only
// UPDATE authorises on possession of an identifier: a caller in tenant A who
// learns an invitation id belonging to tenant B could cancel B's invitation.
// Matching on (id, tenant_id) makes a cross-tenant id affect zero rows, which
// surfaces as ErrInvitationNotFound — the same answer a caller gets for an id
// that does not exist, so the predicate leaks nothing about other tenants.
func (s *InvitationStore) SetStatus(ctx context.Context, tenantID, id, status string) error {
	if s == nil || s.db == nil {
		return errors.New("invitation store not configured")
	}
	if tenantID == "" {
		return errors.New("set invitation status: tenant required")
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE tenant_invitations SET status = $2, updated_at = NOW() WHERE id = $1 AND tenant_id = $3`,
		id, status, tenantID)
	if err != nil {
		return fmt.Errorf("set invitation status: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrInvitationNotFound
	}
	return nil
}

// FindPendingByEmail returns the pending invitation for (tenant, email), or
// ErrInvitationNotFound. Used by resend/cancel when addressed by email.
func (s *InvitationStore) FindPendingByEmail(ctx context.Context, tenantID, email string) (*InvitationRecord, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("invitation store not configured")
	}
	if err := s.ensureTable(ctx); err != nil {
		return nil, err
	}
	const q = `
		SELECT id, tenant_id, email, role, status, expires_at
		FROM tenant_invitations
		WHERE tenant_id = $1 AND email = $2 AND status = 'pending'`
	var r InvitationRecord
	switch err := s.db.QueryRowContext(ctx, q, tenantID, email).
		Scan(&r.ID, &r.TenantID, &r.Email, &r.Role, &r.Status, &r.ExpiresAt); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrInvitationNotFound
	case err != nil:
		return nil, fmt.Errorf("find pending invitation: %w", err)
	default:
		return &r, nil
	}
}

// ListPending returns the non-expired pending invitations for a tenant.
func (s *InvitationStore) ListPending(ctx context.Context, tenantID string) ([]PendingInvitation, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if err := s.ensureTable(ctx); err != nil {
		return nil, err
	}
	const q = `
		SELECT id, email, role, invited_by, expires_at
		FROM tenant_invitations
		WHERE tenant_id = $1 AND status = 'pending' AND expires_at > NOW()
		ORDER BY created_at`
	rows, err := s.db.QueryContext(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list pending invitations: %w", err)
	}
	defer rows.Close() //nolint:errcheck
	var out []PendingInvitation
	for rows.Next() {
		var inv PendingInvitation
		if err := rows.Scan(&inv.ID, &inv.Email, &inv.Role, &inv.InvitedBy, &inv.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan invitation: %w", err)
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}
