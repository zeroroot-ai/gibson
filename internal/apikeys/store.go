// Package apikeys provides API key management (Create/List/Revoke) for the
// daemon's admin RPCs. Validation (authentication) of API keys has moved to
// the ext_authz service; only the management operations remain here.
//
// The underlying storage is the same api_keys Postgres table as before.
package apikeys

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/lib/pq"
)

const (
	// KeyPrefix is the human-readable prefix for all Gibson service keys.
	KeyPrefix = "gsk"

	apiKeyRandomBytes   = 32
	apiKeyStatusActive  = "active"
	apiKeyStatusRevoked = "revoked"
)

// Record represents the persisted metadata for a Gibson service key.
// Key material is never stored in plaintext; only the SHA-256 hash is kept.
type Record struct {
	KeyID        string     `json:"key_id"`
	TenantID     string     `json:"tenant_id"`
	KeyHash      string     `json:"key_hash"`
	Name         string     `json:"name,omitempty"`
	CreatedBy    string     `json:"created_by,omitempty"`
	AllowedKinds []string   `json:"allowed_kinds"`
	AllowedNames []string   `json:"allowed_names"`
	Capabilities []string   `json:"capabilities"`
	Status       string     `json:"status"`
	MaxUses      *int       `json:"max_uses,omitempty"`
	UseCount     int        `json:"use_count"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Store manages API key records in Postgres.
// It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

// New creates a Store backed by the given *sql.DB.
// db must be non-nil and connected to a Postgres instance with the api_keys table.
func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("apikeys: db must not be nil")
	}
	return &Store{db: db}, nil
}

// CreateKey generates a new tenant-scoped API key, persists its hash, and
// returns the raw key string (only time the secret is available) plus the record.
//
// capabilities may be nil or empty for unrestricted access (normalised to "[]"
// in storage; ext_authz treats empty as "*").
func (s *Store) CreateKey(
	ctx context.Context,
	tenantID string,
	allowedKinds, allowedNames []string,
	capabilities []string,
	name, createdBy string,
) (rawKey string, record *Record, err error) {
	if tenantID == "" {
		return "", nil, fmt.Errorf("apikeys: tenantID must not be empty")
	}

	randomBytes := make([]byte, apiKeyRandomBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, fmt.Errorf("apikeys: failed to generate key material: %w", err)
	}
	randomHex := hex.EncodeToString(randomBytes)

	rawKey = fmt.Sprintf("%s_%s_%s", KeyPrefix, tenantID, randomHex)
	keyID := fmt.Sprintf("%s_%s_%s", KeyPrefix, tenantID, randomHex[:16])
	keyHash := hashKey(rawKey)

	if allowedKinds == nil {
		allowedKinds = []string{}
	}
	if allowedNames == nil {
		allowedNames = []string{}
	}
	if capabilities == nil {
		capabilities = []string{}
	}

	const query = `
INSERT INTO api_keys (
    key_id, tenant_id, key_hash, name, created_by,
    allowed_kinds, allowed_names, capabilities,
    status, use_count
) VALUES (
    $1, $2, $3, $4, $5,
    $6, $7, $8,
    'active', 0
)`
	if _, err := s.db.ExecContext(ctx, query,
		keyID, tenantID, keyHash, name, createdBy,
		pq.Array(allowedKinds), pq.Array(allowedNames), pq.Array(capabilities),
	); err != nil {
		return "", nil, fmt.Errorf("apikeys: CreateKey: %w", err)
	}

	now := time.Now().UTC()
	record = &Record{
		KeyID:        keyID,
		TenantID:     tenantID,
		KeyHash:      keyHash,
		Name:         name,
		CreatedBy:    createdBy,
		AllowedKinds: allowedKinds,
		AllowedNames: allowedNames,
		Capabilities: capabilities,
		Status:       apiKeyStatusActive,
		UseCount:     0,
		CreatedAt:    now,
	}

	slog.InfoContext(ctx, "apikeys: created API key",
		"key_id", keyID, "tenant_id", tenantID,
		"name", name, "created_by", createdBy,
	)
	return rawKey, record, nil
}

// RevokeKey marks the key record as revoked. Idempotent.
func (s *Store) RevokeKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("apikeys: keyID must not be empty")
	}
	const q = `UPDATE api_keys SET status = $2 WHERE key_id = $1 AND status != $2`
	if _, err := s.db.ExecContext(ctx, q, keyID, apiKeyStatusRevoked); err != nil {
		return fmt.Errorf("apikeys: RevokeKey %q: %w", keyID, err)
	}
	slog.InfoContext(ctx, "apikeys: revoked key", "key_id", keyID)
	return nil
}

// ListKeys returns all key records for a tenant (active and revoked).
func (s *Store) ListKeys(ctx context.Context, tenantID string) ([]Record, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("apikeys: tenantID must not be empty")
	}
	const q = `
SELECT key_id, tenant_id, key_hash, name, created_by,
       allowed_kinds, allowed_names, capabilities,
       status, max_uses, use_count, expires_at, last_used_at, created_at
FROM   api_keys
WHERE  tenant_id = $1
ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, q, tenantID)
	if err != nil {
		return nil, fmt.Errorf("apikeys: ListKeys for tenant %q: %w", tenantID, err)
	}
	defer rows.Close()

	var records []Record
	for rows.Next() {
		rec, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("apikeys: ListKeys for tenant %q: %w", tenantID, err)
		}
		records = append(records, rec)
	}
	if rows.Err() != nil {
		return nil, fmt.Errorf("apikeys: ListKeys for tenant %q: %w", tenantID, rows.Err())
	}
	if records == nil {
		records = []Record{}
	}
	return records, nil
}

// ValidateBootstrap checks that rawKey is a valid, active API key.
// Used by capabilitygrant.RegisterCapabilityGrant to validate bootstrap credentials without
// returning a full Identity (validation now lives in ext_authz for gRPC auth;
// this is a server-side check for the registration bootstrap path only).
func (s *Store) ValidateBootstrap(ctx context.Context, rawKey string) error {
	if rawKey == "" {
		return fmt.Errorf("apikeys: empty bootstrap credential")
	}
	kh := hashKey(rawKey)
	const q = `SELECT key_id FROM api_keys WHERE key_hash = $1 AND status = 'active' LIMIT 1`
	var keyID string
	if err := s.db.QueryRowContext(ctx, q, kh).Scan(&keyID); errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("apikeys: bootstrap credential not found or inactive")
	} else if err != nil {
		return fmt.Errorf("apikeys: ValidateBootstrap: %w", err)
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanRow(s scanner) (Record, error) {
	var r Record
	var allowedKinds, allowedNames, capabilities pq.StringArray
	if err := s.Scan(
		&r.KeyID, &r.TenantID, &r.KeyHash, &r.Name, &r.CreatedBy,
		&allowedKinds, &allowedNames, &capabilities,
		&r.Status, &r.MaxUses, &r.UseCount, &r.ExpiresAt, &r.LastUsedAt, &r.CreatedAt,
	); err != nil {
		return Record{}, err
	}
	r.AllowedKinds = []string(allowedKinds)
	r.AllowedNames = []string(allowedNames)
	r.Capabilities = []string(capabilities)
	return r, nil
}
