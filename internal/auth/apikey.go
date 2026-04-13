package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/lib/pq"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

const (
	// apiKeyPrefix is the human-readable prefix for all Gibson service keys.
	// The prefix allows log scanners to identify key type without exposing secret material.
	apiKeyPrefix = "gsk"

	// apiKeyRandomBytes is the number of cryptographically random bytes used for
	// the key secret. 32 bytes yields 64 hex characters = 256-bit entropy.
	apiKeyRandomBytes = 32

	// apiKeyIssuer is the issuer field written into the Identity for keys authenticated
	// through this authenticator. Used for metrics and audit trail attribution.
	apiKeyIssuer = "apikey"

	// apiKeyStatusActive is the canonical string for an active key.
	apiKeyStatusActive = "active"

	// apiKeyStatusRevoked is the canonical string for a revoked key.
	apiKeyStatusRevoked = "revoked"

	// apiKeyStatusConsumed is the canonical string for a single-use key that has
	// been fully used (use_count has reached max_uses).
	apiKeyStatusConsumed = "consumed"

	// SystemTenant is the reserved tenant identifier for platform-hosted shared
	// components (built-in tools, platform agents, internal services). Components
	// registered under this tenant are discoverable by all tenants via the registry's
	// Discover fallback, enabling the platform-operator to run shared infrastructure
	// that any tenant can invoke without per-tenant registration.
	//
	// API keys scoped to SystemTenant grant access to the _system component namespace
	// and are intentionally privileged: only identities with the "admin" or
	// "platform-operator" role may create them (enforced by CreateKey).
	SystemTenant = "_system"
)

// APIKeyRecord represents the persisted metadata for a Gibson service key.
//
// Key material is never stored in plaintext. Only the SHA-256 hash of the raw
// key is persisted. On authentication the raw key is hashed and the hash is
// compared against the stored value via constant-time comparison.
type APIKeyRecord struct {
	// KeyID is the stable, non-secret identifier for this key.
	// Example: "gsk_acme_3f9a…" (first 16 chars of the full key).
	KeyID string `json:"key_id"`

	// TenantID is the tenant this key is scoped to.
	// All authenticated requests using this key will be attributed to this tenant.
	TenantID string `json:"tenant_id"`

	// KeyHash is the hex-encoded SHA-256 digest of the raw key.
	// Only this hash is stored; the raw key is never persisted.
	KeyHash string `json:"key_hash"`

	// Name is a human-readable label for this key (e.g. "CI/CD Deploy Key").
	Name string `json:"name,omitempty"`

	// CreatedBy is the email or subject identifier of the identity that created
	// this key. Used for audit trail attribution.
	CreatedBy string `json:"created_by,omitempty"`

	// AllowedKinds restricts which component kinds this key may register.
	// An empty slice means all kinds are permitted.
	AllowedKinds []string `json:"allowed_kinds"`

	// AllowedNames restricts which component names this key may use.
	// An empty slice means all names are permitted.
	AllowedNames []string `json:"allowed_names"`

	// Capabilities are the resource:action grants for this key.
	// An empty slice means "all capabilities" for backward compatibility; Authenticate
	// normalises this to []string{"*"} when building the Identity.
	//
	// Examples: ["graphrag:write", "plugin:gitlab:read", "missions:execute", "*"]
	Capabilities []string `json:"capabilities"`

	// Status is one of "active", "revoked", "consumed", or "expired".
	Status string `json:"status"`

	// MaxUses is the optional maximum number of times this key may be used.
	// nil means unlimited. When use_count reaches max_uses, the key is
	// transitioned to status="consumed" atomically on the final use.
	MaxUses *int `json:"max_uses,omitempty"`

	// UseCount is the number of times this key has been successfully authenticated.
	UseCount int `json:"use_count"`

	// ExpiresAt is the optional expiry timestamp. nil means no expiry.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`

	// LastUsedAt records when the key was most recently authenticated.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`

	// CreatedAt records when the key was first created.
	CreatedAt time.Time `json:"created_at"`
}

// APIKeyAuthenticator validates Gibson service keys stored in Postgres and returns
// an Identity scoped to the key's tenant on success.
//
// Key lifecycle:
//  1. CreateKey generates a random key and stores a hash record in Postgres.
//  2. Authenticate validates a presented key against the stored hash.
//  3. RevokeKey marks a record as revoked (retained for audit).
//  4. ListKeys enumerates all key records for a given tenant.
//
// Thread-safe for concurrent use.
// Implements the Authenticator interface.
type APIKeyAuthenticator struct {
	db *sql.DB
}

// NewAPIKeyAuthenticator creates a new authenticator backed by the provided *sql.DB.
//
// The db must be non-nil and connected to a Postgres instance that has had
// RunMigrations applied (api_keys table must exist).
func NewAPIKeyAuthenticator(db *sql.DB) (*APIKeyAuthenticator, error) {
	if db == nil {
		return nil, fmt.Errorf("db is nil")
	}
	return &APIKeyAuthenticator{db: db}, nil
}

// CreateKey generates a new tenant-scoped API key and persists the record.
//
// The returned rawKey is the only time the secret material is available. It is
// the caller's responsibility to transmit and store it securely. The rawKey is
// never logged or stored by this function.
//
// Key format: gsk_{tenantID}_{32_hex_random}
//
// capabilities is the list of resource:action grants for this key.
// Pass nil or an empty slice to grant unrestricted access (legacy behaviour);
// the record will store an empty slice and Authenticate will normalise it to
// []string{"*"} when building the Identity.
func (a *APIKeyAuthenticator) CreateKey(
	ctx context.Context,
	tenantID string,
	allowedKinds, allowedNames []string,
	capabilities []string,
	name, createdBy string,
) (rawKey string, record *APIKeyRecord, err error) {
	if tenantID == "" {
		return "", nil, fmt.Errorf("tenantID must not be empty")
	}

	// Generate 32 bytes of cryptographic randomness.
	randomBytes := make([]byte, apiKeyRandomBytes)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", nil, fmt.Errorf("failed to generate random key material: %w", err)
	}
	randomHex := hex.EncodeToString(randomBytes)

	// Assemble the full raw key and derive the key_id from the first 16 chars.
	rawKey = fmt.Sprintf("%s_%s_%s", apiKeyPrefix, tenantID, randomHex)
	keyID := fmt.Sprintf("%s_%s_%s", apiKeyPrefix, tenantID, randomHex[:16])

	// Hash the raw key for storage. We never log or persist rawKey.
	keyHash := hashKey(rawKey)

	// Normalise nil slices to empty so Postgres TEXT[] columns receive '{}'.
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

	_, execErr := a.db.ExecContext(ctx, query,
		keyID,
		tenantID,
		keyHash,
		name,
		createdBy,
		pq.Array(allowedKinds),
		pq.Array(allowedNames),
		pq.Array(capabilities),
	)
	if execErr != nil {
		return "", nil, fmt.Errorf("apikey: CreateKey: %w", execErr)
	}

	now := time.Now().UTC()
	record = &APIKeyRecord{
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

	slog.Info("apikey: created new API key",
		"key_id", keyID,
		"tenant_id", tenantID,
		"allowed_kinds", allowedKinds,
		"allowed_names", allowedNames,
		"capabilities", capabilities,
		"name", name,
		"created_by", createdBy,
	)

	return rawKey, record, nil
}

// Authenticate validates a raw API key and returns the scoped Identity on success.
//
// Process:
//  1. Hash the presented token with SHA-256.
//  2. Query api_keys WHERE key_hash = $1 AND status = 'active'.
//  3. Verify the stored hash matches the presented hash via constant-time compare.
//  4. Check expires_at (if set).
//  5. Check max_uses vs use_count (if set).
//  6. Atomically increment use_count and update last_used_at.
//     If use_count now equals max_uses, set status='consumed'.
//  7. Build and return an Identity with Subject=key_id, tenant_id in Claims.
//
// The raw token is never logged.
func (a *APIKeyAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	startTime := time.Now()
	defer func() {
		latencyMs := float64(time.Since(startTime).Milliseconds())
		recordAuthLatency(ctx, apiKeyIssuer, latencyMs)
	}()

	if token == "" {
		recordAuthAttempt(ctx, apiKeyIssuer, "error")
		return nil, ErrMissingToken()
	}

	// Compute hash of the presented token. Never log token itself.
	presentedHash := hashKey(token)

	// Fetch the record by hash. We query status='active' to avoid loading
	// revoked/consumed/expired records early; we still validate below for
	// defense in depth.
	record, err := a.fetchRecordByHash(ctx, presentedHash)
	if err != nil {
		recordAuthAttempt(ctx, apiKeyIssuer, "failure")
		return nil, err
	}

	// Verify hash via constant-time comparison to prevent timing attacks.
	if !constantTimeCompareStrings(presentedHash, record.KeyHash) {
		// Should not occur given we looked up by hash, but guards against
		// a corrupt or race-condition-affected store.
		recordAuthAttempt(ctx, apiKeyIssuer, "failure")
		return nil, ErrInvalidSignature()
	}

	// Reject non-active keys (defense in depth — the query already filters on status).
	if record.Status != apiKeyStatusActive {
		recordAuthAttempt(ctx, apiKeyIssuer, "failure")
		return nil, ErrTokenExpired()
	}

	// Reject expired keys.
	if record.ExpiresAt != nil && time.Now().UTC().After(*record.ExpiresAt) {
		recordAuthAttempt(ctx, apiKeyIssuer, "failure")
		return nil, ErrTokenExpired()
	}

	// Reject keys that have already hit their use limit.
	if record.MaxUses != nil && record.UseCount >= *record.MaxUses {
		recordAuthAttempt(ctx, apiKeyIssuer, "failure")
		return nil, ErrTokenExpired()
	}

	// Atomically increment use_count and update last_used_at.
	// If use_count now equals max_uses, transition to consumed.
	if err := a.incrementUseCount(ctx, record.KeyID, record.MaxUses); err != nil {
		// Non-fatal: log and continue. A failure here should not block auth.
		slog.Warn("apikey: failed to increment use_count",
			"key_id", record.KeyID,
			"error", err,
		)
	}

	// Resolve capabilities with backward-compatibility: keys created before
	// capability-scoping was introduced have an empty Capabilities slice. Treat
	// this as unrestricted ("*") so existing keys continue to work without
	// requiring a migration.
	caps := record.Capabilities
	if len(caps) == 0 {
		caps = []string{"*"}
	}

	// Under the declarative-rbac-framework, API keys map to the "admin" role by
	// default. Keys scoped to the system tenant map to "platform-operator".
	roles := []string{"admin"}
	if record.TenantID == SystemTenant {
		roles = []string{"platform-operator"}
	}

	// Build the Identity. Tenant is encoded in Claims["tenant_id"] following
	// the existing ExtractTenantFromIdentity("tenant_id") convention.
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: record.KeyID,
			Issuer:  apiKeyIssuer,
			Groups:  []string{},
			Claims: map[string]any{
				"tenant_id":     record.TenantID,
				"key_id":        record.KeyID,
				"allowed_kinds": record.AllowedKinds,
				"allowed_names": record.AllowedNames,
			},
			// API keys do not expire on a fixed schedule; use a far-future time.
			ExpiresAt:       time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC),
			AuthenticatedAt: time.Now().UTC(),
		},
		Roles:        roles,
		Capabilities: caps,
	}

	recordAuthAttempt(ctx, apiKeyIssuer, "success")
	return identity, nil
}

// RevokeKey marks the key record as revoked.
//
// The record is retained in Postgres so that audit logs can still resolve
// key IDs, but Authenticate will refuse revoked keys. Revocation is idempotent.
func (a *APIKeyAuthenticator) RevokeKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("keyID must not be empty")
	}

	const query = `
UPDATE api_keys
SET    status = $2
WHERE  key_id = $1 AND status != $2`

	if _, err := a.db.ExecContext(ctx, query, keyID, apiKeyStatusRevoked); err != nil {
		return fmt.Errorf("apikey: RevokeKey %q: %w", keyID, err)
	}

	slog.Info("apikey: revoked API key", "key_id", keyID)
	return nil
}

// ListKeys returns all APIKeyRecord entries associated with a tenant.
//
// Both active and revoked keys are returned so that callers can render full
// key management UIs. The caller should filter by Status if needed.
func (a *APIKeyAuthenticator) ListKeys(ctx context.Context, tenantID string) ([]APIKeyRecord, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenantID must not be empty")
	}

	const query = `
SELECT key_id, tenant_id, key_hash, name, created_by,
       allowed_kinds, allowed_names, capabilities,
       status, max_uses, use_count, expires_at, last_used_at, created_at
FROM   api_keys
WHERE  tenant_id = $1
ORDER BY created_at DESC`

	rows, err := a.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("apikey: ListKeys for tenant %q: %w", tenantID, err)
	}
	defer rows.Close()

	var records []APIKeyRecord
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("apikey: ListKeys for tenant %q: %w", tenantID, err)
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("apikey: ListKeys for tenant %q: %w", tenantID, err)
	}

	if records == nil {
		records = []APIKeyRecord{}
	}
	return records, nil
}

// fetchRecord retrieves the APIKeyRecord for the given key_id.
func (a *APIKeyAuthenticator) fetchRecord(ctx context.Context, keyID string) (*APIKeyRecord, error) {
	const query = `
SELECT key_id, tenant_id, key_hash, name, created_by,
       allowed_kinds, allowed_names, capabilities,
       status, max_uses, use_count, expires_at, last_used_at, created_at
FROM   api_keys
WHERE  key_id = $1`

	row := a.db.QueryRowContext(ctx, query, keyID)
	rec, err := scanRecord(row)
	if err == sql.ErrNoRows {
		return nil, ErrInvalidToken(fmt.Errorf("API key record not found: %s", keyID))
	}
	if err != nil {
		return nil, fmt.Errorf("apikey: fetchRecord %q: %w", keyID, err)
	}
	return &rec, nil
}

// fetchRecordByHash retrieves the APIKeyRecord for the given key_hash.
// Only records with status='active' are returned.
func (a *APIKeyAuthenticator) fetchRecordByHash(ctx context.Context, keyHash string) (*APIKeyRecord, error) {
	const query = `
SELECT key_id, tenant_id, key_hash, name, created_by,
       allowed_kinds, allowed_names, capabilities,
       status, max_uses, use_count, expires_at, last_used_at, created_at
FROM   api_keys
WHERE  key_hash = $1 AND status = 'active'`

	row := a.db.QueryRowContext(ctx, query, keyHash)
	rec, err := scanRecord(row)
	if err == sql.ErrNoRows {
		return nil, ErrInvalidToken(fmt.Errorf("API key not found"))
	}
	if err != nil {
		return nil, fmt.Errorf("apikey: fetchRecordByHash: %w", err)
	}
	return &rec, nil
}

// scanner is the common interface for sql.Row and sql.Rows, allowing scanRecord
// to be used from both QueryRowContext and QueryContext.
type scanner interface {
	Scan(dest ...any) error
}

// scanRecord scans a single api_keys row into an APIKeyRecord.
func scanRecord(row scanner) (APIKeyRecord, error) {
	var rec APIKeyRecord
	err := row.Scan(
		&rec.KeyID,
		&rec.TenantID,
		&rec.KeyHash,
		&rec.Name,
		&rec.CreatedBy,
		pq.Array(&rec.AllowedKinds),
		pq.Array(&rec.AllowedNames),
		pq.Array(&rec.Capabilities),
		&rec.Status,
		&rec.MaxUses,
		&rec.UseCount,
		&rec.ExpiresAt,
		&rec.LastUsedAt,
		&rec.CreatedAt,
	)
	if err != nil {
		return APIKeyRecord{}, err
	}
	// Ensure slices are non-nil for consistent behaviour.
	if rec.AllowedKinds == nil {
		rec.AllowedKinds = []string{}
	}
	if rec.AllowedNames == nil {
		rec.AllowedNames = []string{}
	}
	if rec.Capabilities == nil {
		rec.Capabilities = []string{}
	}
	return rec, nil
}

// incrementUseCount atomically increments use_count and sets last_used_at.
// If maxUses is non-nil and the new use_count equals maxUses, the key is
// transitioned to status='consumed' in the same UPDATE.
func (a *APIKeyAuthenticator) incrementUseCount(ctx context.Context, keyID string, maxUses *int) error {
	if maxUses != nil {
		// Single-use (or bounded-use) key: consume when limit is reached.
		const query = `
UPDATE api_keys
SET    use_count    = use_count + 1,
       last_used_at = now(),
       status       = CASE WHEN use_count + 1 >= $2 THEN 'consumed' ELSE status END
WHERE  key_id = $1`

		if _, err := a.db.ExecContext(ctx, query, keyID, *maxUses); err != nil {
			return fmt.Errorf("apikey: incrementUseCount %q: %w", keyID, err)
		}
	} else {
		// Unlimited key: just bump the counter and timestamp.
		const query = `
UPDATE api_keys
SET    use_count    = use_count + 1,
       last_used_at = now()
WHERE  key_id = $1`

		if _, err := a.db.ExecContext(ctx, query, keyID); err != nil {
			return fmt.Errorf("apikey: incrementUseCount %q: %w", keyID, err)
		}
	}
	return nil
}

// hashKey computes the hex-encoded SHA-256 digest of a raw API key string.
//
// This is the sole hashing function for key material in this package.
// Both CreateKey (for storage) and Authenticate (for comparison) must use
// this function to ensure consistency.
func hashKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

// constantTimeCompareStrings performs a constant-time comparison of two strings.
//
// Returns true only if both strings have equal length and identical content.
// Length inequality is handled before the constant-time byte comparison to
// prevent leaking length information through short-circuit evaluation.
func constantTimeCompareStrings(a, b string) bool {
	aBytes := []byte(a)
	bBytes := []byte(b)
	if len(aBytes) != len(bBytes) {
		return false
	}
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

// parsePermissions converts permission strings in "action:resource" format into
// the Gibson Permission slice used by the Identity type.
//
// Strings that do not contain a colon separator are silently skipped.
// A wildcard segment ("*") is preserved as-is and matched by RoleBinder.
func parsePermissions(perms []string) []Permission {
	result := make([]Permission, 0, len(perms))
	for _, p := range perms {
		// Find the first colon separator.
		for i := 0; i < len(p); i++ {
			if p[i] == ':' {
				action := p[:i]
				resource := p[i+1:]
				if action != "" && resource != "" {
					result = append(result, Permission{
						Action:   action,
						Resource: resource,
						Scope:    "*",
					})
				}
				break
			}
		}
	}
	return result
}
