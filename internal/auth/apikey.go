package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/redis/go-redis/v9"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

const (
	// apiKeyPrefix is the human-readable prefix for all Gibson service keys.
	// The prefix allows log scanners to identify key type without exposing secret material.
	apiKeyPrefix = "gsk"

	// apiKeyRandomBytes is the number of cryptographically random bytes used for
	// the key secret. 32 bytes yields 64 hex characters = 256-bit entropy.
	apiKeyRandomBytes = 32

	// apiKeyHashKeyPrefix is the Redis key prefix used for the hash → key_id lookup.
	// Format: apikey_hash:{sha256_hex}
	apiKeyHashKeyPrefix = "apikey_hash:"

	// apiKeyRecordKeyPrefix is the Redis key prefix used for the full record.
	// Format: apikey:{key_id}
	apiKeyRecordKeyPrefix = "apikey:"

	// apiKeyTenantSetKeyPrefix is the Redis key prefix for the SET of key_ids per tenant.
	// Format: apikeys:tenant:{tenant_id}
	apiKeyTenantSetKeyPrefix = "apikeys:tenant:"

	// apiKeyIssuer is the issuer field written into the Identity for keys authenticated
	// through this authenticator. Used for metrics and audit trail attribution.
	apiKeyIssuer = "apikey"

	// apiKeyStatusActive is the canonical string for an active key.
	apiKeyStatusActive = "active"

	// apiKeyStatusRevoked is the canonical string for a revoked key.
	apiKeyStatusRevoked = "revoked"

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
//
// The record is stored as a JSON blob at apikey:{key_id} in Redis.
// A secondary reverse-lookup entry at apikey_hash:{sha256_hex} stores the key_id,
// allowing O(1) lookup during authentication without scanning all records.
// A tenant-scoped SET at apikeys:tenant:{tenant_id} supports ListKeys.
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

	// AllowedKinds restricts which component kinds this key may register.
	// An empty slice means all kinds are permitted.
	AllowedKinds []string `json:"allowed_kinds"`

	// AllowedNames restricts which component names this key may use.
	// An empty slice means all names are permitted.
	AllowedNames []string `json:"allowed_names"`

	// Permissions are the string-encoded permission grants for this key.
	// Format follows the Gibson permission model: "action:resource".
	// Example: ["execute:mission", "read:finding"]
	Permissions []string `json:"permissions"`

	// CreatedAt records when the key was first created.
	CreatedAt time.Time `json:"created_at"`

	// LastUsedAt records when the key was most recently authenticated.
	// Updated asynchronously on each successful Authenticate call.
	LastUsedAt time.Time `json:"last_used_at"`

	// Capabilities are the Casbin resource:action grants for this key.
	// Each entry is a capability string parsed by ParseCapability to derive
	// the (resource, action) tuple stored as a Casbin policy rule.
	//
	// An empty slice means "all capabilities" for backward compatibility with
	// keys created before capability-scoping was introduced; Authenticate will
	// normalise this to []string{"*"} when building the Identity.
	//
	// Examples: ["graphrag:write", "plugin:gitlab:read", "missions:execute", "*"]
	Capabilities []string `json:"capabilities"`

	// Status is either "active" or "revoked".
	// Revoked keys are retained in Redis for audit purposes but will never
	// authenticate successfully.
	Status string `json:"status"`
}

// APIKeyAuthenticator validates Gibson service keys stored in Redis and returns
// an Identity scoped to the key's tenant on success.
//
// Key lifecycle:
//  1. CreateKey generates a random key and stores a hash record in Redis.
//  2. Authenticate validates a presented key against the stored hash.
//  3. RevokeKey marks a record as revoked (retained for audit).
//  4. ListKeys enumerates all key records for a given tenant.
//
// Thread-safe for concurrent use.
// Implements the Authenticator interface.
type APIKeyAuthenticator struct {
	client   *redis.Client
	enforcer *casbin.Enforcer
}

// NewAPIKeyAuthenticator creates a new authenticator backed by the provided Redis client.
//
// The client must be connected and ready; no dial is performed here.
// To enable Casbin policy synchronisation, call WithEnforcer after construction.
func NewAPIKeyAuthenticator(client *redis.Client) (*APIKeyAuthenticator, error) {
	if client == nil {
		return nil, fmt.Errorf("redis client is nil")
	}
	return &APIKeyAuthenticator{client: client}, nil
}

// WithEnforcer wires a Casbin enforcer into the authenticator so that
// CreateKey and RevokeKey automatically sync policies to the Casbin store.
//
// This method returns the receiver to allow call chaining:
//
//	auth, _ := NewAPIKeyAuthenticator(redisClient)
//	auth.WithEnforcer(enforcer)
//
// Calling this with a nil enforcer is a no-op; the authenticator continues to
// operate without Casbin synchronisation.
func (a *APIKeyAuthenticator) WithEnforcer(enforcer *casbin.Enforcer) *APIKeyAuthenticator {
	a.enforcer = enforcer
	return a
}

// CreateKey generates a new tenant-scoped API key and persists the record.
//
// The returned rawKey is the only time the secret material is available. It is
// the caller's responsibility to transmit and store it securely. The rawKey is
// never logged or stored by this function.
//
// Key format: gsk_{tenantID}_{32_hex_random}
//
// capabilities is the list of Casbin resource:action grants for this key.
// Pass nil or an empty slice to grant unrestricted access (legacy behaviour);
// the record will store an empty slice and Authenticate will normalise it to
// []string{"*"} when building the Identity.
//
// If the authenticator has an enforcer configured (via WithEnforcer), Casbin
// policies are added for each capability immediately after the Redis writes.
//
// Redis writes (non-atomic — partial failure is possible; the secondary
// hash-lookup entry is written last so a missing reverse-lookup entry causes
// an Authenticate miss rather than a corrupt authentication):
//  1. SET apikey:{key_id}          → JSON record
//  2. SADD apikeys:tenant:{tenant_id} key_id
//  3. SET apikey_hash:{sha256_hex}  → key_id
func (a *APIKeyAuthenticator) CreateKey(
	ctx context.Context,
	tenantID string,
	allowedKinds, allowedNames []string,
	capabilities []string,
) (rawKey string, record *APIKeyRecord, err error) {
	if tenantID == "" {
		return "", nil, fmt.Errorf("tenantID must not be empty")
	}

	// Keys scoped to the system tenant are privileged: they grant access to
	// platform-hosted shared components visible to all tenants. Only identities
	// carrying the "admin" or "platform-operator" role may create them. This
	// prevents unprivileged tenants from minting keys that can masquerade as or
	// interact with system-level infrastructure.
	if tenantID == SystemTenant {
		caller, ok := GibsonIdentityFromContext(ctx)
		if !ok || (!caller.HasRole("admin") && !caller.HasRole("platform-operator")) {
			return "", nil, fmt.Errorf(
				"creating a key for tenant %q requires the admin or platform-operator role",
				SystemTenant,
			)
		}
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

	now := time.Now().UTC()
	record = &APIKeyRecord{
		KeyID:        keyID,
		TenantID:     tenantID,
		KeyHash:      keyHash,
		AllowedKinds: allowedKinds,
		AllowedNames: allowedNames,
		Permissions:  []string{},
		Capabilities: capabilities,
		CreatedAt:    now,
		LastUsedAt:   now,
		Status:       apiKeyStatusActive,
	}
	if record.AllowedKinds == nil {
		record.AllowedKinds = []string{}
	}
	if record.AllowedNames == nil {
		record.AllowedNames = []string{}
	}
	if record.Capabilities == nil {
		record.Capabilities = []string{}
	}

	data, err := json.Marshal(record)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal API key record: %w", err)
	}

	// 1. Persist the record document.
	recordKey := apiKeyRecordKeyPrefix + keyID
	if err := a.client.Set(ctx, recordKey, data, 0).Err(); err != nil {
		return "", nil, fmt.Errorf("failed to store API key record: %w", err)
	}

	// 2. Add the key_id to the tenant's set for ListKeys.
	tenantSetKey := apiKeyTenantSetKeyPrefix + tenantID
	if err := a.client.SAdd(ctx, tenantSetKey, keyID).Err(); err != nil {
		// Non-fatal: the key record is stored; list operations will miss this
		// entry until re-added, but the key itself remains functional.
		slog.Warn("apikey: failed to add key_id to tenant set",
			"key_id", keyID,
			"tenant_id", tenantID,
			"error", err,
		)
	}

	// 3. Write the reverse hash → key_id lookup last. If this write fails the
	//    key cannot be authenticated, which is safer than an inconsistent state
	//    where the hash exists but the record does not.
	hashLookupKey := apiKeyHashKeyPrefix + keyHash
	if err := a.client.Set(ctx, hashLookupKey, keyID, 0).Err(); err != nil {
		return "", nil, fmt.Errorf("failed to store API key hash lookup: %w", err)
	}

	// Sync Casbin policies for the new key's capabilities if an enforcer is
	// configured. This is best-effort: a Casbin failure does not roll back the
	// Redis writes because the key must be usable even when the policy store is
	// temporarily unavailable. The policies can be recovered via SyncAllPolicies.
	if a.enforcer != nil && len(record.Capabilities) > 0 {
		if casbinErr := AddPoliciesForKey(a.enforcer, keyID, tenantID, record.Capabilities); casbinErr != nil {
			slog.Warn("apikey: failed to sync Casbin policies for new key",
				"key_id", keyID,
				"tenant_id", tenantID,
				"error", casbinErr,
			)
		}
	}

	slog.Info("apikey: created new API key",
		"key_id", keyID,
		"tenant_id", tenantID,
		"allowed_kinds", allowedKinds,
		"allowed_names", allowedNames,
		"capabilities", record.Capabilities,
	)

	return rawKey, record, nil
}

// Authenticate validates a raw API key and returns the scoped Identity on success.
//
// Process:
//  1. Hash the presented token with SHA-256.
//  2. Look up the key_id via the hash reverse-lookup key.
//  3. Fetch the full record by key_id.
//  4. Verify the stored hash matches the presented hash via constant-time compare.
//  5. Check that the record status is "active".
//  6. Fire-and-forget goroutine to update LastUsedAt.
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

	// Look up key_id by hash.
	hashLookupKey := apiKeyHashKeyPrefix + presentedHash
	keyID, err := a.client.Get(ctx, hashLookupKey).Result()
	if err != nil {
		if err == redis.Nil {
			recordAuthAttempt(ctx, apiKeyIssuer, "failure")
			return nil, ErrInvalidToken(fmt.Errorf("API key not found"))
		}
		recordAuthAttempt(ctx, apiKeyIssuer, "error")
		return nil, fmt.Errorf("failed to lookup API key hash: %w", err)
	}

	// Fetch the full record.
	record, err := a.fetchRecord(ctx, keyID)
	if err != nil {
		recordAuthAttempt(ctx, apiKeyIssuer, "error")
		return nil, err
	}

	// Verify hash via constant-time comparison to prevent timing attacks.
	if !constantTimeCompareStrings(presentedHash, record.KeyHash) {
		// This should not occur given we looked up by hash, but guards against
		// a corrupt or race-condition-affected store.
		recordAuthAttempt(ctx, apiKeyIssuer, "failure")
		return nil, ErrInvalidSignature()
	}

	// Reject revoked keys.
	if record.Status != apiKeyStatusActive {
		recordAuthAttempt(ctx, apiKeyIssuer, "failure")
		return nil, ErrTokenExpired()
	}

	// Update LastUsedAt asynchronously. We do not wait for this; a failure here
	// should not block the authentication path.
	go func() {
		updateCtx := context.Background()
		if updateErr := a.updateLastUsed(updateCtx, keyID); updateErr != nil {
			slog.Warn("apikey: failed to update last_used_at",
				"key_id", keyID,
				"error", updateErr,
			)
		}
	}()

	// Build permissions from the record's permission strings.
	permissions := parsePermissions(record.Permissions)

	// Resolve capabilities with backward-compatibility: keys created before
	// capability-scoping was introduced have an empty Capabilities slice. Treat
	// this as unrestricted ("*") so existing keys continue to work without
	// requiring a migration.
	caps := record.Capabilities
	if len(caps) == 0 {
		caps = []string{"*"}
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
		Roles:        []string{},
		Permissions:  permissions,
		Capabilities: caps,
	}

	recordAuthAttempt(ctx, apiKeyIssuer, "success")
	return identity, nil
}

// RevokeKey marks the key record as revoked.
//
// The record and hash lookup are retained in Redis so that audit logs can still
// resolve key IDs, but Authenticate will refuse revoked keys. The key_id is NOT
// removed from the tenant set so that ListKeys continues to surface revoked keys
// with their status visible.
func (a *APIKeyAuthenticator) RevokeKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("keyID must not be empty")
	}

	record, err := a.fetchRecord(ctx, keyID)
	if err != nil {
		return err
	}

	if record.Status == apiKeyStatusRevoked {
		// Idempotent: already revoked.
		return nil
	}

	record.Status = apiKeyStatusRevoked

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal updated API key record: %w", err)
	}

	recordKey := apiKeyRecordKeyPrefix + keyID
	if err := a.client.Set(ctx, recordKey, data, 0).Err(); err != nil {
		return fmt.Errorf("failed to update API key record for revocation: %w", err)
	}

	// Remove all Casbin policies for the revoked key so it can no longer be
	// used for authorization decisions even if somehow re-activated in Redis.
	// Best-effort: a Casbin failure is logged but does not cause RevokeKey to
	// return an error, since the Redis record is already marked revoked.
	if a.enforcer != nil {
		if casbinErr := RemovePoliciesForKey(a.enforcer, keyID); casbinErr != nil {
			slog.Warn("apikey: failed to remove Casbin policies on revocation",
				"key_id", keyID,
				"tenant_id", record.TenantID,
				"error", casbinErr,
			)
		}
	}

	slog.Info("apikey: revoked API key",
		"key_id", keyID,
		"tenant_id", record.TenantID,
	)

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

	tenantSetKey := apiKeyTenantSetKeyPrefix + tenantID
	keyIDs, err := a.client.SMembers(ctx, tenantSetKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list API key IDs for tenant %q: %w", tenantID, err)
	}

	records := make([]APIKeyRecord, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		record, err := a.fetchRecord(ctx, keyID)
		if err != nil {
			// Log and skip; a missing record may indicate a partial CreateKey
			// failure that only cleaned up the set entry later.
			slog.Warn("apikey: skipping missing record during ListKeys",
				"key_id", keyID,
				"tenant_id", tenantID,
				"error", err,
			)
			continue
		}
		records = append(records, *record)
	}

	return records, nil
}

// SyncAllPolicies loads every active API key from Redis across all known tenants
// and ensures that each key's Casbin policies exist in the enforcer.
//
// This is intended for use at daemon startup to reconcile the Casbin policy store
// with the ground-truth key records in Redis. It is safe to call multiple times;
// AddPoliciesForKey is idempotent for policies that already exist.
//
// Returns a non-nil error only if the initial tenant-set scan fails. Per-key
// errors are logged and skipped so that a single corrupt record does not block
// the rest of the sync.
//
// No-op if the authenticator has no enforcer configured.
func (a *APIKeyAuthenticator) SyncAllPolicies(ctx context.Context) error {
	if a.enforcer == nil {
		return nil
	}

	// Scan all apikeys:tenant:* keys to discover every known tenant.
	pattern := apiKeyTenantSetKeyPrefix + "*"
	var cursor uint64
	var tenantSetKeys []string
	for {
		keys, nextCursor, err := a.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("apikey: SyncAllPolicies: failed to scan tenant sets: %w", err)
		}
		tenantSetKeys = append(tenantSetKeys, keys...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	synced, skipped := 0, 0
	for _, tenantSetKey := range tenantSetKeys {
		tenantID := tenantSetKey[len(apiKeyTenantSetKeyPrefix):]

		keyIDs, err := a.client.SMembers(ctx, tenantSetKey).Result()
		if err != nil {
			slog.Warn("apikey: SyncAllPolicies: failed to list keys for tenant",
				"tenant_id", tenantID,
				"error", err,
			)
			skipped++
			continue
		}

		for _, keyID := range keyIDs {
			record, err := a.fetchRecord(ctx, keyID)
			if err != nil {
				slog.Warn("apikey: SyncAllPolicies: skipping key with missing record",
					"key_id", keyID,
					"tenant_id", tenantID,
					"error", err,
				)
				skipped++
				continue
			}

			// Only sync active keys with explicit capability grants. Inactive keys
			// have their policies removed on revocation; omit legacy wildcard keys
			// from Casbin since they were never added there in the first place.
			if record.Status != apiKeyStatusActive || len(record.Capabilities) == 0 {
				continue
			}

			if err := AddPoliciesForKey(a.enforcer, record.KeyID, record.TenantID, record.Capabilities); err != nil {
				slog.Warn("apikey: SyncAllPolicies: failed to sync policies for key",
					"key_id", keyID,
					"tenant_id", tenantID,
					"error", err,
				)
				skipped++
				continue
			}
			synced++
		}
	}

	slog.Info("apikey: SyncAllPolicies complete",
		"synced", synced,
		"skipped", skipped,
	)
	return nil
}

// fetchRecord retrieves and unmarshals the APIKeyRecord for the given key_id.
func (a *APIKeyAuthenticator) fetchRecord(ctx context.Context, keyID string) (*APIKeyRecord, error) {
	recordKey := apiKeyRecordKeyPrefix + keyID
	data, err := a.client.Get(ctx, recordKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrInvalidToken(fmt.Errorf("API key record not found: %s", keyID))
		}
		return nil, fmt.Errorf("failed to fetch API key record %q: %w", keyID, err)
	}

	var record APIKeyRecord
	if err := json.Unmarshal([]byte(data), &record); err != nil {
		return nil, fmt.Errorf("failed to unmarshal API key record %q: %w", keyID, err)
	}

	return &record, nil
}

// updateLastUsed sets the LastUsedAt field on the stored record to now.
//
// This is a best-effort operation called from a fire-and-forget goroutine.
// Callers must not rely on synchronous completion.
func (a *APIKeyAuthenticator) updateLastUsed(ctx context.Context, keyID string) error {
	record, err := a.fetchRecord(ctx, keyID)
	if err != nil {
		return err
	}

	record.LastUsedAt = time.Now().UTC()

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal API key record for last_used update: %w", err)
	}

	recordKey := apiKeyRecordKeyPrefix + keyID
	return a.client.Set(ctx, recordKey, data, 0).Err()
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
// A wildcard segment ("*") is preserved as-is and handled by HasPermission.
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
