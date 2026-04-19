package providerconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ProviderConfigStore is the daemon's single source of truth for
// tenant-configured LLM providers. Credentials are encrypted at rest
// via the crypto.CredentialStore pipeline; reads return masked values
// via AsRecord; Resolve returns the decrypted credential for the
// ExecuteLLM/StreamLLM execution path only.
type ProviderConfigStore interface {
	// List returns all provider configs for the given tenant, with credentials masked.
	List(ctx context.Context, tenantID string) ([]*ProviderConfig, error)

	// Get returns the named provider config for the given tenant, with credentials masked.
	Get(ctx context.Context, tenantID string, name string) (*ProviderConfig, error)

	// Create persists a new provider config. Returns ErrAlreadyExists if a config
	// with the same name already exists for this tenant. Returns ErrKeyProviderUnset
	// if the store was constructed without a KeyProvider. Returns ErrUnsupportedType
	// if the provider type is not in llm.SupportedProviderTypes().
	Create(ctx context.Context, tenantID string, input *ProviderConfigInput) (*ProviderConfig, error)

	// Update replaces the named provider config. Returns ErrNotFound if no config
	// with that name exists for the tenant.
	Update(ctx context.Context, tenantID string, name string, input *ProviderConfigInput) (*ProviderConfig, error)

	// Delete removes the named provider config. Returns ErrNotFound if it does not exist.
	Delete(ctx context.Context, tenantID string, name string) error

	// GetDefault returns the provider config marked as default for the tenant.
	// Returns ErrNotFound if no default has been set.
	GetDefault(ctx context.Context, tenantID string) (*ProviderConfig, error)

	// SetDefault marks the named provider as the tenant's default. Returns ErrNotFound
	// if no provider with that name exists for the tenant.
	SetDefault(ctx context.Context, tenantID string, name string) error

	// GetFallbackChain returns the ordered list of provider names to try in sequence
	// when the primary provider fails. Returns an empty slice if none is set.
	GetFallbackChain(ctx context.Context, tenantID string) ([]string, error)

	// SetFallbackChain replaces the fallback chain. Each name must refer to an
	// existing provider config for the tenant.
	SetFallbackChain(ctx context.Context, tenantID string, names []string) error

	// Resolve returns the decrypted config for the execution path.
	//
	// SECURITY CONTRACT: Caller MUST NOT log or persist the returned Credentials
	// map. The decrypted credential must not escape the calling handler's stack frame.
	Resolve(ctx context.Context, tenantID string, name string) (*DecryptedConfig, error)
}

// encryptedPayload is the JSON blob written into EncryptedValue.
// It is encrypted with AES-256-GCM before storage.
type encryptedPayload struct {
	Type         string            `json:"type"`
	DefaultModel string            `json:"default_model"`
	IsDefault    bool              `json:"is_default"`
	Enabled      bool              `json:"enabled"`
	Credentials  map[string]string `json:"credentials"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// storedRecord is the JSON document stored at each provider Redis key.
// The EncryptedPayload, IV, and Salt are base64 URL-encoded binary blobs.
// The Name and ID are stored in plaintext for key reconstruction and listing.
type storedRecord struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	EncryptedPayload []byte `json:"enc"`
	IV               []byte `json:"iv"`
	Salt             []byte `json:"salt"`
}

// redisStore implements ProviderConfigStore backed by a raw Redis client.
// It uses AES-256-GCM encryption via crypto.Encryptor and resolves the
// master key through crypto.KeyProvider on every write/read.
type redisStore struct {
	rdb     redis.UniversalClient
	enc     crypto.Encryptor
	keyProv crypto.KeyProvider
}

// Ensure redisStore satisfies the interface at compile time.
var _ ProviderConfigStore = (*redisStore)(nil)

// NewStore constructs a ProviderConfigStore backed by the given Redis client.
//
// Parameters:
//   - rdb: raw Redis client (plain redis.UniversalClient — no RedisJSON/RediSearch required)
//   - enc: AES-256-GCM encryptor used to protect credential payloads
//   - kp: KeyProvider that resolves the master encryption key; if nil, NewStore panics
//     to catch misconfiguration at startup. Write operations also return ErrKeyProviderUnset
//     at runtime if the provider is absent.
//
// The function returns ErrKeyProviderUnset if kp is nil so the daemon startup
// fails fast when security.key_provider is not configured.
func NewStore(rdb redis.UniversalClient, enc crypto.Encryptor, kp crypto.KeyProvider) (ProviderConfigStore, error) {
	if kp == nil {
		return nil, ErrKeyProviderUnset
	}
	if enc == nil {
		return nil, fmt.Errorf("encryptor cannot be nil")
	}
	if rdb == nil {
		return nil, fmt.Errorf("redis client cannot be nil")
	}
	return &redisStore{
		rdb:     rdb,
		enc:     enc,
		keyProv: kp,
	}, nil
}

// ---------------------------------------------------------------------------
// Redis key helpers
// ---------------------------------------------------------------------------

// providerKey returns the Redis key for a named provider config.
// Format: gibson:providerconfig:<tenantID>:provider:<name>
func providerKey(tenantID, name string) string {
	return fmt.Sprintf("gibson:providerconfig:%s:provider:%s", tenantID, name)
}

// tenantProviderPrefix returns the scan prefix for all providers of a tenant.
func tenantProviderPrefix(tenantID string) string {
	return fmt.Sprintf("gibson:providerconfig:%s:provider:", tenantID)
}

// defaultKey returns the Redis key for the tenant's default provider name.
func defaultKey(tenantID string) string {
	return fmt.Sprintf("gibson:providerconfig:%s:_default", tenantID)
}

// fallbackKey returns the Redis key for the tenant's fallback chain.
func fallbackKey(tenantID string) string {
	return fmt.Sprintf("gibson:providerconfig:%s:_fallback", tenantID)
}

// ---------------------------------------------------------------------------
// Encryption helpers
// ---------------------------------------------------------------------------

func (s *redisStore) masterKey(ctx context.Context) ([]byte, error) {
	if s.keyProv == nil {
		return nil, ErrKeyProviderUnset
	}
	mk, err := s.keyProv.GetEncryptionKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("key provider: %w", err)
	}
	return mk, nil
}

func (s *redisStore) encryptPayload(ctx context.Context, p *encryptedPayload) (ciphertext, iv, salt []byte, err error) {
	mk, err := s.masterKey(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	plaintext, err := json.Marshal(p)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("marshal payload: %w", err)
	}
	return s.enc.Encrypt(plaintext, mk)
}

func (s *redisStore) decryptPayload(ctx context.Context, ciphertext, iv, salt []byte) (*encryptedPayload, error) {
	mk, err := s.masterKey(ctx)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.enc.Decrypt(ciphertext, iv, salt, mk)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	var p encryptedPayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("unmarshal decrypted payload: %w", err)
	}
	return &p, nil
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

func (s *redisStore) writeRecord(ctx context.Context, tenantID string, rec *storedRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("marshal stored record: %w", err)
	}
	key := providerKey(tenantID, rec.Name)
	return s.rdb.Set(ctx, key, data, 0).Err()
}

func (s *redisStore) readRecord(ctx context.Context, tenantID, name string) (*storedRecord, error) {
	key := providerKey(tenantID, name)
	data, err := s.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("redis get %q: %w", key, err)
	}
	var rec storedRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("unmarshal stored record: %w", err)
	}
	return &rec, nil
}

func (s *redisStore) recordToConfig(ctx context.Context, tenantID string, rec *storedRecord) (*ProviderConfig, map[string]string, error) {
	payload, err := s.decryptPayload(ctx, rec.EncryptedPayload, rec.IV, rec.Salt)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt provider %q: %w", rec.Name, err)
	}
	id, err := types.ParseID(rec.ID)
	if err != nil {
		// Fallback: if stored ID is somehow invalid, surface a non-fatal error
		return nil, nil, fmt.Errorf("parse stored ID %q: %w", rec.ID, err)
	}
	cfg := &ProviderConfig{
		ID:           id,
		TenantID:     tenantID,
		Name:         rec.Name,
		Type:         llm.ProviderType(payload.Type),
		DefaultModel: payload.DefaultModel,
		IsDefault:    payload.IsDefault,
		Enabled:      payload.Enabled,
		CreatedAt:    payload.CreatedAt,
		UpdatedAt:    payload.UpdatedAt,
	}
	return cfg, payload.Credentials, nil
}

// ---------------------------------------------------------------------------
// ProviderConfigStore implementation
// ---------------------------------------------------------------------------

func (s *redisStore) List(ctx context.Context, tenantID string) ([]*ProviderConfig, error) {
	prefix := tenantProviderPrefix(tenantID)
	pattern := prefix + "*"

	var keys []string
	var cursor uint64
	for {
		batch, nextCursor, err := s.rdb.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan provider keys: %w", err)
		}
		keys = append(keys, batch...)
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	configs := make([]*ProviderConfig, 0, len(keys))
	for _, key := range keys {
		// Extract name from key
		name := strings.TrimPrefix(key, prefix)
		if name == "" {
			continue
		}
		rec, err := s.readRecord(ctx, tenantID, name)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // Key disappeared between SCAN and GET; skip
			}
			return nil, fmt.Errorf("read record %q: %w", name, err)
		}
		cfg, creds, err := s.recordToConfig(ctx, tenantID, rec)
		if err != nil {
			return nil, err
		}
		configs = append(configs, AsRecord(cfg, creds))
	}
	return configs, nil
}

func (s *redisStore) Get(ctx context.Context, tenantID string, name string) (*ProviderConfig, error) {
	rec, err := s.readRecord(ctx, tenantID, name)
	if err != nil {
		return nil, err
	}
	cfg, creds, err := s.recordToConfig(ctx, tenantID, rec)
	if err != nil {
		return nil, err
	}
	return AsRecord(cfg, creds), nil
}

func (s *redisStore) Create(ctx context.Context, tenantID string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	// Atomically check existence and write using SET NX.
	key := providerKey(tenantID, input.Name)
	now := time.Now().UTC()

	payload := &encryptedPayload{
		Type:         string(input.Type),
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		Credentials:  input.Credentials,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	ciphertext, iv, salt, err := s.encryptPayload(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("encrypt provider config: %w", err)
	}

	id := types.NewID()
	rec := &storedRecord{
		ID:               id.String(),
		Name:             input.Name,
		EncryptedPayload: ciphertext,
		IV:               iv,
		Salt:             salt,
	}
	data, err := json.Marshal(rec)
	if err != nil {
		return nil, fmt.Errorf("marshal stored record: %w", err)
	}

	// SET NX ensures atomically that we don't overwrite an existing config.
	ok, err := s.rdb.SetNX(ctx, key, data, 0).Result()
	if err != nil {
		return nil, fmt.Errorf("redis set nx: %w", err)
	}
	if !ok {
		return nil, ErrAlreadyExists
	}

	if input.SetAsDefault {
		if err := s.rdb.Set(ctx, defaultKey(tenantID), input.Name, 0).Err(); err != nil {
			// Non-fatal: log but don't fail the create.
			// The provider was created; the default pointer update failed.
			// In production the caller can retry SetDefault.
			_ = err
		}
	}

	cfg := &ProviderConfig{
		ID:           id,
		TenantID:     tenantID,
		Name:         input.Name,
		Type:         input.Type,
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	return AsRecord(cfg, input.Credentials), nil
}

func (s *redisStore) Update(ctx context.Context, tenantID string, name string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	// Read existing to get created_at and ID.
	rec, err := s.readRecord(ctx, tenantID, name)
	if err != nil {
		return nil, err // ErrNotFound propagates
	}

	existingPayload, err := s.decryptPayload(ctx, rec.EncryptedPayload, rec.IV, rec.Salt)
	if err != nil {
		return nil, fmt.Errorf("decrypt existing: %w", err)
	}

	now := time.Now().UTC()
	newPayload := &encryptedPayload{
		Type:         string(input.Type),
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		Credentials:  input.Credentials,
		CreatedAt:    existingPayload.CreatedAt,
		UpdatedAt:    now,
	}

	ciphertext, iv, salt, err := s.encryptPayload(ctx, newPayload)
	if err != nil {
		return nil, fmt.Errorf("encrypt updated provider config: %w", err)
	}

	updatedRec := &storedRecord{
		ID:               rec.ID,
		Name:             rec.Name,
		EncryptedPayload: ciphertext,
		IV:               iv,
		Salt:             salt,
	}
	if err := s.writeRecord(ctx, tenantID, updatedRec); err != nil {
		return nil, err
	}

	if input.SetAsDefault {
		_ = s.rdb.Set(ctx, defaultKey(tenantID), name, 0).Err()
	}

	id, _ := types.ParseID(rec.ID)
	cfg := &ProviderConfig{
		ID:           id,
		TenantID:     tenantID,
		Name:         name,
		Type:         input.Type,
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		CreatedAt:    existingPayload.CreatedAt,
		UpdatedAt:    now,
	}
	return AsRecord(cfg, input.Credentials), nil
}

func (s *redisStore) Delete(ctx context.Context, tenantID string, name string) error {
	key := providerKey(tenantID, name)

	n, err := s.rdb.Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("redis del: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}

	// If this was the default, clear it.
	defName, _ := s.rdb.Get(ctx, defaultKey(tenantID)).Result()
	if defName == name {
		_ = s.rdb.Del(ctx, defaultKey(tenantID)).Err()
	}

	return nil
}

func (s *redisStore) GetDefault(ctx context.Context, tenantID string) (*ProviderConfig, error) {
	name, err := s.rdb.Get(ctx, defaultKey(tenantID)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get default key: %w", err)
	}
	return s.Get(ctx, tenantID, name)
}

func (s *redisStore) SetDefault(ctx context.Context, tenantID string, name string) error {
	// Verify the provider exists before setting as default.
	if _, err := s.readRecord(ctx, tenantID, name); err != nil {
		return err // ErrNotFound propagates
	}

	// Unset is_default on the previous default (best effort — payload update).
	// We skip rewriting the old default's payload to avoid a scrypt round-trip;
	// is_default in the payload is advisory. The canonical default is the pointer key.

	if err := s.rdb.Set(ctx, defaultKey(tenantID), name, 0).Err(); err != nil {
		return fmt.Errorf("set default key: %w", err)
	}
	return nil
}

func (s *redisStore) GetFallbackChain(ctx context.Context, tenantID string) ([]string, error) {
	data, err := s.rdb.Get(ctx, fallbackKey(tenantID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("get fallback chain: %w", err)
	}
	var chain []string
	if err := json.Unmarshal(data, &chain); err != nil {
		return nil, fmt.Errorf("unmarshal fallback chain: %w", err)
	}
	return chain, nil
}

func (s *redisStore) SetFallbackChain(ctx context.Context, tenantID string, names []string) error {
	// Validate that every name in the chain exists for this tenant.
	for _, name := range names {
		if _, err := s.readRecord(ctx, tenantID, name); err != nil {
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("fallback chain references unknown provider %q: %w", name, ErrNotFound)
			}
			return err
		}
	}

	data, err := json.Marshal(names)
	if err != nil {
		return fmt.Errorf("marshal fallback chain: %w", err)
	}
	if err := s.rdb.Set(ctx, fallbackKey(tenantID), data, 0).Err(); err != nil {
		return fmt.Errorf("set fallback chain: %w", err)
	}
	return nil
}

func (s *redisStore) Resolve(ctx context.Context, tenantID string, name string) (*DecryptedConfig, error) {
	rec, err := s.readRecord(ctx, tenantID, name)
	if err != nil {
		return nil, err
	}
	cfg, creds, err := s.recordToConfig(ctx, tenantID, rec)
	if err != nil {
		return nil, err
	}
	// Populate masked credentials on the embedded ProviderConfig.
	masked := AsRecord(cfg, creds)
	return &DecryptedConfig{
		ProviderConfig: *masked,
		Credentials:    creds,
	}, nil
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

func validateType(t llm.ProviderType) error {
	for _, supported := range llm.SupportedProviderTypes() {
		if t == supported {
			return nil
		}
	}
	return fmt.Errorf("%w: %q (supported: %s)", ErrUnsupportedType, t, joinTypes(llm.SupportedProviderTypes()))
}

func joinTypes(types []llm.ProviderType) string {
	ss := make([]string, len(types))
	for i, t := range types {
		ss[i] = string(t)
	}
	return strings.Join(ss, ", ")
}
