package providerconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zero-day-ai/gibson/internal/datapool/envelope"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// postgresStore implements ProviderConfigStore backed by the per-tenant
// tenant_secrets table (migration 006), using AES Key Wrap DEK +
// AES-256-GCM per-record envelope encryption.
//
// Key format (name column PRIMARY KEY): "provider_config:<name>"
// Meta rows: providerDefaultKey and providerFallbackKey constants below.
//
// AAD = "secret:<name>" — ties the envelope to the row key so a row cannot
// be silently moved or renamed without decryption failing. Matches the AAD
// convention used by TenantSecretsOps for cred: keys in the same table.
//
// The tenantID carried on each method call is stored in the ProviderConfig
// for callers that need it (e.g., the API handler's list response). It is NOT
// used as a Postgres filter — the per-tenant database is the isolation boundary.
type postgresStore struct {
	pg  *pgxpool.Pool
	kek []byte
}

// newPostgresStore constructs a ProviderConfigStore backed by a per-tenant
// Postgres database with envelope encryption.
//
//   - pg: pgxpool connected to the tenant's Postgres database
//   - kek: 32-byte per-tenant KEK derived from the master KEK; callers must
//     zero this slice when no longer needed (Conn.Release does this automatically)
func newPostgresStore(pg *pgxpool.Pool, kek []byte) (ProviderConfigStore, error) {
	if len(kek) != 32 {
		return nil, fmt.Errorf("providerconfig: KEK must be 32 bytes, got %d", len(kek))
	}
	if pg == nil {
		return nil, fmt.Errorf("providerconfig: postgres pool cannot be nil")
	}
	return &postgresStore{pg: pg, kek: kek}, nil
}

// Ensure postgresStore satisfies the interface.
var _ ProviderConfigStore = (*postgresStore)(nil)

// ---------------------------------------------------------------------------
// Key and AAD constants
// ---------------------------------------------------------------------------

const (
	providerConfigKeyPrefix = "provider_config:"
	providerDefaultKey      = "provider_config:__default"
	providerFallbackKey     = "provider_config:__fallback_chain"
)

// rowKey returns the tenant_secrets primary key for a user-named provider config.
func rowKey(name string) string {
	return providerConfigKeyPrefix + name
}

// nameFromKey strips the prefix from a tenant_secrets key to recover the
// user-visible provider config name.
func nameFromKey(key string) string {
	return strings.TrimPrefix(key, providerConfigKeyPrefix)
}

// isMetaKey reports whether key is a synthetic meta row (default pointer or
// fallback chain), which should not appear in List results.
func isMetaKey(key string) bool {
	return key == providerDefaultKey || key == providerFallbackKey
}

// secretAAD returns the AAD bytes for the given tenant_secrets row key.
// Matches the "secret:<key>" convention used by TenantSecretsOps.
func secretAAD(key string) []byte {
	return []byte("secret:" + key)
}

// ---------------------------------------------------------------------------
// Payload stored inside the envelope
// ---------------------------------------------------------------------------

// providerConfigPayload is the JSON blob encrypted per record.
type providerConfigPayload struct {
	Type         string            `json:"type"`
	DefaultModel string            `json:"default_model"`
	IsDefault    bool              `json:"is_default"`
	Enabled      bool              `json:"enabled"`
	Credentials  map[string]string `json:"credentials"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

func (s *postgresStore) encryptPayload(p *providerConfigPayload, key string) ([]byte, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal provider config payload: %w", err)
	}
	return envelope.Encrypt(s.kek, plain, secretAAD(key))
}

func (s *postgresStore) decryptPayload(enc []byte, key string) (*providerConfigPayload, error) {
	plain, err := envelope.Decrypt(s.kek, enc, secretAAD(key))
	if err != nil {
		return nil, fmt.Errorf("decrypt provider config %q: %w", key, err)
	}
	var p providerConfigPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("unmarshal provider config payload: %w", err)
	}
	return &p, nil
}

// ---------------------------------------------------------------------------
// ProviderConfigStore implementation
// ---------------------------------------------------------------------------

func (s *postgresStore) List(ctx context.Context, tenantID string) ([]*ProviderConfig, error) {
	rows, err := s.pg.Query(ctx,
		`SELECT name, envelope FROM tenant_secrets WHERE starts_with(name, $1) ORDER BY name`,
		providerConfigKeyPrefix,
	)
	if err != nil {
		return nil, fmt.Errorf("list provider configs: %w", err)
	}
	defer rows.Close()

	var configs []*ProviderConfig
	for rows.Next() {
		var key string
		var enc []byte
		if err := rows.Scan(&key, &enc); err != nil {
			return nil, fmt.Errorf("scan provider config row: %w", err)
		}
		if isMetaKey(key) {
			continue
		}
		name := nameFromKey(key)
		p, err := s.decryptPayload(enc, key)
		if err != nil {
			// Skip rows that fail decryption rather than aborting the list.
			continue
		}
		cfg := payloadToConfig(tenantID, name, p)
		configs = append(configs, AsRecord(cfg, p.Credentials))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate provider configs: %w", err)
	}
	return configs, nil
}

func (s *postgresStore) Get(ctx context.Context, tenantID string, name string) (*ProviderConfig, error) {
	key := rowKey(name)
	var enc []byte
	err := s.pg.QueryRow(ctx,
		`SELECT envelope FROM tenant_secrets WHERE name = $1`, key,
	).Scan(&enc)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get provider config %q: %w", name, err)
	}
	p, err := s.decryptPayload(enc, key)
	if err != nil {
		return nil, fmt.Errorf("decrypt provider config %q: %w", name, err)
	}
	cfg := payloadToConfig(tenantID, name, p)
	return AsRecord(cfg, p.Credentials), nil
}

func (s *postgresStore) Create(ctx context.Context, tenantID string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	key := rowKey(input.Name)
	now := time.Now().UTC()
	p := &providerConfigPayload{
		Type:         string(input.Type),
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		Credentials:  input.Credentials,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	enc, err := s.encryptPayload(p, key)
	if err != nil {
		return nil, fmt.Errorf("encrypt provider config: %w", err)
	}

	_, err = s.pg.Exec(ctx,
		`INSERT INTO tenant_secrets (name, envelope, created_at, updated_at) VALUES ($1, $2, now(), now())`,
		key, enc,
	)
	if err != nil {
		if isPgUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("insert provider config: %w", err)
	}

	if input.SetAsDefault {
		_ = s.writeDefault(ctx, tenantID, input.Name)
	}

	cfg := &ProviderConfig{
		ID:           types.NewID(),
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

func (s *postgresStore) Update(ctx context.Context, tenantID string, name string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	key := rowKey(name)

	// Fetch existing to preserve created_at.
	var existingEnc []byte
	err := s.pg.QueryRow(ctx,
		`SELECT envelope FROM tenant_secrets WHERE name = $1`, key,
	).Scan(&existingEnc)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("fetch existing provider config: %w", err)
	}

	existing, decErr := s.decryptPayload(existingEnc, key)
	createdAt := time.Now().UTC()
	if decErr == nil {
		createdAt = existing.CreatedAt
	}

	now := time.Now().UTC()
	p := &providerConfigPayload{
		Type:         string(input.Type),
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		Credentials:  input.Credentials,
		CreatedAt:    createdAt,
		UpdatedAt:    now,
	}
	newEnc, err := s.encryptPayload(p, key)
	if err != nil {
		return nil, fmt.Errorf("encrypt updated provider config: %w", err)
	}

	_, err = s.pg.Exec(ctx,
		`UPDATE tenant_secrets SET envelope = $1, updated_at = now() WHERE name = $2`,
		newEnc, key,
	)
	if err != nil {
		return nil, fmt.Errorf("update provider config: %w", err)
	}

	if input.SetAsDefault {
		_ = s.writeDefault(ctx, tenantID, name)
	}

	cfg := &ProviderConfig{
		ID:           types.NewID(),
		TenantID:     tenantID,
		Name:         name,
		Type:         input.Type,
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		CreatedAt:    createdAt,
		UpdatedAt:    now,
	}
	return AsRecord(cfg, input.Credentials), nil
}

func (s *postgresStore) Delete(ctx context.Context, tenantID string, name string) error {
	key := rowKey(name)
	tag, err := s.pg.Exec(ctx,
		`DELETE FROM tenant_secrets WHERE name = $1`, key,
	)
	if err != nil {
		return fmt.Errorf("delete provider config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	// Clear default/fallback chain if they reference this name (best effort).
	_ = s.clearDefaultIfMatch(ctx, name)
	return nil
}

func (s *postgresStore) GetDefault(ctx context.Context, tenantID string) (*ProviderConfig, error) {
	name, err := s.readDefault(ctx)
	if err != nil {
		return nil, ErrNotFound
	}
	return s.Get(ctx, tenantID, name)
}

func (s *postgresStore) SetDefault(ctx context.Context, tenantID string, name string) error {
	// Verify provider exists.
	if _, err := s.Get(ctx, tenantID, name); err != nil {
		return err
	}
	return s.writeDefault(ctx, tenantID, name)
}

func (s *postgresStore) GetFallbackChain(ctx context.Context, tenantID string) ([]string, error) {
	var data []byte
	err := s.pg.QueryRow(ctx,
		`SELECT envelope FROM tenant_secrets WHERE name = $1`, providerFallbackKey,
	).Scan(&data)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("get fallback chain: %w", err)
	}
	plain, err := envelope.Decrypt(s.kek, data, secretAAD(providerFallbackKey))
	if err != nil {
		return []string{}, nil
	}
	var chain []string
	if err := json.Unmarshal(plain, &chain); err != nil {
		return []string{}, nil
	}
	return chain, nil
}

func (s *postgresStore) SetFallbackChain(ctx context.Context, tenantID string, names []string) error {
	for _, name := range names {
		if _, err := s.Get(ctx, tenantID, name); err != nil {
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
	enc, err := envelope.Encrypt(s.kek, data, secretAAD(providerFallbackKey))
	if err != nil {
		return fmt.Errorf("encrypt fallback chain: %w", err)
	}
	_, err = s.pg.Exec(ctx,
		`INSERT INTO tenant_secrets (name, envelope, created_at, updated_at)
		 VALUES ($1, $2, now(), now())
		 ON CONFLICT (name) DO UPDATE SET envelope = EXCLUDED.envelope, updated_at = now()`,
		providerFallbackKey, enc,
	)
	return err
}

func (s *postgresStore) Resolve(ctx context.Context, tenantID string, name string) (*DecryptedConfig, error) {
	key := rowKey(name)
	var enc []byte
	err := s.pg.QueryRow(ctx,
		`SELECT envelope FROM tenant_secrets WHERE name = $1`, key,
	).Scan(&enc)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("resolve provider config %q: %w", name, err)
	}
	p, err := s.decryptPayload(enc, key)
	if err != nil {
		return nil, fmt.Errorf("resolve: decrypt: %w", err)
	}
	cfg := payloadToConfig(tenantID, name, p)
	masked := AsRecord(cfg, p.Credentials)
	return &DecryptedConfig{
		ProviderConfig: *masked,
		Credentials:    p.Credentials,
	}, nil
}

// ---------------------------------------------------------------------------
// Default pointer helpers (stored as meta rows in tenant_secrets)
// ---------------------------------------------------------------------------

func (s *postgresStore) readDefault(ctx context.Context) (string, error) {
	var enc []byte
	err := s.pg.QueryRow(ctx,
		`SELECT envelope FROM tenant_secrets WHERE name = $1`, providerDefaultKey,
	).Scan(&enc)
	if err != nil {
		return "", fmt.Errorf("read default: %w", err)
	}
	plain, err := envelope.Decrypt(s.kek, enc, secretAAD(providerDefaultKey))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *postgresStore) writeDefault(ctx context.Context, _ string, name string) error {
	enc, err := envelope.Encrypt(s.kek, []byte(name), secretAAD(providerDefaultKey))
	if err != nil {
		return fmt.Errorf("encrypt default pointer: %w", err)
	}
	_, err = s.pg.Exec(ctx,
		`INSERT INTO tenant_secrets (name, envelope, created_at, updated_at)
		 VALUES ($1, $2, now(), now())
		 ON CONFLICT (name) DO UPDATE SET envelope = EXCLUDED.envelope, updated_at = now()`,
		providerDefaultKey, enc,
	)
	return err
}

func (s *postgresStore) clearDefaultIfMatch(ctx context.Context, name string) error {
	current, err := s.readDefault(context.Background())
	if err != nil || current != name {
		return nil
	}
	_, err = s.pg.Exec(context.Background(),
		`DELETE FROM tenant_secrets WHERE name = $1`, providerDefaultKey,
	)
	return err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func payloadToConfig(tenantID, name string, p *providerConfigPayload) *ProviderConfig {
	return &ProviderConfig{
		ID:           types.NewID(),
		TenantID:     tenantID,
		Name:         name,
		Type:         llm.ProviderType(p.Type),
		DefaultModel: p.DefaultModel,
		IsDefault:    p.IsDefault,
		Enabled:      p.Enabled,
		CreatedAt:    p.CreatedAt,
		UpdatedAt:    p.UpdatedAt,
	}
}

// isPgUniqueViolation returns true when err is a Postgres unique constraint
// violation (SQLSTATE 23505).
func isPgUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	// pgx wraps the PgError inside the error chain.
	type pgError interface{ SQLState() string }
	var pe pgError
	if errors.As(err, &pe) {
		return pe.SQLState() == "23505"
	}
	return false
}

// NewPostgresStore constructs a ProviderConfigStore backed by a per-tenant
// Postgres database. pg must be connected to the tenant's dedicated database.
// kek must be exactly 32 bytes (the per-tenant KEK from Conn.KEK).
func NewPostgresStore(pg *pgxpool.Pool, kek []byte) (ProviderConfigStore, error) {
	return newPostgresStore(pg, kek)
}
