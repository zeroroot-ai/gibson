package providerconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/zero-day-ai/gibson/internal/datapool/envelope"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
)

// postgresStore implements ProviderConfigStore backed by a per-tenant Postgres
// database, using AES Key Wrap DEK + AES-256-GCM per-record envelope encryption.
//
// The tenantID carried on each method call is stored in the ProviderConfig for
// callers that need it (e.g., the API handler's list response). It is NOT used
// as a Postgres filter — the per-tenant database is the isolation boundary.
//
// AAD = "providerconfig:<provider>:<name>" — ties the envelope to the row
// identity so a row cannot be moved between providers or renamed without
// decryption failing.
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
// AAD helpers
// ---------------------------------------------------------------------------

func providerConfigAAD(provider, name string) []byte {
	return []byte("providerconfig:" + provider + ":" + name)
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

func (s *postgresStore) encryptPayload(p *providerConfigPayload, provider, name string) ([]byte, error) {
	plain, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal provider config payload: %w", err)
	}
	return envelope.Encrypt(s.kek, plain, providerConfigAAD(provider, name))
}

func (s *postgresStore) decryptPayload(env []byte, provider, name string) (*providerConfigPayload, error) {
	plain, err := envelope.Decrypt(s.kek, env, providerConfigAAD(provider, name))
	if err != nil {
		return nil, fmt.Errorf("decrypt provider config %q/%q: %w", provider, name, err)
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
		`SELECT provider, name, envelope FROM provider_configs ORDER BY provider, name`,
	)
	if err != nil {
		return nil, fmt.Errorf("list provider configs: %w", err)
	}
	defer rows.Close()

	var configs []*ProviderConfig
	for rows.Next() {
		var provider, name string
		var env []byte
		if err := rows.Scan(&provider, &name, &env); err != nil {
			return nil, fmt.Errorf("scan provider config row: %w", err)
		}
		p, err := s.decryptPayload(env, provider, name)
		if err != nil {
			// Skip rows that fail decryption rather than aborting the list.
			continue
		}
		cfg := payloadToConfig(tenantID, provider, name, p)
		configs = append(configs, AsRecord(cfg, p.Credentials))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate provider configs: %w", err)
	}
	return configs, nil
}

func (s *postgresStore) Get(ctx context.Context, tenantID string, name string) (*ProviderConfig, error) {
	// name may be "provider:name" or just "name" — normalise to match rows.
	// In this schema, the name column uniquely identifies within a provider.
	// We scan all providers for this name for backward compatibility.
	rows, err := s.pg.Query(ctx,
		`SELECT provider, name, envelope FROM provider_configs WHERE name = $1 LIMIT 1`, name,
	)
	if err != nil {
		return nil, fmt.Errorf("get provider config %q: %w", name, err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, ErrNotFound
	}
	var provider, rowName string
	var env []byte
	if err := rows.Scan(&provider, &rowName, &env); err != nil {
		return nil, fmt.Errorf("scan provider config: %w", err)
	}
	p, err := s.decryptPayload(env, provider, rowName)
	if err != nil {
		return nil, fmt.Errorf("decrypt provider config %q: %w", name, err)
	}
	cfg := payloadToConfig(tenantID, provider, rowName, p)
	return AsRecord(cfg, p.Credentials), nil
}

func (s *postgresStore) Create(ctx context.Context, tenantID string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	provider := string(input.Type)
	now := time.Now().UTC()
	p := &providerConfigPayload{
		Type:         provider,
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		Credentials:  input.Credentials,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	env, err := s.encryptPayload(p, provider, input.Name)
	if err != nil {
		return nil, fmt.Errorf("encrypt provider config: %w", err)
	}

	_, err = s.pg.Exec(ctx,
		`INSERT INTO provider_configs (provider, name, envelope, created_at, updated_at)
		 VALUES ($1, $2, $3, now(), now())`,
		provider, input.Name, env,
	)
	if err != nil {
		// Detect unique constraint violation.
		if isPgUniqueViolation(err) {
			return nil, ErrAlreadyExists
		}
		return nil, fmt.Errorf("insert provider config: %w", err)
	}

	if input.SetAsDefault {
		_ = s.writeDefault(ctx, tenantID, input.Name)
	}

	id := types.NewID()
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

func (s *postgresStore) Update(ctx context.Context, tenantID string, name string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	provider := string(input.Type)

	// Fetch existing to preserve created_at.
	var env []byte
	err := s.pg.QueryRow(ctx,
		`SELECT envelope FROM provider_configs WHERE name = $1`, name,
	).Scan(&env)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("fetch existing provider config: %w", err)
	}

	// Read existing payload to get created_at (we decrypt just for that).
	existing, decErr := s.decryptPayload(env, provider, name)
	createdAt := time.Now().UTC()
	if decErr == nil {
		createdAt = existing.CreatedAt
	}

	now := time.Now().UTC()
	p := &providerConfigPayload{
		Type:         provider,
		DefaultModel: input.DefaultModel,
		IsDefault:    input.SetAsDefault,
		Enabled:      input.Enabled,
		Credentials:  input.Credentials,
		CreatedAt:    createdAt,
		UpdatedAt:    now,
	}
	newEnv, err := s.encryptPayload(p, provider, name)
	if err != nil {
		return nil, fmt.Errorf("encrypt updated provider config: %w", err)
	}

	_, err = s.pg.Exec(ctx,
		`UPDATE provider_configs SET envelope = $1, updated_at = now() WHERE name = $2`,
		newEnv, name,
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
	tag, err := s.pg.Exec(ctx,
		`DELETE FROM provider_configs WHERE name = $1`, name,
	)
	if err != nil {
		return fmt.Errorf("delete provider config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	// Also clear default/fallback chain if they reference this name (best effort).
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
		`SELECT envelope FROM provider_configs WHERE name = '_fallback_chain' AND provider = '_meta'`,
	).Scan(&data)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("get fallback chain: %w", err)
	}
	plain, err := envelope.Decrypt(s.kek, data, providerConfigAAD("_meta", "_fallback_chain"))
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
	env, err := envelope.Encrypt(s.kek, data, providerConfigAAD("_meta", "_fallback_chain"))
	if err != nil {
		return fmt.Errorf("encrypt fallback chain: %w", err)
	}
	_, err = s.pg.Exec(ctx,
		`INSERT INTO provider_configs (provider, name, envelope, created_at, updated_at)
		 VALUES ('_meta', '_fallback_chain', $1, now(), now())
		 ON CONFLICT (provider, name) DO UPDATE SET envelope = EXCLUDED.envelope, updated_at = now()`,
		env,
	)
	return err
}

func (s *postgresStore) Resolve(ctx context.Context, tenantID string, name string) (*DecryptedConfig, error) {
	rows, err := s.pg.Query(ctx,
		`SELECT provider, name, envelope FROM provider_configs WHERE name = $1 LIMIT 1`, name,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve provider config %q: %w", name, err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, ErrNotFound
	}
	var provider, rowName string
	var env []byte
	if err := rows.Scan(&provider, &rowName, &env); err != nil {
		return nil, fmt.Errorf("scan provider config: %w", err)
	}
	p, err := s.decryptPayload(env, provider, rowName)
	if err != nil {
		return nil, fmt.Errorf("resolve: decrypt: %w", err)
	}
	cfg := payloadToConfig(tenantID, provider, rowName, p)
	masked := AsRecord(cfg, p.Credentials)
	return &DecryptedConfig{
		ProviderConfig: *masked,
		Credentials:    p.Credentials,
	}, nil
}

// ---------------------------------------------------------------------------
// Default pointer helpers (stored as a special meta row)
// ---------------------------------------------------------------------------

func (s *postgresStore) readDefault(ctx context.Context) (string, error) {
	var env []byte
	err := s.pg.QueryRow(ctx,
		`SELECT envelope FROM provider_configs WHERE name = '_default' AND provider = '_meta'`,
	).Scan(&env)
	if err != nil {
		return "", fmt.Errorf("read default: %w", err)
	}
	plain, err := envelope.Decrypt(s.kek, env, providerConfigAAD("_meta", "_default"))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *postgresStore) writeDefault(ctx context.Context, _ string, name string) error {
	env, err := envelope.Encrypt(s.kek, []byte(name), providerConfigAAD("_meta", "_default"))
	if err != nil {
		return fmt.Errorf("encrypt default pointer: %w", err)
	}
	_, err = s.pg.Exec(ctx,
		`INSERT INTO provider_configs (provider, name, envelope, created_at, updated_at)
		 VALUES ('_meta', '_default', $1, now(), now())
		 ON CONFLICT (provider, name) DO UPDATE SET envelope = EXCLUDED.envelope, updated_at = now()`,
		env,
	)
	return err
}

func (s *postgresStore) clearDefaultIfMatch(ctx context.Context, name string) error {
	current, err := s.readDefault(context.Background())
	if err != nil || current != name {
		return nil
	}
	_, err = s.pg.Exec(context.Background(),
		`DELETE FROM provider_configs WHERE name = '_default' AND provider = '_meta'`,
	)
	return err
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func payloadToConfig(tenantID, provider, name string, p *providerConfigPayload) *ProviderConfig {
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
//
// This is the Phase C replacement for the Redis-backed redisStore. The same
// ProviderConfigStore interface is preserved so callers do not require changes.
func NewPostgresStore(pg *pgxpool.Pool, kek []byte) (ProviderConfigStore, error) {
	return newPostgresStore(pg, kek)
}
