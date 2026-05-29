package providerconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/datapool"
	"github.com/zeroroot-ai/gibson/internal/datapool/envelope"
)

// secretsServiceIface is the narrow slice of secrets.Service that
// brokerBackedStore needs. Production passes *secrets.Service; tests inject a
// fake. The interface is defined here (not in the secrets package) to keep the
// providerconfig package free of a concrete import cycle.
type secretsServiceIface interface {
	Put(ctx context.Context, name string, value []byte) error
	Resolve(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	List(ctx context.Context, filter sdksecrets.Filter) ([]string, error)
}

// brokerBackedStore implements ProviderConfigStore by routing:
//   - plaintext metadata (type, model, flags, timestamps) to the per-tenant
//     provider_configs Postgres table via providerConfigDAO.
//   - credentials to the secrets broker (secrets.Service) under keys
//     "provider_cred:<name>:<field>", one key per credential field.
//
// Lazy migration: on the first read of a provider whose row is absent from
// provider_configs but whose legacy key "provider_config:<name>" exists in
// tenant_secrets, the store decrypts the blob using conn.KEK, writes metadata
// to provider_configs, routes each credential field through secrets.Service.Put,
// and deletes the legacy row. This is idempotent — ON CONFLICT DO NOTHING
// protects against concurrent migration races.
type brokerBackedStore struct {
	pool datapool.Pool
	svc  secretsServiceIface
}

// NewBrokerBackedStore constructs a ProviderConfigStore that stores metadata in
// Postgres and credentials via the secrets broker. Both arguments must be
// non-nil; the function panics on nil so misconfiguration is caught at startup.
func NewBrokerBackedStore(pool datapool.Pool, svc secretsServiceIface) ProviderConfigStore {
	if pool == nil {
		panic("providerconfig: NewBrokerBackedStore: pool must not be nil")
	}
	if svc == nil {
		panic("providerconfig: NewBrokerBackedStore: secretsService must not be nil")
	}
	return &brokerBackedStore{pool: pool, svc: svc}
}

var _ ProviderConfigStore = (*brokerBackedStore)(nil)

// credKeyPrefix returns the secrets-broker key prefix for all credential fields
// of a named provider. Format: "provider_cred:<name>:".
func credKeyPrefix(name string) string {
	return "provider_cred:" + name + ":"
}

// credKey returns the secrets-broker key for a single credential field.
// Format: "provider_cred:<name>:<field>".
func credKey(name, field string) string {
	return credKeyPrefix(name) + field
}

// withTenant injects tenantID into ctx so secrets.Service can extract it.
func withTenant(ctx context.Context, tenantID string) context.Context {
	return auth.ContextWithTenantString(ctx, tenantID)
}

// acquireConn acquires a per-tenant Conn from the pool.
func (s *brokerBackedStore) acquireConn(ctx context.Context, tenantID string) (*datapool.Conn, error) {
	tid, err := auth.NewTenantID(tenantID)
	if err != nil {
		return nil, fmt.Errorf("providerconfig: invalid tenant %q: %w", tenantID, err)
	}
	conn, err := s.pool.For(ctx, tid)
	if err != nil {
		return nil, fmt.Errorf("providerconfig: acquire conn for %s: %w", tenantID, err)
	}
	return conn, nil
}

// putCredentials writes each credential field to the secrets broker.
func (s *brokerBackedStore) putCredentials(ctx context.Context, tenantID, name string, creds map[string]string) error {
	tctx := withTenant(ctx, tenantID)
	for field, val := range creds {
		if err := s.svc.Put(tctx, credKey(name, field), []byte(val)); err != nil {
			return fmt.Errorf("providerconfig: put credential %q field %q: %w", name, field, err)
		}
	}
	return nil
}

// getCredentials lists and resolves all credential fields for the provider from
// the secrets broker. Returns an empty (non-nil) map when no credentials exist.
func (s *brokerBackedStore) getCredentials(ctx context.Context, tenantID, name string) (map[string]string, error) {
	tctx := withTenant(ctx, tenantID)
	prefix := credKeyPrefix(name)
	keys, err := s.svc.List(tctx, sdksecrets.Filter{Prefix: prefix})
	if err != nil {
		return nil, fmt.Errorf("providerconfig: list credentials for %q: %w", name, err)
	}
	creds := make(map[string]string, len(keys))
	for _, key := range keys {
		val, err := s.svc.Resolve(tctx, key)
		if err != nil {
			return nil, fmt.Errorf("providerconfig: resolve credential %q: %w", key, err)
		}
		creds[strings.TrimPrefix(key, prefix)] = string(val)
	}
	return creds, nil
}

// deleteCredentials removes all credential fields for the provider from the broker.
func (s *brokerBackedStore) deleteCredentials(ctx context.Context, tenantID, name string) error {
	tctx := withTenant(ctx, tenantID)
	prefix := credKeyPrefix(name)
	keys, err := s.svc.List(tctx, sdksecrets.Filter{Prefix: prefix})
	if err != nil {
		return fmt.Errorf("providerconfig: list credentials for delete %q: %w", name, err)
	}
	for _, key := range keys {
		if err := s.svc.Delete(tctx, key); err != nil {
			return fmt.Errorf("providerconfig: delete credential %q: %w", key, err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Lazy migration helpers
// ---------------------------------------------------------------------------

// maybeMigrateOne checks for a legacy tenant_secrets row ("provider_config:<name>").
// If found, it decrypts the blob with conn.KEK, writes metadata to provider_configs,
// routes each credential field through secrets.Service.Put, and deletes the old row.
// Returns nil, nil when no legacy row exists (not an error).
func (s *brokerBackedStore) maybeMigrateOne(ctx context.Context, conn *datapool.Conn, tenantID, name string) (*ProviderConfig, error) {
	legacyKey := "provider_config:" + name
	aad := []byte("secret:" + legacyKey)

	var enc []byte
	err := conn.Postgres.QueryRow(ctx,
		`SELECT envelope FROM tenant_secrets WHERE name = $1`, legacyKey,
	).Scan(&enc)
	if err != nil {
		return nil, nil // no legacy row
	}

	plain, err := envelope.Decrypt(conn.KEK, enc, aad)
	if err != nil {
		return nil, fmt.Errorf("providerconfig: migrate: decrypt legacy %q: %w", name, err)
	}
	var p legacyProviderPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("providerconfig: migrate: unmarshal legacy %q: %w", name, err)
	}

	dao := newProviderConfigDAO(conn.Postgres)
	cfg, err := dao.insertMigrated(ctx, tenantID, name, &p)
	if err != nil {
		return nil, fmt.Errorf("providerconfig: migrate: insert metadata %q: %w", name, err)
	}

	if err := s.putCredentials(ctx, tenantID, name, p.Credentials); err != nil {
		return nil, fmt.Errorf("providerconfig: migrate: write credentials %q: %w", name, err)
	}

	// Best-effort cleanup: if this fails the migration is still correct — the
	// legacy row will be re-migrated on next read (ON CONFLICT DO NOTHING).
	_ = dao.deleteLegacyRow(ctx, name)

	return cfg, nil
}

// maybeMigrateAll migrates all legacy tenant_secrets rows not yet present in
// provider_configs. Called at the top of List to surface every provider.
func (s *brokerBackedStore) maybeMigrateAll(ctx context.Context, conn *datapool.Conn, tenantID string) error {
	dao := newProviderConfigDAO(conn.Postgres)
	names, err := dao.legacyProviderNames(ctx)
	if err != nil {
		return err
	}
	for _, name := range names {
		if _, err := s.maybeMigrateOne(ctx, conn, tenantID, name); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ProviderConfigStore implementation
// ---------------------------------------------------------------------------

func (s *brokerBackedStore) List(ctx context.Context, tenantID string) ([]*ProviderConfig, error) {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	if err := s.maybeMigrateAll(ctx, conn, tenantID); err != nil {
		return nil, err
	}

	dao := newProviderConfigDAO(conn.Postgres)
	metas, err := dao.list(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	result := make([]*ProviderConfig, 0, len(metas))
	for _, meta := range metas {
		creds, err := s.getCredentials(ctx, tenantID, meta.Name)
		if err != nil {
			return nil, err
		}
		result = append(result, AsRecord(meta, creds))
	}
	return result, nil
}

func (s *brokerBackedStore) Get(ctx context.Context, tenantID, name string) (*ProviderConfig, error) {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	meta, err := dao.get(ctx, tenantID, name)
	if errors.Is(err, ErrNotFound) {
		migrated, migrErr := s.maybeMigrateOne(ctx, conn, tenantID, name)
		if migrErr != nil {
			return nil, migrErr
		}
		if migrated == nil {
			return nil, fmt.Errorf("provider %q: %w", name, ErrNotFound)
		}
		meta = migrated
	} else if err != nil {
		return nil, err
	}

	creds, err := s.getCredentials(ctx, tenantID, name)
	if err != nil {
		return nil, err
	}
	return AsRecord(meta, creds), nil
}

func (s *brokerBackedStore) Create(ctx context.Context, tenantID string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	meta, err := dao.insert(ctx, tenantID, input)
	if err != nil {
		return nil, err
	}

	if err := s.putCredentials(ctx, tenantID, input.Name, input.Credentials); err != nil {
		_ = dao.delete(ctx, input.Name) // best-effort rollback of metadata row
		return nil, err
	}

	if input.SetAsDefault {
		_ = dao.setDefault(ctx, input.Name)
	}

	return AsRecord(meta, input.Credentials), nil
}

func (s *brokerBackedStore) Update(ctx context.Context, tenantID, name string, input *ProviderConfigInput) (*ProviderConfig, error) {
	if err := validateType(input.Type); err != nil {
		return nil, err
	}

	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	// Trigger migration if the metadata row is absent but a legacy row exists.
	if _, lookupErr := dao.get(ctx, tenantID, name); errors.Is(lookupErr, ErrNotFound) {
		if _, migrErr := s.maybeMigrateOne(ctx, conn, tenantID, name); migrErr != nil {
			return nil, migrErr
		}
	}

	meta, err := dao.update(ctx, tenantID, name, input)
	if err != nil {
		return nil, err
	}

	if err := s.putCredentials(ctx, tenantID, name, input.Credentials); err != nil {
		return nil, err
	}

	if input.SetAsDefault {
		_ = dao.setDefault(ctx, name)
	}

	return AsRecord(meta, input.Credentials), nil
}

func (s *brokerBackedStore) Delete(ctx context.Context, tenantID, name string) error {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	if err := dao.delete(ctx, name); err != nil {
		return err
	}

	if err := s.deleteCredentials(ctx, tenantID, name); err != nil {
		return err
	}

	// Clean up any surviving legacy row (best effort).
	_ = dao.deleteLegacyRow(ctx, name)

	return nil
}

func (s *brokerBackedStore) GetDefault(ctx context.Context, tenantID string) (*ProviderConfig, error) {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	name, daoErr := newProviderConfigDAO(conn.Postgres).getDefault(ctx)
	conn.Release()
	if daoErr != nil {
		return nil, ErrNotFound
	}
	return s.Get(ctx, tenantID, name)
}

func (s *brokerBackedStore) SetDefault(ctx context.Context, tenantID, name string) error {
	// Verify the provider exists (or migrate it) before setting default.
	if _, err := s.Get(ctx, tenantID, name); err != nil {
		return err
	}

	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return err
	}
	defer conn.Release()

	return newProviderConfigDAO(conn.Postgres).setDefault(ctx, name)
}

func (s *brokerBackedStore) Resolve(ctx context.Context, tenantID, name string) (*DecryptedConfig, error) {
	conn, err := s.acquireConn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	dao := newProviderConfigDAO(conn.Postgres)
	meta, err := dao.get(ctx, tenantID, name)
	if errors.Is(err, ErrNotFound) {
		migrated, migrErr := s.maybeMigrateOne(ctx, conn, tenantID, name)
		if migrErr != nil {
			return nil, migrErr
		}
		if migrated == nil {
			return nil, fmt.Errorf("provider %q: %w", name, ErrNotFound)
		}
		meta = migrated
	} else if err != nil {
		return nil, err
	}

	creds, err := s.getCredentials(ctx, tenantID, name)
	if err != nil {
		return nil, err
	}

	masked := AsRecord(meta, creds)
	return &DecryptedConfig{
		ProviderConfig: *masked,
		Credentials:    creds,
	}, nil
}
