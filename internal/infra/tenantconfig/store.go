// Package tenantconfig persists per-tenant broker configurations to the
// operator-shared (dashboard) Postgres database.
//
// Each row's config column is envelope-encrypted under the system-tenant
// KEK with AAD "tenant_secrets_broker_config:<tenant_id>".
//
// This package is the shared implementation consumed by both the gibson
// daemon (internal/platform/secrets/configstore) and the tenant-operator saga
// (internal/saga/flows/write_broker_config). The daemon's configstore
// package wraps this; the operator imports it directly.
package tenantconfig

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zeroroot-ai/sdk/auth"

	"github.com/zeroroot-ai/gibson/internal/infra/tenantconfig/envelope"
)

// Store persists per-tenant broker configurations to the operator-shared
// (dashboard) Postgres database. Safe for concurrent use.
type Store struct {
	pg  *pgxpool.Pool
	kek []byte // system-tenant KEK; 32 bytes
}

// NewStore constructs a Store. pg must be a pool connected to the
// operator-shared Postgres database that contains the
// tenant_secrets_broker_config table. kek must be the 32-byte
// system-tenant KEK retrieved from the daemon's KeyProvider.
func NewStore(pg *pgxpool.Pool, kek []byte) (*Store, error) {
	if pg == nil {
		return nil, errors.New("tenantconfig: pg pool must not be nil")
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("tenantconfig: KEK must be 32 bytes, got %d", len(kek))
	}
	return &Store{pg: pg, kek: kek}, nil
}

// ErrNotFound is returned by GetRaw when no broker config row exists for
// the given tenant.
var ErrNotFound = errors.New("tenantconfig: broker config not found")

// configAAD returns the additional authenticated data for the given
// tenant's broker config envelope.
func configAAD(tenantID auth.TenantID) []byte {
	return []byte("tenant_secrets_broker_config:" + tenantID.String())
}

// GetRaw retrieves the decrypted provider config JSON blob for the given
// tenant. Returns ErrNotFound when no row exists.
func (s *Store) GetRaw(ctx context.Context, tenant auth.TenantID) (provider string, configJSON []byte, err error) {
	var providerName string
	var encBlob []byte

	err = s.pg.QueryRow(ctx,
		`SELECT provider, config FROM tenant_secrets_broker_config WHERE tenant_id = $1`,
		tenant.String(),
	).Scan(&providerName, &encBlob)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, ErrNotFound
		}
		return "", nil, fmt.Errorf("tenantconfig: query tenant %s: %w", tenant, err)
	}

	plaintext, err := envelope.Decrypt(s.kek, encBlob, configAAD(tenant))
	if err != nil {
		return "", nil, fmt.Errorf("tenantconfig: decrypt config for tenant %s: %w", tenant, err)
	}
	return providerName, plaintext, nil
}

// SetRaw persists the provider name and encrypted config blob for the
// given tenant. It upserts — if a row already exists it is replaced.
// actor is stored in created_by / updated_by for audit.
func (s *Store) SetRaw(ctx context.Context, tenant auth.TenantID, provider string, configJSON []byte, actor string) error {
	if provider == "" {
		return errors.New("tenantconfig: provider must not be empty")
	}
	if len(configJSON) == 0 {
		return errors.New("tenantconfig: configJSON must not be empty")
	}
	if actor == "" {
		actor = "system"
	}

	enc, err := envelope.Encrypt(s.kek, configJSON, configAAD(tenant))
	if err != nil {
		return fmt.Errorf("tenantconfig: encrypt config for tenant %s: %w", tenant, err)
	}

	_, err = s.pg.Exec(ctx,
		`INSERT INTO tenant_secrets_broker_config
		    (tenant_id, provider, config, created_at, updated_at, created_by, updated_by)
		 VALUES ($1, $2, $3, now(), now(), $4, $4)
		 ON CONFLICT (tenant_id) DO UPDATE
		   SET provider   = EXCLUDED.provider,
		       config     = EXCLUDED.config,
		       updated_at = now(),
		       updated_by = EXCLUDED.updated_by`,
		tenant.String(), provider, enc, actor,
	)
	if err != nil {
		return fmt.Errorf("tenantconfig: upsert tenant %s: %w", tenant, err)
	}
	return nil
}

// DeleteRaw removes the broker config row for the given tenant. It is a
// no-op if no row exists.
func (s *Store) DeleteRaw(ctx context.Context, tenant auth.TenantID) error {
	_, err := s.pg.Exec(ctx,
		`DELETE FROM tenant_secrets_broker_config WHERE tenant_id = $1`,
		tenant.String(),
	)
	if err != nil {
		return fmt.Errorf("tenantconfig: delete tenant %s: %w", tenant, err)
	}
	return nil
}
