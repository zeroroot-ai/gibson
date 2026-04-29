// Package secrets provides the daemon-internal broker stack: registry,
// per-tenant broker configuration store, circuit breaker, audit writer,
// and the secrets.Service that handlers call.
//
// All public symbols in this package are safe for concurrent use.
//
// Spec: secrets-broker, Phase 7.
// Requirements: 6, 7, 9, 11.4.
package secrets

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zero-day-ai/sdk/auth"

	"github.com/zero-day-ai/gibson/internal/datapool/envelope"
)

// TenantConfigStore persists per-tenant broker configurations to the
// operator-shared (dashboard) Postgres database. Each row's config column
// is envelope-encrypted under the system-tenant KEK with AAD
// "tenant_secrets_broker_config:<tenant_id>".
//
// TenantConfigStore is safe for concurrent use.
type TenantConfigStore struct {
	pg  *pgxpool.Pool
	kek []byte // system-tenant KEK; 32 bytes
}

// NewTenantConfigStore constructs a TenantConfigStore. pg must be a pool
// connected to the operator-shared Postgres database that contains the
// tenant_secrets_broker_config table. kek must be the 32-byte system-tenant
// KEK retrieved from the daemon's KeyProvider.
func NewTenantConfigStore(pg *pgxpool.Pool, kek []byte) (*TenantConfigStore, error) {
	if pg == nil {
		return nil, errors.New("tenant config store: pg pool must not be nil")
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("tenant config store: KEK must be 32 bytes, got %d", len(kek))
	}
	return &TenantConfigStore{pg: pg, kek: kek}, nil
}

// ErrBrokerConfigNotFound is returned by GetRaw when no broker config
// row exists for the given tenant.
var ErrBrokerConfigNotFound = errors.New("secrets: broker config not found")

// configAAD returns the additional authenticated data for the given tenant's
// broker config envelope.
func configAAD(tenantID auth.TenantID) []byte {
	return []byte("tenant_secrets_broker_config:" + tenantID.String())
}

// GetRaw retrieves the decrypted provider config JSON blob for the given
// tenant. Returns ErrBrokerConfigNotFound when no row exists.
func (s *TenantConfigStore) GetRaw(ctx context.Context, tenant auth.TenantID) (provider string, configJSON []byte, err error) {
	var providerName string
	var encBlob []byte

	err = s.pg.QueryRow(ctx,
		`SELECT provider, config FROM tenant_secrets_broker_config WHERE tenant_id = $1`,
		tenant.String(),
	).Scan(&providerName, &encBlob)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, ErrBrokerConfigNotFound
		}
		return "", nil, fmt.Errorf("tenant config store: query tenant %s: %w", tenant, err)
	}

	plaintext, err := envelope.Decrypt(s.kek, encBlob, configAAD(tenant))
	if err != nil {
		return "", nil, fmt.Errorf("tenant config store: decrypt config for tenant %s: %w", tenant, err)
	}
	return providerName, plaintext, nil
}

// SetRaw persists the provider name and encrypted config blob for the given
// tenant. It upserts — if a row already exists it is replaced. The caller is
// responsible for running Probe before calling SetRaw (ConfigStore.Set does
// this). actor is stored in created_by / updated_by for audit.
func (s *TenantConfigStore) SetRaw(ctx context.Context, tenant auth.TenantID, provider string, configJSON []byte, actor string) error {
	if provider == "" {
		return errors.New("tenant config store: provider must not be empty")
	}
	if len(configJSON) == 0 {
		return errors.New("tenant config store: configJSON must not be empty")
	}
	if actor == "" {
		actor = "system"
	}

	enc, err := envelope.Encrypt(s.kek, configJSON, configAAD(tenant))
	if err != nil {
		return fmt.Errorf("tenant config store: encrypt config for tenant %s: %w", tenant, err)
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
		return fmt.Errorf("tenant config store: upsert tenant %s: %w", tenant, err)
	}
	return nil
}

// DeleteRaw removes the broker config row for the given tenant. It is a no-op
// if no row exists.
func (s *TenantConfigStore) DeleteRaw(ctx context.Context, tenant auth.TenantID) error {
	_, err := s.pg.Exec(ctx,
		`DELETE FROM tenant_secrets_broker_config WHERE tenant_id = $1`,
		tenant.String(),
	)
	if err != nil {
		return fmt.Errorf("tenant config store: delete tenant %s: %w", tenant, err)
	}
	return nil
}
