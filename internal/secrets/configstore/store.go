// Package configstore persists per-tenant broker configurations to the
// operator-shared (dashboard) Postgres database. It is the narrow seam
// that owns raw pgx access for the secrets-broker stack, isolated so the
// rest of internal/secrets/ stays free of raw store imports (per the
// gibsoncheck forbidrawstoreimports rule).
//
// Each row's config column is envelope-encrypted under the system-tenant
// KEK with AAD "tenant_secrets_broker_config:<tenant_id>".
//
// Spec: secrets-broker, Phase 7. Requirements: 6, 7, 9, 11.4.
package configstore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zero-day-ai/sdk/auth"

	"github.com/zero-day-ai/gibson/internal/datapool/envelope"
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
		return nil, errors.New("configstore: pg pool must not be nil")
	}
	if len(kek) != 32 {
		return nil, fmt.Errorf("configstore: KEK must be 32 bytes, got %d", len(kek))
	}
	return &Store{pg: pg, kek: kek}, nil
}

// ErrNotFound is returned by GetRaw when no broker config row exists for
// the given tenant.
var ErrNotFound = errors.New("configstore: broker config not found")

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
		return "", nil, fmt.Errorf("configstore: query tenant %s: %w", tenant, err)
	}

	plaintext, err := envelope.Decrypt(s.kek, encBlob, configAAD(tenant))
	if err != nil {
		return "", nil, fmt.Errorf("configstore: decrypt config for tenant %s: %w", tenant, err)
	}
	return providerName, plaintext, nil
}

// SetRaw persists the provider name and encrypted config blob for the
// given tenant. It upserts — if a row already exists it is replaced. The
// caller is responsible for running Probe before calling SetRaw
// (secrets.ConfigStore.Set does this). actor is stored in created_by /
// updated_by for audit.
func (s *Store) SetRaw(ctx context.Context, tenant auth.TenantID, provider string, configJSON []byte, actor string) error {
	if provider == "" {
		return errors.New("configstore: provider must not be empty")
	}
	if len(configJSON) == 0 {
		return errors.New("configstore: configJSON must not be empty")
	}
	if actor == "" {
		actor = "system"
	}

	enc, err := envelope.Encrypt(s.kek, configJSON, configAAD(tenant))
	if err != nil {
		return fmt.Errorf("configstore: encrypt config for tenant %s: %w", tenant, err)
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
		return fmt.Errorf("configstore: upsert tenant %s: %w", tenant, err)
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
		return fmt.Errorf("configstore: delete tenant %s: %w", tenant, err)
	}
	return nil
}
