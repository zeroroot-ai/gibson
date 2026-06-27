// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"fmt"
	"strings"

	"github.com/redis/go-redis/v9"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"

	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
)

// RedisVSSConfig holds configuration for the Redis VSS provisioner.
type RedisVSSConfig struct {
	// Addr is the Redis server address (host:port). Required.
	Addr string

	// Password is the Redis auth password. Empty for unauthenticated clusters.
	Password string

	// VectorDim is the HNSW embedding dimension. Defaults to 1536 (OpenAI
	// text-embedding-3-small).
	VectorDim int

	// VaultClient writes the per-tenant RediSearch index name to
	// tenant/<id>/infra/vector so the daemon can resolve it via the secrets
	// broker. May be nil (dev/test — Vault write is skipped).
	VaultClient vaultadmin.AdminClient
}

type redisVSSProvisioner struct {
	cfg    RedisVSSConfig
	client *redis.Client
}

// NewRedisVSSProvisioner creates a Redis VSS provisioner. The provisioner
// connects to the same Redis server as the Redis data-plane step
// (DATAPLANE_REDIS_ADDR). VectorDim defaults to 1536 when zero or negative.
func NewRedisVSSProvisioner(cfg RedisVSSConfig) (*redisVSSProvisioner, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("dataplane/vector: Addr is required")
	}
	if cfg.VectorDim <= 0 {
		cfg.VectorDim = 1536
	}
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       0,
	})
	return &redisVSSProvisioner{cfg: cfg, client: client}, nil
}

// Close releases the underlying Redis connection.
func (p *redisVSSProvisioner) Close() error {
	return p.client.Close()
}

// vssIndexName returns the FT index name for the tenant:
// "vector_idx:tenant_<underscore>".
func vssIndexName(tenantID string) (string, error) {
	dbName, err := tenantDBName(tenantID)
	if err != nil {
		return "", err
	}
	return "vector_idx:" + dbName, nil
}

// vssKeyPrefix returns the hash key prefix used in the FT.CREATE PREFIX clause:
// "vec:tenant_<underscore>:".
func vssKeyPrefix(tenantID string) (string, error) {
	dbName, err := tenantDBName(tenantID)
	if err != nil {
		return "", err
	}
	return "vec:" + dbName + ":", nil
}

// Provision creates the per-tenant RediSearch HNSW index. Idempotent: if the
// index already exists and is healthy, Provision returns nil without
// re-writing the Vault entry (it was already written on the prior attempt).
func (p *redisVSSProvisioner) Provision(ctx context.Context, tenantID string) error {
	idxName, err := vssIndexName(tenantID)
	if err != nil {
		return err
	}
	kp, err := vssKeyPrefix(tenantID)
	if err != nil {
		return err
	}

	// FT.CREATE <index>
	//   ON HASH PREFIX 1 <prefix>
	//   SCHEMA embedding VECTOR HNSW 6
	//     DIM <dim> DISTANCE_METRIC COSINE TYPE FLOAT32
	createErr := p.client.Do(ctx,
		"FT.CREATE", idxName,
		"ON", "HASH",
		"PREFIX", "1", kp,
		"SCHEMA", "embedding", "VECTOR", "HNSW", "6",
		"DIM", fmt.Sprintf("%d", p.cfg.VectorDim),
		"DISTANCE_METRIC", "COSINE",
		"TYPE", "FLOAT32",
	).Err()

	if createErr != nil {
		// RediSearch returns "Index already exists" when the index was created
		// in a prior reconcile loop. Confirm with FT.INFO and treat as success
		// so the saga does not roll back a live index.
		if strings.Contains(createErr.Error(), "already exists") ||
			strings.Contains(createErr.Error(), "Index already exists") {
			if infoErr := p.client.Do(ctx, "FT.INFO", idxName).Err(); infoErr != nil {
				return fmt.Errorf(
					"dataplane/vector: FT.CREATE returned already-exists but FT.INFO failed: %w",
					infoErr,
				)
			}
			// Already provisioned — skip Vault write (done on prior attempt).
			return nil
		}
		return fmt.Errorf("dataplane/vector: FT.CREATE %s: %w", idxName, createErr)
	}

	// Write index name to Vault so the daemon can resolve it via the
	// secrets broker without needing direct operator config access.
	if p.cfg.VaultClient != nil {
		creds := pdataplane.VectorCredentials{IndexName: idxName}
		if err := p.cfg.VaultClient.WriteInfraVector(ctx, tenantID, creds); err != nil {
			return fmt.Errorf("dataplane/vector: write credentials to Vault: %w", err)
		}
	}
	return nil
}

// Deprovision deletes the per-tenant RediSearch index and all its documents
// (FT.DROPINDEX ... DD). Idempotent: "no such index" is treated as success.
func (p *redisVSSProvisioner) Deprovision(ctx context.Context, tenantID string) error {
	idxName, err := vssIndexName(tenantID)
	if err != nil {
		return err
	}
	// FT.DROPINDEX <index> DD deletes indexed documents together with the index.
	if err := p.client.Do(ctx, "FT.DROPINDEX", idxName, "DD").Err(); err != nil {
		if strings.Contains(err.Error(), "no such index") ||
			strings.Contains(err.Error(), "Unknown Index") {
			return nil // Already gone — idempotent.
		}
		return fmt.Errorf("dataplane/vector: FT.DROPINDEX %s: %w", idxName, err)
	}
	return nil
}
