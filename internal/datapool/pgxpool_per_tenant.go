package datapool

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zero-day-ai/sdk/auth"
)

// pgSanitizeRE matches only characters that are safe in a Postgres database
// or role name. The auth package already enforces the tenant ID character set
// (lowercase letter start, [a-z0-9_-] body) but hyphens are legal in tenant
// IDs yet illegal in bare Postgres identifiers, so we additionally replace
// hyphens with underscores here.
var pgSanitizeRE = regexp.MustCompile(`[^a-z0-9_]`)

// sanitizeForPostgres converts a tenant ID string to a safe Postgres
// identifier component. Hyphens are replaced with underscores. Any character
// outside [a-z0-9_] is rejected (returns an error) to prevent injection.
func sanitizeForPostgres(tenantID string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("datapool: postgres: empty tenant ID")
	}
	// Replace hyphens with underscores (hyphens are valid in TenantID but
	// not in unquoted Postgres identifiers).
	replaced := strings.ReplaceAll(tenantID, "-", "_")
	if pgSanitizeRE.MatchString(replaced) {
		return "", fmt.Errorf("datapool: postgres: tenant ID %q contains characters unsafe for Postgres identifiers after sanitization", tenantID)
	}
	return replaced, nil
}

// pgPerTenant manages a per-tenant cache of *pgxpool.Pool. Each tenant's
// pool is connected to the tenant's dedicated Postgres database.
type pgPerTenant struct {
	mu     sync.Mutex
	pools  map[auth.TenantID]*pgxpool.Pool
	cfg    Config
	closed bool
}

func newPgPerTenant(cfg Config) *pgPerTenant {
	return &pgPerTenant{
		pools: make(map[auth.TenantID]*pgxpool.Pool),
		cfg:   cfg,
	}
}

// ForTenant returns (or lazily creates) a *pgxpool.Pool connected to the
// tenant's dedicated Postgres database.
//
// The connection string is: postgres://HOST/tenant_SANITIZED
// The role is: tenant_SANITIZED_app
// The password is derived from the first 32 hex characters of tenantKEK.
//
// Returns *NotProvisionedError if the database does not exist.
func (p *pgPerTenant) ForTenant(ctx context.Context, tenant auth.TenantID, tenantKEK []byte) (*pgxpool.Pool, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("datapool: postgres: pool is closed")
	}
	if pool, ok := p.pools[tenant]; ok {
		p.mu.Unlock()
		return pool, nil
	}
	p.mu.Unlock()

	sanitized, err := sanitizeForPostgres(tenant.String())
	if err != nil {
		return nil, err
	}

	if p.cfg.PostgresHost == "" {
		return nil, &NotProvisionedError{Tenant: tenant.String(), Reason: "postgres host not configured"}
	}

	// Derive the per-tenant role password from the KEK.
	// Use the first 32 hex characters of the KEK (16 bytes → 32 hex chars).
	// The tenant-operator creates the role with the same derivation.
	password, err := derivePostgresPassword(tenantKEK)
	if err != nil {
		return nil, fmt.Errorf("datapool: postgres: could not derive role password for tenant %s: %w", tenant, err)
	}

	dbName := "tenant_" + sanitized
	roleName := "tenant_" + sanitized + "_app"

	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s/%s?pool_max_conns=%d",
		roleName,
		password,
		p.cfg.PostgresHost,
		dbName,
		p.cfg.PoolMaxConns,
	)

	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("datapool: postgres: invalid connection string for tenant %s: %w", tenant, err)
	}

	acquireCtx, cancel := context.WithTimeout(ctx, p.cfg.AcquireTimeout)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(acquireCtx, poolCfg)
	if err != nil {
		if isPostgresDBNotExist(err, dbName) {
			return nil, &NotProvisionedError{
				Tenant: tenant.String(),
				Reason: fmt.Sprintf("Postgres database %q does not exist", dbName),
			}
		}
		return nil, fmt.Errorf("datapool: postgres: failed to create pool for tenant %s: %w", tenant, err)
	}

	// Verify connectivity (triggers a real connection, surfacing missing-DB errors).
	pingCtx, pingCancel := context.WithTimeout(ctx, p.cfg.AcquireTimeout)
	defer pingCancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		if isPostgresDBNotExist(err, dbName) {
			return nil, &NotProvisionedError{
				Tenant: tenant.String(),
				Reason: fmt.Sprintf("Postgres database %q does not exist", dbName),
			}
		}
		return nil, fmt.Errorf("datapool: postgres: ping failed for tenant %s: %w", tenant, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		pool.Close()
		return nil, fmt.Errorf("datapool: postgres: pool closed during init")
	}
	// Double-check: another goroutine may have initialized this tenant's pool
	// while we were connecting. Prefer the existing one and discard ours.
	if existing, ok := p.pools[tenant]; ok {
		pool.Close()
		return existing, nil
	}
	p.pools[tenant] = pool
	return pool, nil
}

// EvictTenant closes and removes the tenant's pool if present.
func (p *pgPerTenant) EvictTenant(tenant auth.TenantID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pool, ok := p.pools[tenant]; ok {
		pool.Close()
		delete(p.pools, tenant)
	}
}

// Close closes all tenant pools.
func (p *pgPerTenant) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for id, pool := range p.pools {
		pool.Close()
		delete(p.pools, id)
	}
}

// derivePostgresPassword derives a safe password string from the tenant KEK.
// Uses the first 32 hex characters of the KEK (first 16 raw bytes encoded as
// lowercase hex). The tenant-operator uses the same derivation when creating
// the role.
func derivePostgresPassword(kek []byte) (string, error) {
	if len(kek) < 16 {
		return "", fmt.Errorf("KEK too short to derive password")
	}
	return hex.EncodeToString(kek[:16]), nil
}

// isPostgresDBNotExist returns true if the error message indicates the target
// Postgres database does not exist. PostgreSQL error code 3D000 (invalid
// catalog name) or a matching message substring is used.
func isPostgresDBNotExist(err error, dbName string) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// pgx surfaces this as "SQLSTATE 3D000" in the error or as a message
	// containing the database name.
	return strings.Contains(msg, "3D000") ||
		strings.Contains(msg, fmt.Sprintf("database %q does not exist", dbName)) ||
		strings.Contains(msg, fmt.Sprintf(`database "%s" does not exist`, dbName))
}
