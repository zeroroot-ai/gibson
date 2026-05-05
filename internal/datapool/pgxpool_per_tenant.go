package datapool

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zero-day-ai/sdk/auth"

	pdataplane "github.com/zero-day-ai/gibson/pkg/platform/dataplane"
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

// ForTenant returns (or lazily creates) a *pgxpool.Pool connected to
// the tenant's dedicated Postgres database. The DSN comes from Vault
// via cfg.PostgresSecretsReader (broker.Resolve on infra/postgres);
// Phase 6.2 removed the legacy KEK-based fallback.
//
// Returns *NotProvisionedError if the broker is not wired, has no
// entry for this tenant, or the Postgres database does not exist.
//
// The tenantKEK argument is retained for signature stability with
// pool_impl.go callers but is no longer used by this function. Conn.KEK
// is still derived for user-secret encryption (separate concern).
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

	dsn, dbName, err := p.resolveDSN(ctx, tenant, tenantKEK)
	if err != nil {
		return nil, err
	}

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

// resolveDSN returns the per-tenant DSN + database name from Vault
// via the secrets broker. The operator writes the canonical
// PostgresCredentials JSON to tenant/<id>/infra/postgres; the broker
// returns the unwrapped bytes (SDK's secrets/providers/vault/
// provider.go:127). The daemon never derives the password locally.
//
// Spec tenant-provisioning-unification-phase2 Phase 6.2: removed the
// legacy KEK-based fallback path. Clusters that have not deployed the
// operator's Phase 3 Vault writes need to opt into the chart's
// pre-upgrade tenant-credentials-backfill Job before upgrading the
// daemon (Phase 8.5 + migration-safety NFR).
//
// tenantKEK is retained as an argument for caller-signature stability
// but is no longer used here — Conn.KEK is still derived in
// pool_impl.go for user-secret encryption (a separate concern from
// Postgres password derivation, which has moved to Vault).
func (p *pgPerTenant) resolveDSN(ctx context.Context, tenant auth.TenantID, _ []byte) (dsn, dbName string, err error) {
	if p.cfg.PostgresSecretsReader == nil {
		return "", "", &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "datapool.Config.PostgresSecretsReader not wired — daemon cannot resolve per-tenant Postgres credentials",
		}
	}
	// Push the tenant onto ctx so the broker's per-tenant routing
	// resolves to the correct path.
	ctxWithTenant := auth.WithTenant(ctx, tenant)
	raw, getErr := p.cfg.PostgresSecretsReader.Resolve(ctxWithTenant, pdataplane.VaultPathInfraPostgres)
	if getErr != nil {
		return "", "", &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: fmt.Sprintf("vault read of %s failed: %v", pdataplane.VaultPathInfraPostgres, getErr),
		}
	}
	var creds pdataplane.PostgresCredentials
	if jsonErr := json.Unmarshal(raw, &creds); jsonErr != nil {
		return "", "", fmt.Errorf("datapool: postgres: malformed PostgresCredentials JSON in Vault: %w", jsonErr)
	}
	if creds.DSN == "" {
		return "", "", &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "vault entry for infra/postgres has empty dsn field",
		}
	}
	// Append pool_max_conns query param so caller-side ParseConfig
	// honors our pool sizing without the operator needing to know
	// about it.
	sep := "&"
	if !strings.Contains(creds.DSN, "?") {
		sep = "?"
	}
	fullDSN := fmt.Sprintf("%s%spool_max_conns=%d", creds.DSN, sep, p.cfg.PoolMaxConns)
	return fullDSN, creds.Database, nil
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
