package datapool

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	pcpools "github.com/zeroroot-ai/gibson/internal/infra/pools"
	"github.com/zeroroot-ai/sdk/auth"
)

// pgxPoolProductionOpts are the required connection lifecycle settings applied
// to every per-tenant pgxpool. These are enforced via platform-clients/pools
// so that the daemon uses the same validated defaults as every other platform
// service (ext-authz, tenant-operator, etc.).
//
// Values follow platform-clients/pools recommended production defaults:
//   - MaxConnLifetime: 1 h  — connections older than this are recycled.
//   - MaxConnIdleTime: 30 m — idle connections are released after 30 min.
//
// Spec: zeroroot-ai/.github#101 audit P1 (missing MaxConnLifetime).
var pgxPoolProductionOpts = pcpools.PgxPoolOptions{
	MaxConnLifetime: 1 * time.Hour,
	MaxConnIdleTime: 30 * time.Minute,
}

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
// the tenant's dedicated Postgres database. The DSN is produced by
// cfg.PostgresDSNResolver — a narrow, datapool-shaped interface the
// daemon adapts to whatever credential source the platform happens to
// use (today: Vault, via the secrets broker; see daemon.go bootstrap).
//
// Returns *NotProvisionedError if the resolver is not wired, has no
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

	// Apply required connection lifecycle settings enforced by platform-clients/pools.
	// MaxConnLifetime and MaxConnIdleTime are required fields; failing to set them
	// leaves connections open indefinitely, exhausting server-side connection slots
	// (audit finding P1, zeroroot-ai/.github#101).
	poolCfg.MaxConnLifetime = pgxPoolProductionOpts.MaxConnLifetime
	poolCfg.MaxConnIdleTime = pgxPoolProductionOpts.MaxConnIdleTime
	if p.cfg.PoolMaxConns > 0 {
		poolCfg.MaxConns = p.cfg.PoolMaxConns
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

// resolveDSN returns the per-tenant DSN + database name by delegating
// to the constructor-injected cfg.PostgresDSNResolver. The datapool
// layer is intentionally agnostic to the credential source — the
// daemon's resolver closure adapts to whatever the platform uses
// (today: Vault via the secrets broker; cf. daemon.initBrokerStack).
//
// gibson#106: this used to call into the secrets-broker chain
// directly (cfg.PostgresSecretsReader.Resolve(ctx, "infra/postgres") +
// PostgresCredentials JSON unmarshal). That was a layer violation —
// the lowest-level connection primitive reaching back into upper-layer
// abstractions, with a documented recursion path (gibson#101, mitigated
// by gibson#105). The DSN-resolver indirection breaks that coupling:
// the JSON unmarshal and broker-chain knowledge now live in the daemon
// bootstrap closure, where they belong.
//
// tenantKEK is retained as an argument for caller-signature stability
// but is no longer used here — Conn.KEK is still derived in
// pool_impl.go for user-secret encryption (a separate concern from
// Postgres password derivation, which has moved to Vault).
func (p *pgPerTenant) resolveDSN(ctx context.Context, tenant auth.TenantID, _ []byte) (dsn, dbName string, err error) {
	if p.cfg.PostgresDSNResolver == nil {
		return "", "", &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "datapool.Config.PostgresDSNResolver not wired — daemon cannot resolve per-tenant Postgres credentials",
		}
	}
	rawDSN, db, resolveErr := p.cfg.PostgresDSNResolver.ResolveDSN(ctx, tenant)
	if resolveErr != nil {
		// Resolver-side NotProvisionedError surfaces unchanged so callers
		// (e.g. mission/finding/component handlers) can map it to a
		// fast FailedPrecondition without retry. Any other error is
		// wrapped as a generic NotProvisionedError — we cannot
		// distinguish "transient infra issue" from "credentials never
		// written" at this layer without leaking the broker error
		// taxonomy upward.
		var notProv *NotProvisionedError
		if errors.As(resolveErr, &notProv) {
			return "", "", notProv
		}
		return "", "", &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: fmt.Sprintf("DSN resolver failed: %v", resolveErr),
		}
	}
	if rawDSN == "" {
		return "", "", &NotProvisionedError{
			Tenant: tenant.String(),
			Reason: "DSN resolver returned empty DSN",
		}
	}
	// Append pool_max_conns query param so caller-side ParseConfig
	// honors our pool sizing without the resolver needing to know
	// about it.
	sep := "&"
	if !strings.Contains(rawDSN, "?") {
		sep = "?"
	}
	fullDSN := fmt.Sprintf("%s%spool_max_conns=%d", rawDSN, sep, p.cfg.PoolMaxConns)
	return fullDSN, db, nil
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
