package datapool

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/sdk/auth"
)

const (
	// DefaultAcquireTimeout is the maximum time Pool.For will wait for a
	// connection from a sub-pool before returning an error.
	DefaultAcquireTimeout = 5 * time.Second

	// DefaultPoolMaxConns is the default maximum number of Postgres
	// connections per tenant pool.
	DefaultPoolMaxConns = 10

	// DefaultIdleTTL is how long a tenant's pool may be idle (no active
	// Conn checked out, no recent For call) before the evictor tears it down.
	DefaultIdleTTL = 30 * time.Minute

	// DefaultEvictionCheckInterval is how often the background evictor
	// goroutine wakes to scan for idle tenant pools.
	DefaultEvictionCheckInterval = 5 * time.Minute
)

// Config carries tuning parameters for a Pool. All fields have sane
// defaults via DefaultConfig().
type Config struct {
	// AcquireTimeout is the maximum wait time for Pool.For to return a Conn.
	// Default: 5 s.
	AcquireTimeout time.Duration

	// PoolMaxConns is the maximum number of Postgres connections per tenant
	// pool. Default: 10.
	PoolMaxConns int32

	// IdleTTL is the idle eviction threshold. A tenant pool idle longer than
	// this (with no active Conn checked out) is closed by the evictor.
	// Default: 30 min.
	IdleTTL time.Duration

	// EvictionCheckInterval is how often the evictor goroutine runs.
	// Default: 5 min.
	EvictionCheckInterval time.Duration

	// PostgresHost is the host:port for the Postgres cluster.
	PostgresHost string

	// PostgresUser is the template for the per-tenant Postgres role.
	// The actual role name is "tenant_<sanitized>_app".
	PostgresUser string

	// RedisAddr is the host:port of the Redis instance.
	RedisAddr string

	// RedisPassword is the AUTH password for the Redis instance.
	RedisPassword string

	// Neo4jURI is the bolt URI for the Neo4j cluster.
	Neo4jURI string

	// Neo4jUser is the Neo4j user with per-database access.
	Neo4jUser string

	// Neo4jPassword is the Neo4j password.
	Neo4jPassword string

	// VectorStoreAddr is the host:port of the vector store.
	VectorStoreAddr string

	// Neo4jResolver is the per-tenant endpoint resolver used to construct
	// per-tenant Neo4j drivers. When set, Neo4jURI/Neo4jUser/Neo4jPassword are
	// ignored for session routing (they may still be set for backward compat).
	//
	// Spec: per-tenant-data-plane-completion Task 16 / Req 5.5.
	Neo4jResolver Neo4jEndpointResolver

	// PostgresDSNResolver resolves the per-tenant Postgres DSN + database
	// name for ForTenant. The daemon wires a closure that knows how to
	// produce these — typically by reading the canonical
	// PostgresCredentials payload from Vault at tenant/<id>/infra/postgres,
	// but the datapool layer is intentionally agnostic to the source.
	//
	// Layer rationale (gibson#106): the data-plane pool is the lowest
	// connection primitive. It MUST NOT reach back into upper layers
	// (secrets broker, audit chain, FGA) to resolve its own credentials —
	// any back-reference risks the recursion documented in gibson#101 +
	// gibson#105 and couples a foundational primitive to higher-level
	// abstractions. Inject a narrow, datapool-shaped resolver instead;
	// the daemon's closure adapts to whatever credential source the
	// platform happens to use (Vault today, file-mount or KMS-direct
	// tomorrow) without changing the datapool API surface.
	//
	// Required: pgPerTenant.ForTenant returns *NotProvisionedError when
	// nil so misconfiguration surfaces as a fast, named error.
	PostgresDSNResolver PostgresDSNResolver
}

// PostgresDSNResolver is the narrow interface pgPerTenant.ForTenant uses
// to obtain per-tenant Postgres connection coordinates. Implementations
// must be safe for concurrent use.
//
// Spec: gibson#106 (replaces the broker-chain-shaped PostgresSecretsReader
// interface; see file-level docstring above for layer rationale).
type PostgresDSNResolver interface {
	// ResolveDSN returns the libpq/pgx DSN and the Postgres database name
	// for tenant. The pool appends its own sizing parameters
	// (pool_max_conns, etc.) on top of the returned DSN — implementations
	// should NOT bake those in.
	ResolveDSN(ctx context.Context, tenant auth.TenantID) (dsn, dbName string, err error)
}

// PostgresDSNResolverFunc adapts a plain function to PostgresDSNResolver.
// This is the form daemon bootstrap uses to defer resolution until the
// secrets broker has finished initialising (the closure captures
// d.secretsService by reference; cf. the Neo4j FuncSecretsReader pattern
// in neo4j_endpoint_resolver_instance.go).
type PostgresDSNResolverFunc func(ctx context.Context, tenant auth.TenantID) (dsn, dbName string, err error)

// ResolveDSN implements PostgresDSNResolver.
func (f PostgresDSNResolverFunc) ResolveDSN(ctx context.Context, tenant auth.TenantID) (string, string, error) {
	return f(ctx, tenant)
}

// DefaultConfig returns a Config with all fields set to production-safe
// defaults. Override individual fields before passing to NewPool.
func DefaultConfig() Config {
	return Config{
		AcquireTimeout:        DefaultAcquireTimeout,
		PoolMaxConns:          DefaultPoolMaxConns,
		IdleTTL:               DefaultIdleTTL,
		EvictionCheckInterval: DefaultEvictionCheckInterval,
	}
}

// AdminAcquirer is the narrow interface that pool.Admin() delegates to. It
// is satisfied by *admin.AdminPool (internal/datapool/admin). The interface
// lives here (not in admin/) to avoid a circular import: admin imports
// datapool; datapool must not import admin.
//
// SetAdminPool wires the concrete implementation after construction.
type AdminAcquirer interface {
	// Acquire verifies the calling identity and returns a cross-tenant
	// AdminConn. Identical contract to admin.AdminPool.Acquire.
	Acquire(ctx context.Context) (*AdminConn, error)
}

// Pool is the single chokepoint for acquiring tenant-scoped data-plane
// connections. All four storage backends (Postgres, Redis, Neo4j, vector
// store) are accessible only through the Conn returned by For.
//
// The Pool interface is implemented by pool (pool_impl.go). It is declared as
// an interface so tests can inject fakes and so the implementation can be
// swapped without touching handler code.
type Pool interface {
	// For returns a Conn bundle bound to tenant's four storage backends plus
	// the per-tenant KEK. The Conn is lazily initialized on first call per
	// tenant and evicted after IdleTTL of inactivity.
	//
	// Errors:
	//   - *NotProvisionedError if the tenant's data-plane is not ready.
	//   - context.DeadlineExceeded if AcquireTimeout is hit during cold init.
	//   - any underlying store connection error.
	//
	// The caller MUST call conn.Release() exactly once (defer is recommended).
	For(ctx context.Context, tenant auth.TenantID) (*Conn, error)

	// Admin returns a cross-tenant AdminConn for platform-operator code paths.
	// Acquisition requires the caller to hold the platform_operator FGA
	// relation; this is enforced inside the AdminAcquirer implementation
	// (internal/datapool/admin.AdminPool).
	//
	// Wire the implementation via SetAdminPool before calling Admin.
	// Returns ErrAdminPoolNotConfigured when no AdminAcquirer has been set.
	Admin(ctx context.Context) (*AdminConn, error)

	// SetAdminPool wires the AdminAcquirer (admin.AdminPool) into the pool so
	// that Admin() can delegate to it. Must be called before Admin() is used.
	SetAdminPool(acquirer AdminAcquirer)

	// Close shuts down the pool, closing all per-tenant sub-pools and
	// stopping the background evictor. In-flight Conns are not forcibly
	// closed; callers should release them before calling Close.
	Close() error
}

// ErrAdminPoolNotConfigured is returned by Pool.Admin when no AdminAcquirer
// has been wired via SetAdminPool.
var ErrAdminPoolNotConfigured = fmt.Errorf("datapool: Admin pool not configured; call SetAdminPool first")
