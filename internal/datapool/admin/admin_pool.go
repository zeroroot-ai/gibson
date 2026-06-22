// Package admin provides the cross-tenant admin pool for the Gibson daemon.
//
// AdminPool is the ONLY authorised escape hatch from the per-tenant isolation
// provided by datapool.Pool. It is intended exclusively for platform-operator
// code paths: billing aggregation, fleet metrics, capacity planning, and
// cross-tenant reporting. Normal handler code must NEVER import or use this
// package — a gibsoncheck rule enforces that invariant.
//
// Every AdminConn acquisition:
//   - verifies the calling identity holds the platform_operator FGA relation
//     on system_tenant:_system
//   - emits an audit event with the calling subject, the RPC method, and a
//     timestamp
//   - increments the gibson_admin_pool_acquire_total metric
//
// Usage (platform-operator code paths in internal/admin/ only):
//
//	conn, err := adminPool.Acquire(ctx)
//	if err != nil { return err }
//	defer conn.Release()
//	err = admin.ForEachTenant(ctx, conn, lister, tenantPool,
//	    func(tenant auth.TenantID, tc *datapool.Conn) error {
//	        // use tc.Postgres, tc.Redis, tc.Neo4j, tc.Vector
//	        return nil
//	    })
//
// Spec: database-per-tenant-data-plane, Phase E, task 5.1.
// Requirements: 11.1–11.5.
package admin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	neo4jconfig "github.com/neo4j/neo4j-go-driver/v5/neo4j/config"
	redis "github.com/redis/go-redis/v9"
	pcpools "github.com/zeroroot-ai/gibson/internal/infra/pools"
	"google.golang.org/grpc"

	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/datapool"
	"github.com/zeroroot-ai/gibson/internal/datapool/vectordb"
	"github.com/zeroroot-ai/sdk/auth"
)

// ErrUnauthorizedAdmin is returned by Acquire when the calling identity does
// not hold the platform_operator FGA relation on system_tenant:_system.
var ErrUnauthorizedAdmin = errors.New("admin pool: caller does not have platform_operator relation on system_tenant:_system")

// AuditEmitter is the narrow interface required by AdminPool to emit audit
// events. The concrete implementation in production is audit.Logger or
// audit.Writer; in tests a fake is injected.
type AuditEmitter interface {
	// EmitAdminAcquire records that an AdminConn was acquired. The method
	// name should be the full gRPC method string (e.g.,
	// "/gibson.tenant.v1.TenantAdminService/AggregateUsage") or a
	// descriptive label when called outside a gRPC context.
	EmitAdminAcquire(ctx context.Context, subject, rpcMethod string)
}

// AdminPoolConfig carries the admin-credential connection strings. These are
// separate from per-tenant credentials and grant cross-database visibility.
// All fields are required when the corresponding store is in use.
type AdminPoolConfig struct {
	// PostgresDSN is the DSN for an admin Postgres role that has CONNECT
	// privilege on every tenant_* database. Example:
	//   postgres://gibson_admin:pw@postgres:5432/postgres
	PostgresDSN string

	// RedisAddr is the host:port of the Redis instance. The admin client
	// connects to db 0 (the master index DB) to enumerate tenant→db-index
	// mappings.
	RedisAddr string

	// RedisPassword is the optional AUTH password for the Redis instance.
	RedisPassword string

	// Neo4jURI is the bolt URI for Neo4j. The admin role must have cross-DB
	// read privileges.
	Neo4jURI string

	// Neo4jUser is the Neo4j admin user.
	Neo4jUser string

	// Neo4jPassword is the Neo4j admin password.
	Neo4jPassword string

	// VectorStoreAddr is the host:port of the vector store admin endpoint.
	VectorStoreAddr string
}

// AdminPool is the cross-tenant connection pool. It holds a single set of
// admin sub-clients (one per store) and uses the per-tenant datapool.Pool for
// ForEachTenant iteration.
//
// AdminPool implements datapool.AdminAcquirer so it can be wired into
// Pool.SetAdminPool.
//
// AdminPool is safe for concurrent use. Acquire is the only entry point for
// handlers in internal/admin/.
type AdminPool struct {
	pgAdmin     *pgxpool.Pool
	redisAdmin  *redis.Client
	neo4jAdmin  neo4j.DriverWithContext
	vectorAdmin vectordb.Driver

	// tenantPool is used by ForEachTenant to acquire per-tenant Conns.
	tenantPool datapool.Pool

	// fgaClient checks platform_operator relation.
	fgaClient authz.Authorizer

	// auditEmitter records every AdminConn acquisition.
	auditEmitter AuditEmitter

	logger *slog.Logger
}

// New constructs an AdminPool. tenantPool, fgaClient, and auditEmitter must
// be non-nil; nil values return an error immediately.
//
// The caller is responsible for calling Close() when the AdminPool is no
// longer needed.
func New(cfg AdminPoolConfig, tenantPool datapool.Pool, fgaClient authz.Authorizer, auditEmitter AuditEmitter, logger *slog.Logger) (*AdminPool, error) {
	if tenantPool == nil {
		return nil, fmt.Errorf("admin.New: tenantPool must not be nil")
	}
	if fgaClient == nil {
		return nil, fmt.Errorf("admin.New: fgaClient must not be nil")
	}
	if auditEmitter == nil {
		return nil, fmt.Errorf("admin.New: auditEmitter must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	initMetrics()

	ap := &AdminPool{
		tenantPool:   tenantPool,
		fgaClient:    fgaClient,
		auditEmitter: auditEmitter,
		logger:       logger.With("component", "datapool.admin"),
	}

	// Connect admin Postgres pool when a DSN is provided.
	// Apply required connection lifecycle settings via platform-clients/pools
	// (audit finding P1, zeroroot-ai/.github#101).
	if cfg.PostgresDSN != "" {
		pgPool, err := pcpools.NewPgxPool(context.Background(), cfg.PostgresDSN, pcpools.PgxPoolOptions{
			MaxConnLifetime: 1 * time.Hour,
			MaxConnIdleTime: 30 * time.Minute,
		})
		if err != nil {
			return nil, fmt.Errorf("admin.New: postgres: %w", err)
		}
		ap.pgAdmin = pgPool
	}

	// Connect admin Redis client (db 0 — master index).
	// Apply required connection lifecycle settings via platform-clients/pools.
	if cfg.RedisAddr != "" {
		ap.redisAdmin = redis.NewClient(&redis.Options{
			Addr:            cfg.RedisAddr,
			Password:        cfg.RedisPassword,
			DB:              0, // always db 0; admin code is the only code that may do this
			PoolSize:        10,
			DialTimeout:     5 * time.Second,
			ReadTimeout:     3 * time.Second,
			WriteTimeout:    3 * time.Second,
			ConnMaxLifetime: 30 * time.Minute,
		})
	}

	// Connect admin Neo4j driver when a URI is provided.
	// Apply required connection lifecycle settings via platform-clients/pools.
	if cfg.Neo4jURI != "" {
		driver, err := neo4j.NewDriverWithContext(
			cfg.Neo4jURI,
			neo4j.BasicAuth(cfg.Neo4jUser, cfg.Neo4jPassword, ""),
			func(c *neo4jconfig.Config) {
				c.MaxConnectionLifetime = 1 * time.Hour
				c.ConnectionAcquisitionTimeout = 60 * time.Second
			},
		)
		if err != nil {
			return nil, fmt.Errorf("admin.New: neo4j: %w", err)
		}
		ap.neo4jAdmin = driver
	}

	return ap, nil
}

// Acquire returns a *datapool.AdminConn for the calling platform-operator
// identity. It implements datapool.AdminAcquirer so it can be wired into
// Pool.SetAdminPool.
//
// It performs three steps before returning:
//  1. Resolves the calling identity from context via auth.IdentityFromContext.
//  2. Checks the FGA relation: user:<subject> has platform_operator on
//     system_tenant:_system. Returns ErrUnauthorizedAdmin on denial.
//  3. Emits an audit event and increments the metric.
//
// The returned *datapool.AdminConn must be released via conn.Release() after
// use. Internal/admin/ callers that need ForEachTenant should use this
// AdminConn together with the admin.ForEachTenant free function.
func (ap *AdminPool) Acquire(ctx context.Context) (*datapool.AdminConn, error) {
	// Step 1: resolve calling identity.
	identity, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("admin pool: acquire: identity not available: %w", err)
	}
	subject := identity.Subject
	if subject == "" {
		return nil, fmt.Errorf("admin pool: acquire: identity subject is empty")
	}

	// Step 2: FGA authorization check.
	fgaUser := "user:" + subject
	allowed, err := ap.fgaClient.Check(ctx, fgaUser, "platform_operator", "system_tenant:_system")
	if err != nil {
		return nil, fmt.Errorf("admin pool: acquire: FGA check failed: %w", err)
	}
	if !allowed {
		ap.logger.Warn("admin pool: access denied",
			slog.String("subject", subject),
			slog.String("relation", "platform_operator"),
			slog.String("object", "system_tenant:_system"),
		)
		return nil, ErrUnauthorizedAdmin
	}

	// Step 3: resolve RPC method from gRPC context (best-effort).
	rpcMethod := ""
	if info, ok := grpc.Method(ctx); ok {
		rpcMethod = info
	}

	// Emit audit event and metric.
	ap.auditEmitter.EmitAdminAcquire(ctx, subject, rpcMethod)
	recordAcquire(rpcMethod, subject)

	ap.logger.Info("admin pool: acquired",
		slog.String("subject", subject),
		slog.String("rpc", rpcMethod),
	)

	conn := &datapool.AdminConn{
		AdminPostgres:    ap.pgAdmin,
		AdminRedis:       ap.redisAdmin,
		AdminNeo4jDriver: ap.neo4jAdmin,
		AdminVector:      ap.vectorAdmin,
		Subject:          subject,
		RPCMethod:        rpcMethod,
	}

	return conn, nil
}

// Close shuts down the AdminPool by closing all admin sub-clients.
// It is idempotent.
func (ap *AdminPool) Close() error {
	if ap.pgAdmin != nil {
		ap.pgAdmin.Close()
	}
	if ap.redisAdmin != nil {
		_ = ap.redisAdmin.Close()
	}
	if ap.neo4jAdmin != nil {
		_ = ap.neo4jAdmin.Close(context.Background())
	}
	return nil
}

// TenantPool returns the underlying per-tenant Pool. This is exposed so that
// admin.ForEachTenant can acquire per-tenant Conns without holding a reference
// directly.
func (ap *AdminPool) TenantPool() datapool.Pool {
	return ap.tenantPool
}
