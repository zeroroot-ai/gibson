package datapool

import (
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgxpool"
	neo4j "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	redis "github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool/vectordb"
	"github.com/zeroroot-ai/sdk/auth"
)

// Conn is a tenant-bound connection bundle. It holds one client per storage
// backend, all scoped to the same tenant. The KEK field carries the
// per-tenant key encryption key derived from the master KEK; it is zeroed
// when Release is called.
//
// Callers MUST call Release exactly once after use (typically via defer).
// Further use of any Conn field after Release is a programming error and
// will produce unpredictable results.
//
// Example:
//
//	conn, err := pool.For(ctx, tenant)
//	if err != nil { return err }
//	defer conn.Release()
//	// use conn.Postgres, conn.Redis, conn.Neo4j, conn.Vector
type Conn struct {
	// Tenant is the identity this connection bundle is bound to.
	Tenant auth.TenantID

	// Postgres is a pgxpool.Pool connected to the tenant's dedicated
	// Postgres database (tenant_<sanitized_id>). The pool itself is
	// long-lived and shared across Conn instances for this tenant.
	Postgres *pgxpool.Pool

	// Redis is a *redis.Client bound to the tenant's dedicated logical DB
	// (resolved from the master index at db 0). Never points at db 0.
	Redis *redis.Client

	// Neo4j is a session bound to the tenant's dedicated Neo4j database
	// (tenant_<sanitized_id>). The session is per-Conn; callers should
	// not close it directly — Release handles that.
	Neo4j neo4j.SessionWithContext

	// Vector is a Client bound to the tenant's dedicated collection
	// (tenant_<sanitized_id>). Callers should not close it directly.
	Vector vectordb.Client

	// KEK is the 32-byte per-tenant key encryption key, derived from the
	// master KEK via HKDF-SHA256. It is held only for the lifetime of this
	// Conn and zeroed on Release. Never persist or log this value.
	KEK []byte

	// release is the internal hook called by Release to return connections
	// to their pools and update eviction tracking.
	release func()

	// released guards against double-release.
	released atomic.Bool
}

// Release returns all underlying connections to their respective pools,
// zeros the KEK, and updates eviction tracking. It is idempotent: the second
// and subsequent calls are no-ops.
//
// After Release, all fields on Conn are in an undefined state. Do not use
// them.
func (c *Conn) Release() {
	if !c.released.CompareAndSwap(false, true) {
		return // already released
	}
	// KEK zeroing is in conn_release.go.
	connRelease(c)
}

// AdminConn provides cross-tenant data access for platform-operator code
// paths. It is returned by Pool.Admin (via the wired AdminAcquirer) and
// by admin.AdminPool.Acquire directly for internal/server/admin/ callers.
//
// AdminConn acquisition requires the calling identity to hold the
// platform_operator FGA relation on system_tenant:_system. Every acquisition
// is audit-logged. Use AdminConn only inside internal/server/admin/; it must not
// appear in tenant-handler code.
//
// The admin-specific sub-clients and ForEachTenant helper live in
// internal/infra/datapool/admin/ and are populated by admin.AdminPool.Acquire.
// Callers that need ForEachTenant must use admin.AdminPool.Acquire directly
// rather than going through Pool.Admin.
type AdminConn struct {
	// AdminPostgres is the admin pgxpool.Pool with CONNECT on all tenant_* DBs.
	// May be nil if Postgres was not configured.
	AdminPostgres *pgxpool.Pool

	// AdminRedis is the admin *redis.Client pointing at db 0 (master index).
	// May be nil if Redis was not configured.
	AdminRedis *redis.Client

	// AdminNeo4jDriver is the admin Neo4j driver with cross-DB privileges.
	// May be nil if Neo4j was not configured.
	AdminNeo4jDriver neo4j.DriverWithContext

	// AdminVector is the admin vector-store driver.
	// May be nil if the vector store was not configured.
	AdminVector vectordb.Driver

	// Subject is the FGA subject that acquired this AdminConn (e.g., "platform-svc").
	Subject string

	// RPCMethod is the gRPC method that triggered the acquisition (best-effort).
	RPCMethod string

	// release is the cleanup hook (may be nil for no-op release).
	release func()

	// released guards against double-release.
	released atomic.Bool
}

// Release returns the AdminConn to the pool. Idempotent.
func (a *AdminConn) Release() {
	if !a.released.CompareAndSwap(false, true) {
		return
	}
	if a.release != nil {
		a.release()
	}
}
