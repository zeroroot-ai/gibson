package datapool

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zero-day-ai/sdk/auth"

	pdataplane "github.com/zero-day-ai/gibson/pkg/platform/dataplane"
)

const (
	// instanceResolverCacheTTL is the lifetime of a cached Neo4j endpoint lookup.
	// Requirement 5.4: resolver results must be cached for 5 min to avoid per-RPC
	// registry queries.
	instanceResolverCacheTTL = 5 * time.Minute
)

// secretsReader is the narrow interface instanceResolver uses to read
// per-tenant credentials from the daemon's secrets broker. The broker
// routes to the correct per-tenant Vault namespace based on the tenant
// present in ctx (set by the SDK auth interceptor upstream of every RPC).
//
// In production this is satisfied by *secrets.Service. In tests it is
// satisfied by a lightweight fake.
//
// Design D3 (amended): credentials are stored in Vault and read through
// the broker — no filesystem mount or K8s API call in the daemon.
type secretsReader interface {
	Resolve(ctx context.Context, name string) ([]byte, error)
}

// FuncSecretsReader is a secretsReader that delegates to a function, allowing
// deferred resolution of the underlying broker. This lets the instanceResolver
// be constructed before the secrets broker is initialized — the function is
// called at RPC time, not at construction time.
//
// Usage in daemon bootstrap:
//
//	poolCfg.Neo4jResolver = datapool.NewInstanceResolver(pool,
//	    datapool.FuncSecretsReader(func(ctx context.Context, name string) ([]byte, error) {
//	        if d.secretsService == nil {
//	            return nil, fmt.Errorf("secrets broker not initialized")
//	        }
//	        return d.secretsService.Resolve(ctx, name)
//	    }),
//	)
type FuncSecretsReader func(ctx context.Context, name string) ([]byte, error)

// Resolve implements secretsReader.
func (f FuncSecretsReader) Resolve(ctx context.Context, name string) ([]byte, error) {
	return f(ctx, name)
}

// instanceCacheEntry holds a cached endpoint and its expiry time.
type instanceCacheEntry struct {
	endpoint *Neo4jEndpoint
	expiry   time.Time
}

// instanceResolver implements Neo4jEndpointResolver for the "instance" tenant
// mode. Each tenant has a dedicated Neo4j StatefulSet provisioned by the
// tenant-operator. This resolver:
//
//  1. Looks up the tenant's bolt URI in the Postgres-backed endpoint registry
//     (tenant_neo4j_endpoints table).
//  2. Reads the tenant's username and password from the daemon's secrets broker,
//     which routes to the per-tenant Vault namespace (design D3 amended).
//  3. Caches results for 5 min to avoid per-RPC Postgres queries.
//
// Error contracts:
//   - Registry row not found → *NotProvisionedError (tenant not yet provisioned)
//   - Secrets broker path not found → *NotProvisionedError (credentials not yet written)
//   - Registry Postgres unreachable → wrapped infrastructure error (NOT NotProvisionedError)
//
// Concurrency: the cache is protected by a sync.RWMutex; all methods are safe
// for concurrent use from multiple goroutines.
type instanceResolver struct {
	registry secretsBrokerReader
	secrets  secretsReader

	mu    sync.RWMutex
	cache map[string]instanceCacheEntry

	// Test hooks — nil in production.
	mockReg  registryLookup // overrides registry when set
	onLookup func()         // called once per registry lookup (for call counting in tests)
}

// secretsBrokerReader is the narrow interface used for registry lookups,
// kept separate so tests can inject a mock without a real pgxpool.Pool.
// (This alias exists for internal use; external callers use registryLookup.)
type secretsBrokerReader = *endpointRegistry

// registryLookup is the narrow interface used by instanceResolver so tests can
// inject a mock without needing a real *pgxpool.Pool.
type registryLookup interface {
	Lookup(ctx context.Context, tenantID string) (boltURI, secretName string, err error)
}

// NewInstanceResolver is the exported constructor for daemon bootstrap. It
// constructs an instanceResolver backed by the given admin Postgres pool and
// the daemon's existing secrets broker service.
//
//   - pool: admin Postgres connection pool with read access to tenant_neo4j_endpoints.
//   - secrets: the daemon's secrets broker (typically *secrets.Service); reads
//     credentials from the per-tenant Vault namespace at runtime.
//
// Implements Neo4jEndpointResolver.
func NewInstanceResolver(pool *pgxpool.Pool, secrets secretsReader) Neo4jEndpointResolver {
	return newInstanceResolver(pool, secrets)
}

// newInstanceResolver constructs an instanceResolver.
func newInstanceResolver(pool *pgxpool.Pool, svc secretsReader) *instanceResolver {
	return &instanceResolver{
		registry: newEndpointRegistry(pool),
		secrets:  svc,
		cache:    make(map[string]instanceCacheEntry),
	}
}

// Resolve returns the Neo4j endpoint for the given tenant.
// Implements Neo4jEndpointResolver.
func (r *instanceResolver) Resolve(ctx context.Context, tenant auth.TenantID) (*Neo4jEndpoint, error) {
	tenantStr := tenant.String()

	// Fast path: check cache under read lock.
	if ep := r.cachedEndpoint(tenantStr); ep != nil {
		return ep, nil
	}

	// Slow path: lookup registry then read credentials from Vault broker.
	return r.resolveAndCache(ctx, tenantStr)
}

// cachedEndpoint returns the cached endpoint if present and not expired.
// Returns nil on cache miss or expiry.
func (r *instanceResolver) cachedEndpoint(tenantID string) *Neo4jEndpoint {
	r.mu.RLock()
	entry, ok := r.cache[tenantID]
	r.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(entry.expiry) {
		// Expired — evict under write lock.
		r.mu.Lock()
		delete(r.cache, tenantID)
		r.mu.Unlock()
		return nil
	}
	return entry.endpoint
}

// lookupRegistry returns the effective registry (mock or real).
func (r *instanceResolver) lookupRegistry() registryLookup {
	if r.mockReg != nil {
		return r.mockReg
	}
	return r.registry
}

// resolveAndCache performs the Vault broker credential read (typed
// Neo4jCredentials payload, including bolt URI) and stores the result
// in the cache. Returns NotProvisionedError on known provisioning gaps;
// other errors indicate transient infrastructure failures.
//
// Spec tenant-provisioning-unification-phase2 Phase 6.3: bolt URI now
// comes from the Vault payload too, eliminating the cross-reference to
// the tenant_neo4j_endpoints Postgres registry table. The legacy
// registry-based lookup remains as a fallback when the Vault path
// returns NotFound — for clusters in mid-cutover where the operator's
// Phase 6.3 changes haven't shipped yet.
func (r *instanceResolver) resolveAndCache(ctx context.Context, tenantID string) (*Neo4jEndpoint, error) {
	if r.onLookup != nil {
		r.onLookup()
	}

	if r.secrets != nil {
		if endpoint, ok, err := r.tryVaultPayload(ctx, tenantID); err != nil {
			return nil, err
		} else if ok {
			r.cacheEndpoint(tenantID, endpoint)
			return endpoint, nil
		}
	}

	// Fallback path (parent-spec compatibility): registry lookup for
	// bolt URI + per-key Vault reads for username/password. Removable
	// once every cluster has the operator's Phase 6.3 writes flowing.
	boltURI, _, err := r.lookupRegistry().Lookup(ctx, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, &NotProvisionedError{
				Tenant: tenantID,
				Reason: "neo4j endpoint not yet registered (legacy fallback path)",
			}
		}
		return nil, fmt.Errorf("instanceResolver: registry lookup: %w", err)
	}
	username, password, err := r.readLegacyCredentials(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	endpoint := &Neo4jEndpoint{
		BoltURI:  boltURI,
		Username: username,
		Password: password,
		Database: "",
	}
	r.cacheEndpoint(tenantID, endpoint)
	return endpoint, nil
}

// tryVaultPayload reads the typed pdataplane.Neo4jCredentials JSON
// payload from infra/neo4j. Returns (nil, false, nil) when the payload
// is absent so the caller can fall back to the legacy split-key path.
// Any other error is propagated.
func (r *instanceResolver) tryVaultPayload(ctx context.Context, tenantID string) (*Neo4jEndpoint, bool, error) {
	raw, err := r.secrets.Resolve(ctx, pdataplane.VaultPathInfraNeo4j)
	if err != nil {
		if isNotFoundError(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("instanceResolver: read neo4j credentials for tenant %q: %w", tenantID, err)
	}
	var creds pdataplane.Neo4jCredentials
	if err := json.Unmarshal(raw, &creds); err != nil {
		// Malformed payload — likely an in-flight write or a legacy
		// split-key payload. Treat as fall-through so the legacy path
		// can satisfy the request; a permanent malformed payload will
		// surface there with a clearer error.
		return nil, false, nil
	}
	if creds.BoltURI == "" || creds.Username == "" || creds.Password == "" {
		// Partial payload — legacy split-key writers may have written
		// only username+password. Fall back.
		return nil, false, nil
	}
	return &Neo4jEndpoint{
		BoltURI:  creds.BoltURI,
		Username: creds.Username,
		Password: creds.Password,
		Database: "",
	}, true, nil
}

// readLegacyCredentials is the parent-spec split-key reader (kept for
// the fallback path only).
func (r *instanceResolver) readLegacyCredentials(ctx context.Context, tenantID string) (username, password string, err error) {
	if r.secrets == nil {
		return "", "", fmt.Errorf("instanceResolver: secrets broker not configured for tenant %q", tenantID)
	}
	usernameBytes, err := r.secrets.Resolve(ctx, "infra/neo4j/username")
	if err != nil {
		if isNotFoundError(err) {
			return "", "", &NotProvisionedError{
				Tenant: tenantID,
				Reason: "neo4j credentials not yet written to Vault",
			}
		}
		return "", "", fmt.Errorf("instanceResolver: read neo4j username for tenant %q: %w", tenantID, err)
	}
	passwordBytes, err := r.secrets.Resolve(ctx, "infra/neo4j/password")
	if err != nil {
		if isNotFoundError(err) {
			return "", "", &NotProvisionedError{
				Tenant: tenantID,
				Reason: "neo4j credentials not yet written to Vault",
			}
		}
		return "", "", fmt.Errorf("instanceResolver: read neo4j password for tenant %q: %w", tenantID, err)
	}
	return strings.TrimSpace(string(usernameBytes)), strings.TrimSpace(string(passwordBytes)), nil
}

// cacheEndpoint stores the resolved endpoint with TTL.
func (r *instanceResolver) cacheEndpoint(tenantID string, endpoint *Neo4jEndpoint) {
	r.mu.Lock()
	r.cache[tenantID] = instanceCacheEntry{
		endpoint: endpoint,
		expiry:   time.Now().Add(instanceResolverCacheTTL),
	}
	r.mu.Unlock()
}

// isNotFoundError returns true when the error is a gRPC NotFound status,
// which is what the secrets Service returns when the Vault path is absent.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	// google.golang.org/grpc/codes.NotFound has numeric value 5.
	// Use string matching to avoid importing grpc/status just for this check.
	msg := err.Error()
	return strings.Contains(msg, "code = NotFound") || strings.Contains(msg, "rpc error: code = NotFound")
}
