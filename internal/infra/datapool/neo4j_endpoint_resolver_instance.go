package datapool

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zeroroot-ai/sdk/auth"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
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
//	poolCfg.Neo4jResolver = datapool.NewInstanceResolver(
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
//  1. Reads the tenant's bolt URI, username, and password from the daemon's
//     secrets broker as a unified JSON payload at infra/neo4j (Vault path).
//  2. Caches results for 5 min to avoid per-RPC Vault queries.
//
// Error contracts:
//   - Vault path not found → *NotProvisionedError (credentials not yet written by operator)
//   - Vault broker unreachable → wrapped infrastructure error (NOT NotProvisionedError)
//
// Concurrency: the cache is protected by a sync.RWMutex; all methods are safe
// for concurrent use from multiple goroutines.
type instanceResolver struct {
	secrets secretsReader

	mu    sync.RWMutex
	cache map[string]instanceCacheEntry

	// Test hook — nil in production.
	onLookup func() // called once per Vault lookup (for call counting in tests)
}

// NewInstanceResolver is the exported constructor for daemon bootstrap. It
// constructs an instanceResolver backed by the daemon's existing secrets broker
// service.
//
//   - secrets: the daemon's secrets broker (typically *secrets.Service); reads
//     credentials from the per-tenant Vault namespace at runtime.
//
// Implements Neo4jEndpointResolver.
func NewInstanceResolver(secrets secretsReader) Neo4jEndpointResolver {
	return newInstanceResolver(secrets)
}

// newInstanceResolver constructs an instanceResolver.
func newInstanceResolver(svc secretsReader) *instanceResolver {
	return &instanceResolver{
		secrets: svc,
		cache:   make(map[string]instanceCacheEntry),
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

	// Slow path: read credentials from Vault broker.
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

// resolveAndCache performs the Vault broker credential read (typed
// Neo4jCredentials payload, including bolt URI) and stores the result
// in the cache. Returns NotProvisionedError when the Vault path is absent;
// other errors indicate transient infrastructure failures.
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

	return nil, &NotProvisionedError{Tenant: tenantID, Reason: "neo4j credentials not yet written to Vault"}
}

// tryVaultPayload reads the typed pdataplane.Neo4jCredentials JSON
// payload from infra/neo4j. Returns (nil, false, nil) when the payload
// is absent or incomplete so the caller can return NotProvisionedError.
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
		return nil, false, nil
	}
	if creds.BoltURI == "" || creds.Username == "" || creds.Password == "" {
		return nil, false, nil
	}
	return &Neo4jEndpoint{
		BoltURI:  creds.BoltURI,
		Username: creds.Username,
		Password: creds.Password,
		Database: "",
	}, true, nil
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
