package component

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	componentpb "github.com/zero-day-ai/sdk/api/gen/gibson/component/v1"
)

const (
	// defaultRegistryTTL is the default TTL for registered component keys.
	// Components must call RefreshTTL before expiry or they will be deregistered automatically.
	defaultRegistryTTL = 30 * time.Second

	// systemTenant is the reserved tenant namespace for system-level components
	// that are discoverable by all tenants (e.g., built-in tools, internal agents).
	systemTenant = "_system"
)

// SandboxResources is the Go-side mirror of componentpb.Resources carried
// inside a ComponentInfo entry for sandboxed tools.
type SandboxResources struct {
	VCPU   int32  `json:"vcpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// ComponentInfo describes a running instance of a component registered in the registry.
// Each instance is stored as a JSON-serialized value under a TTL-bound Redis key,
// providing automatic deregistration when an instance stops refreshing its heartbeat.
//
// DispatchMode and the sandboxed-dispatch fields were added under the
// gibson-tool-runner spec. Plugin/agent entries written before that spec
// serialize without these fields — new fields carry `omitempty` tags so
// round-trips remain clean. Entries discovered without a dispatch_mode are
// treated as DISPATCH_MODE_UNSPECIFIED (misconfiguration).
type ComponentInfo struct {
	Kind          string            `json:"kind"`
	Name          string            `json:"name"`
	Version       string            `json:"version"`
	InstanceID    string            `json:"instance_id"`
	TenantID      string            `json:"tenant_id"`
	Metadata      map[string]string `json:"metadata"`
	StartedAt     time.Time         `json:"started_at"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`

	// DispatchMode identifies how harness.CallToolProto should route calls
	// looked up against this entry. Zero value (UNSPECIFIED) is invalid.
	DispatchMode componentpb.DispatchMode `json:"dispatch_mode,omitempty"`

	// Sandboxed-dispatch fields — populated only when DispatchMode ==
	// DISPATCH_MODE_SANDBOXED. Plugin/agent entries leave these zero.
	Image                 string                   `json:"image,omitempty"`
	Command               []string                 `json:"command,omitempty"`
	Env                   map[string]string        `json:"env,omitempty"`
	Resources             SandboxResources         `json:"resources,omitempty"`
	DefaultTimeoutSeconds int32                    `json:"default_timeout_seconds,omitempty"`
	InputSchemaJSON       []byte                   `json:"input_schema_json,omitempty"`
	OutputProtoType       string                   `json:"output_proto_type,omitempty"`
	DefaultParseQuality   componentpb.ParseQuality `json:"default_parse_quality,omitempty"`
	Description           string                   `json:"description,omitempty"`
	Tags                  []string                 `json:"tags,omitempty"`
}

// ComponentRegistry provides service-discovery for Gibson components.
//
// Components register themselves with a short TTL and must periodically call
// RefreshTTL to signal liveness. When a component stops refreshing its key
// expires and it is automatically removed from the registry.
//
// Tenant isolation is enforced at the key level: tenant-scoped components
// are only visible to that tenant, while system components (registered under
// the reserved "_system" tenant) are visible to all tenants via Discover.
//
// Key scheme:
//
//	component:{tenant}:{kind}:{name}:{instance_id}   (tenant-scoped)
//	component:_system:{kind}:{name}:{instance_id}    (system-wide)
type ComponentRegistry interface {
	// Register creates a new instance entry for the component and returns its
	// generated instance ID. The provided ComponentInfo.InstanceID is ignored;
	// a new UUID is always generated to guarantee uniqueness.
	Register(ctx context.Context, tenant, kind, name string, info ComponentInfo) (string, error)

	// Deregister immediately removes an instance from the registry.
	// Returns ErrComponentNotFound if the instance key does not exist.
	Deregister(ctx context.Context, tenant, kind, name, instanceID string) error

	// RefreshTTL resets the TTL on an existing instance to the registry's
	// defaultTTL. Should be called by components on a heartbeat interval
	// shorter than the TTL (e.g., every 10 seconds for a 30-second TTL).
	// Returns ErrComponentNotFound if the instance key does not exist.
	RefreshTTL(ctx context.Context, tenant, kind, name, instanceID string) error

	// Discover returns all live instances matching the given tenant, kind, and name.
	// It checks the tenant namespace first, then falls back to the _system namespace,
	// combining results from both without duplicates.
	Discover(ctx context.Context, tenant, kind, name string) ([]ComponentInfo, error)

	// DiscoverAll returns all live instances for every component matching the given
	// tenant and kind, regardless of name. Results include both tenant-scoped and
	// system-scoped components.
	DiscoverAll(ctx context.Context, tenant, kind string) ([]ComponentInfo, error)

	// ListTenantComponents returns every live instance registered under the tenant,
	// across all kinds and names.
	ListTenantComponents(ctx context.Context, tenant string) ([]ComponentInfo, error)

	// DiscoverTenantOnly returns all live instances matching the given tenant, kind,
	// and name without falling back to the _system namespace. Use this when you
	// explicitly need only tenant-scoped components.
	DiscoverTenantOnly(ctx context.Context, tenant, kind, name string) ([]ComponentInfo, error)

	// DiscoverSystemOnly returns all live instances matching the given kind and name
	// from the _system namespace only. Use this when you need only system-level
	// components regardless of the calling tenant.
	DiscoverSystemOnly(ctx context.Context, kind, name string) ([]ComponentInfo, error)
}

// RedisComponentRegistry is a Redis-backed implementation of ComponentRegistry.
// Keys are stored with a TTL; instances that do not call RefreshTTL before the TTL
// expires are automatically deregistered by Redis.
//
// SCAN is used for key discovery to avoid blocking the Redis server.
type RedisComponentRegistry struct {
	client     redis.UniversalClient
	defaultTTL time.Duration
}

// NewRedisComponentRegistry creates a RedisComponentRegistry with the provided
// Redis client. Accepts any redis.UniversalClient (standalone, cluster, or sentinel).
// If ttl is zero the defaultRegistryTTL constant (30s) is used.
//
// Example:
//
//	reg := component.NewRedisComponentRegistry(redisClient, 30*time.Second)
//
//	instanceID, err := reg.Register(ctx, "acme", "agent", "scanner", component.ComponentInfo{
//	    Kind:    "agent",
//	    Name:    "scanner",
//	    Version: "1.2.0",
//	})
func NewRedisComponentRegistry(client redis.UniversalClient, ttl time.Duration) *RedisComponentRegistry {
	if ttl <= 0 {
		ttl = defaultRegistryTTL
	}
	return &RedisComponentRegistry{
		client:     client,
		defaultTTL: ttl,
	}
}

// Ensure RedisComponentRegistry satisfies ComponentRegistry at compile time.
var _ ComponentRegistry = (*RedisComponentRegistry)(nil)

// instanceKey builds the canonical Redis key for a single component instance.
// Format: component:{tenant}:{kind}:{name}:{instance_id}
func instanceKey(tenant, kind, name, instanceID string) string {
	return fmt.Sprintf("component:%s:%s:%s:%s", tenant, kind, name, instanceID)
}

// scanPattern builds the SCAN glob pattern for a component namespace.
// Passing "*" for any segment matches all values in that position.
//
// Examples:
//
//	scanPattern("acme", "agent", "scanner", "*")  -> "component:acme:agent:scanner:*"
//	scanPattern("acme", "agent", "*", "*")         -> "component:acme:agent:*:*"
//	scanPattern("acme", "*", "*", "*")             -> "component:acme:*:*:*"
func scanPattern(tenant, kind, name, instanceID string) string {
	return fmt.Sprintf("component:%s:%s:%s:%s", tenant, kind, name, instanceID)
}

// Register implements ComponentRegistry.
// A new UUID instance ID is always generated. The caller should persist the
// returned ID to enable future Deregister and RefreshTTL calls.
func (r *RedisComponentRegistry) Register(
	ctx context.Context,
	tenant, kind, name string,
	info ComponentInfo,
) (string, error) {
	instanceID := uuid.New().String()

	now := time.Now()
	info.Kind = kind
	info.Name = name
	info.TenantID = tenant
	info.InstanceID = instanceID
	info.StartedAt = now
	info.LastHeartbeat = now

	if info.Metadata == nil {
		info.Metadata = make(map[string]string)
	}

	data, err := json.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("failed to marshal component info: %w", err)
	}

	key := instanceKey(tenant, kind, name, instanceID)
	if err := r.client.Set(ctx, key, data, r.defaultTTL).Err(); err != nil {
		return "", fmt.Errorf("failed to register component %s/%s/%s: %w", tenant, kind, name, err)
	}

	return instanceID, nil
}

// Deregister implements ComponentRegistry.
func (r *RedisComponentRegistry) Deregister(
	ctx context.Context,
	tenant, kind, name, instanceID string,
) error {
	key := instanceKey(tenant, kind, name, instanceID)

	deleted, err := r.client.Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to deregister component %s/%s/%s/%s: %w",
			tenant, kind, name, instanceID, err)
	}

	if deleted == 0 {
		return ErrComponentNotFound
	}

	return nil
}

// RefreshTTL implements ComponentRegistry.
// Uses EXPIRE to reset the TTL without modifying the stored value. If the key
// no longer exists (expired or deregistered) ErrComponentNotFound is returned.
func (r *RedisComponentRegistry) RefreshTTL(
	ctx context.Context,
	tenant, kind, name, instanceID string,
) error {
	key := instanceKey(tenant, kind, name, instanceID)

	ok, err := r.client.Expire(ctx, key, r.defaultTTL).Result()
	if err != nil {
		return fmt.Errorf("failed to refresh TTL for %s/%s/%s/%s: %w",
			tenant, kind, name, instanceID, err)
	}

	if !ok {
		return ErrComponentNotFound
	}

	return nil
}

// Discover implements ComponentRegistry.
// Searches the tenant namespace first, then the _system namespace. Results
// from both namespaces are combined; duplicates are not possible because
// instance IDs are globally unique UUIDs.
func (r *RedisComponentRegistry) Discover(
	ctx context.Context,
	tenant, kind, name string,
) ([]ComponentInfo, error) {
	tenantResults, err := r.scan(ctx, scanPattern(tenant, kind, name, "*"))
	if err != nil {
		return nil, fmt.Errorf("failed to discover tenant components %s/%s/%s: %w",
			tenant, kind, name, err)
	}

	// Always include system components unless the caller is already querying the
	// system tenant directly to avoid a redundant second SCAN.
	if tenant == systemTenant {
		return tenantResults, nil
	}

	systemResults, err := r.scan(ctx, scanPattern(systemTenant, kind, name, "*"))
	if err != nil {
		return nil, fmt.Errorf("failed to discover system components %s/%s: %w",
			kind, name, err)
	}

	return append(tenantResults, systemResults...), nil
}

// DiscoverAll implements ComponentRegistry.
// Returns all live instances for the given tenant and kind across all component names,
// combined with matching system-scoped components.
func (r *RedisComponentRegistry) DiscoverAll(
	ctx context.Context,
	tenant, kind string,
) ([]ComponentInfo, error) {
	tenantResults, err := r.scan(ctx, scanPattern(tenant, kind, "*", "*"))
	if err != nil {
		return nil, fmt.Errorf("failed to discover all tenant components %s/%s: %w",
			tenant, kind, err)
	}

	if tenant == systemTenant {
		return tenantResults, nil
	}

	systemResults, err := r.scan(ctx, scanPattern(systemTenant, kind, "*", "*"))
	if err != nil {
		return nil, fmt.Errorf("failed to discover all system components %s: %w", kind, err)
	}

	return append(tenantResults, systemResults...), nil
}

// ListTenantComponents implements ComponentRegistry.
// Returns all live instances registered under the tenant, across all kinds and names.
func (r *RedisComponentRegistry) ListTenantComponents(
	ctx context.Context,
	tenant string,
) ([]ComponentInfo, error) {
	results, err := r.scan(ctx, scanPattern(tenant, "*", "*", "*"))
	if err != nil {
		return nil, fmt.Errorf("failed to list components for tenant %s: %w", tenant, err)
	}

	return results, nil
}

// DiscoverTenantOnly implements ComponentRegistry.
// Scans only the tenant namespace; never falls back to _system.
func (r *RedisComponentRegistry) DiscoverTenantOnly(
	ctx context.Context,
	tenant, kind, name string,
) ([]ComponentInfo, error) {
	results, err := r.scan(ctx, scanPattern(tenant, kind, name, "*"))
	if err != nil {
		return nil, fmt.Errorf("failed to discover tenant-only components %s/%s/%s: %w",
			tenant, kind, name, err)
	}

	return results, nil
}

// DiscoverSystemOnly implements ComponentRegistry.
// Scans only the _system namespace, ignoring any tenant-scoped components.
func (r *RedisComponentRegistry) DiscoverSystemOnly(
	ctx context.Context,
	kind, name string,
) ([]ComponentInfo, error) {
	results, err := r.scan(ctx, scanPattern(systemTenant, kind, name, "*"))
	if err != nil {
		return nil, fmt.Errorf("failed to discover system-only components %s/%s: %w",
			kind, name, err)
	}

	return results, nil
}

// scan performs a non-blocking SCAN iteration over keys matching pattern and
// fetches each matching key's value, deserializing it into a ComponentInfo.
// Keys that have expired between the SCAN and the GET are silently skipped.
func (r *RedisComponentRegistry) scan(ctx context.Context, pattern string) ([]ComponentInfo, error) {
	var results []ComponentInfo

	var cursor uint64
	for {
		keys, nextCursor, err := r.client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return nil, fmt.Errorf("SCAN failed for pattern %q: %w", pattern, err)
		}

		for _, key := range keys {
			data, err := r.client.Get(ctx, key).Bytes()
			if err != nil {
				if err == redis.Nil {
					// Key expired between SCAN and GET — skip it.
					continue
				}
				return nil, fmt.Errorf("GET failed for key %q: %w", key, err)
			}

			var info ComponentInfo
			if err := json.Unmarshal(data, &info); err != nil {
				// Corrupted data should not stop discovery; skip the entry.
				continue
			}

			results = append(results, info)
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return results, nil
}
