package component

// plugin_registry.go implements the PluginRegistry for the daemon-side plugin
// runtime (Spec 2, plugin-runtime, Phase 7, Task 14).
//
// Design decisions:
//   - Persistent install metadata lives in Postgres (plugin_install table, migration 008).
//   - Transient runtime state (address, last_heartbeat_at, status) lives in Redis
//     at key "plugin:install:<install_id>:status" with a 90-second TTL. When the
//     key disappears the install is treated as unreachable.
//   - DispatchOne enqueues a work_type="plugin_invoke" item into the existing
//     WorkQueue and waits via WaitForResult. Round-robin across active installs is
//     implemented via an atomic per-(tenant, plugin_name) index.
//   - No background sweeper goroutine is needed: Redis TTL expiry is the sweeper.
//     ListInstalls filters to installs whose Redis status key exists and is "serving".
//
// Requirements: 9.1, 9.2, 9.3.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/sdk/auth"
)

// PluginInstallStatus is the transient runtime status of a plugin install,
// stored in Redis with a 90-second TTL.
type PluginInstallStatus string

const (
	// PluginInstallStatusServing indicates the install is healthy and accepting work.
	PluginInstallStatusServing PluginInstallStatus = "serving"
	// PluginInstallStatusUnreachable indicates the install has not heartbeated within TTL.
	PluginInstallStatusUnreachable PluginInstallStatus = "unreachable"
)

const (
	// pluginInstallTTL is the Redis TTL for transient plugin install status keys.
	// An install whose Redis key has expired is excluded from dispatch.
	pluginInstallTTL = 90 * time.Second

	// pluginWorkType is the work_type string used when enqueuing PluginInvoke work items.
	pluginWorkType = "plugin_invoke"

	// pluginDefaultDeadline is the maximum allowed per-invocation deadline.
	pluginDefaultDeadline = 60 * time.Second

	// pluginKind is the component kind string used in the WorkQueue stream key.
	pluginKind = "plugin"
)

// PluginInstall describes a registered plugin install's persistent metadata.
// This is the value persisted to the plugin_install Postgres table.
type PluginInstall struct {
	// ID is the UUID assigned by the daemon at registration time.
	ID string
	// TenantID is the tenant that owns this install.
	TenantID auth.TenantID
	// Kind is the component kind: agent | tool | plugin (gibson#662). Empty is
	// treated as "plugin" for back-compat.
	Kind string
	// Name is the component name from the manifest metadata.name field.
	Name string
	// Version is the semver version from the manifest.
	Version string
	// ManifestHash is the SHA-256 hex digest of the manifest YAML bytes.
	ManifestHash string
	// DeclaredMethods is the list of method names from manifest spec.methods.
	DeclaredMethods []string
	// ProtoDescriptorSet is the serialised FileDescriptorSet wire bytes.
	ProtoDescriptorSet []byte
	// HostID is the RFC 7638 JWK thumbprint of the registered host key.
	HostID string
	// RuntimeMode is one of: process, pod, setec.
	RuntimeMode string
	// SetecRequired is true when the manifest declares spec.policy.setec_required.
	SetecRequired bool
}

// pluginStatusPayload is the JSON shape stored in Redis under
// "plugin:install:<install_id>:status".
type pluginStatusPayload struct {
	Address         string    `json:"address"`
	LastHeartbeatAt time.Time `json:"last_heartbeat_at"`
	Status          string    `json:"status"`
}

// InstallInfo combines persistent and transient state for an active install.
// Returned by ListInstalls and Status.
type InstallInfo struct {
	// InstallID is the UUID of the plugin_install row.
	InstallID string
	// TenantID is the owning tenant.
	TenantID auth.TenantID
	// Name is the plugin name.
	Name string
	// Version is the plugin semver.
	Version string
	// DeclaredMethods is the set of declared method names.
	DeclaredMethods []string
	// Address is the transient gRPC address of the install (from Redis).
	Address string
	// LastHeartbeatAt is when the install last sent a heartbeat (from Redis).
	LastHeartbeatAt time.Time
	// Status is the transient status (from Redis): "serving" or "unreachable".
	Status PluginInstallStatus
}

// RegistryStatus is a summary of all installs of a named plugin, used for
// dashboard rendering.
type RegistryStatus struct {
	// Installs is the per-install snapshot.
	Installs []InstallInfo
}

// PluginRegistry is the interface for the daemon-side plugin install registry.
//
// All methods are tenant-scoped. The registry does not perform FGA checks —
// those are enforced upstream by ext-authz and by PluginInvokeService.
type PluginRegistry interface {
	// Register persists a new plugin install row in Postgres and creates its
	// initial Redis status key. Idempotent: if a row already exists for
	// (tenant_id, plugin_name, host_id) the row is upserted with updated fields.
	Register(ctx context.Context, install *PluginInstall) error

	// Heartbeat refreshes the Redis TTL for the install identified by installID
	// and updates last_heartbeat_at in the status payload.
	Heartbeat(ctx context.Context, installID string, address string) error

	// ListInstalls returns all installs of name for tenant whose Redis status key
	// currently exists and whose status is "serving".
	ListInstalls(ctx context.Context, tenant auth.TenantID, name string) ([]InstallInfo, error)

	// DispatchOne picks an active serving install of name for tenant (round-robin),
	// enqueues a plugin_invoke work item into the ComponentService WorkQueue, and
	// blocks until a result arrives or deadline elapses.
	//
	// payload is a marshalled PluginInvokeRequest proto (opaque bytes forwarded
	// to the plugin). The result bytes are the serialised PluginInvokeResponse
	// or an error with structured classification.
	DispatchOne(ctx context.Context, tenant auth.TenantID, name, method string, payload []byte, deadline time.Duration) ([]byte, error)

	// Status returns a RegistryStatus snapshot for dashboard rendering.
	Status(ctx context.Context, tenant auth.TenantID, name string) (RegistryStatus, error)
}

// installRoundRobin tracks per-(tenantID+pluginName) dispatch indices for
// round-robin load balancing. The zero value is valid.
type installRoundRobin struct {
	mu      sync.Mutex
	indices map[string]*atomic.Uint64
}

func newInstallRoundRobin() *installRoundRobin {
	return &installRoundRobin{
		indices: make(map[string]*atomic.Uint64),
	}
}

// next returns the next index for the given key, incrementing atomically.
func (r *installRoundRobin) next(key string) uint64 {
	r.mu.Lock()
	counter, ok := r.indices[key]
	if !ok {
		counter = new(atomic.Uint64)
		r.indices[key] = counter
	}
	r.mu.Unlock()
	return counter.Add(1) - 1 // pre-increment; return previous value
}

// postgresPluginRegistry is the production implementation of PluginRegistry.
// It stores persistent metadata in the dashboard Postgres (plugin_install table)
// and transient state in Redis.
type postgresPluginRegistry struct {
	db         *sql.DB
	redis      redis.UniversalClient
	queue      WorkQueue
	roundRobin *installRoundRobin
	logger     *slog.Logger
}

// NewPluginRegistry constructs a PluginRegistry backed by Postgres and Redis.
//
// db must point to the operator-shared (dashboard) Postgres instance containing
// the plugin_install table (migration 008). redisClient is the daemon's Redis
// client used for transient state. queue is the WorkQueue used for DispatchOne.
func NewPluginRegistry(db *sql.DB, redisClient redis.UniversalClient, queue WorkQueue, logger *slog.Logger) PluginRegistry {
	if logger == nil {
		logger = slog.Default()
	}
	return &postgresPluginRegistry{
		db:         db,
		redis:      redisClient,
		queue:      queue,
		roundRobin: newInstallRoundRobin(),
		logger:     logger.With("component", "plugin_registry"),
	}
}

// pluginStatusKey returns the Redis key for an install's transient status.
//
//	plugin:install:<install_id>:status
func pluginStatusKey(installID string) string {
	return fmt.Sprintf("plugin:install:%s:status", installID)
}

// Register implements PluginRegistry.
//
// It upserts a row in plugin_install (ON CONFLICT on the unique host constraint)
// and sets the initial Redis status payload with a 90-second TTL and status "serving".
func (r *postgresPluginRegistry) Register(ctx context.Context, install *PluginInstall) error {
	if install == nil {
		return fmt.Errorf("plugin registry register: install must not be nil")
	}
	if install.ID == "" {
		install.ID = uuid.New().String()
	}

	methodsJSON, err := json.Marshal(install.DeclaredMethods)
	if err != nil {
		return fmt.Errorf("plugin registry register: marshal declared_methods: %w", err)
	}

	// gibson#662: one install registry for every component kind. `kind`
	// discriminates agent/tool/plugin; uniqueness is per (tenant, kind, name,
	// host). Default to plugin when unset for back-compat with existing callers.
	kind := install.Kind
	if kind == "" {
		kind = "plugin"
	}

	const upsertSQL = `
INSERT INTO component_install (
    id, tenant_id, kind, component_name, version, manifest_hash,
    declared_methods, proto_descriptor_set, host_id,
    runtime_mode, setec_required, created_at, created_by
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now(),$12)
ON CONFLICT (tenant_id, kind, component_name, host_id)
DO UPDATE SET
    id                   = EXCLUDED.id,
    version              = EXCLUDED.version,
    manifest_hash        = EXCLUDED.manifest_hash,
    declared_methods     = EXCLUDED.declared_methods,
    proto_descriptor_set = EXCLUDED.proto_descriptor_set,
    runtime_mode         = EXCLUDED.runtime_mode,
    setec_required       = EXCLUDED.setec_required
RETURNING id`

	var assignedID string
	err = r.db.QueryRowContext(ctx, upsertSQL,
		install.ID,
		install.TenantID.String(),
		kind,
		install.Name,
		install.Version,
		install.ManifestHash,
		methodsJSON,
		install.ProtoDescriptorSet,
		install.HostID,
		install.RuntimeMode,
		install.SetecRequired,
		install.HostID, // created_by = host_id
	).Scan(&assignedID)
	if err != nil {
		return fmt.Errorf("component registry register: upsert component_install: %w", err)
	}
	install.ID = assignedID

	// Write initial transient status to Redis with 90-second TTL.
	payload := pluginStatusPayload{
		Address:         "",
		LastHeartbeatAt: time.Now().UTC(),
		Status:          string(PluginInstallStatusServing),
	}
	if err := r.setRedisStatus(ctx, assignedID, payload); err != nil {
		return fmt.Errorf("plugin registry register: set redis status: %w", err)
	}

	r.logger.InfoContext(ctx, "plugin install registered",
		slog.String("install_id", assignedID),
		slog.String("tenant_id", install.TenantID.String()),
		slog.String("plugin_name", install.Name),
		slog.String("version", install.Version),
		slog.String("host_id", install.HostID),
	)

	return nil
}

// Heartbeat implements PluginRegistry.
//
// It reads the current Redis status payload, updates last_heartbeat_at and
// address, and resets the 90-second TTL. If the key has expired (install
// previously unreachable) the payload is recreated with status "serving".
func (r *postgresPluginRegistry) Heartbeat(ctx context.Context, installID string, address string) error {
	if installID == "" {
		return fmt.Errorf("plugin registry heartbeat: installID must not be empty")
	}

	key := pluginStatusKey(installID)

	// Attempt to read existing payload; create fresh one if absent.
	var payload pluginStatusPayload
	data, err := r.redis.Get(ctx, key).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("plugin registry heartbeat: read redis status for %s: %w", installID, err)
	}
	if err == nil {
		if jsonErr := json.Unmarshal(data, &payload); jsonErr != nil {
			// Corrupt payload — recreate.
			payload = pluginStatusPayload{}
		}
	}

	// Update fields.
	payload.LastHeartbeatAt = time.Now().UTC()
	if address != "" {
		payload.Address = address
	}
	payload.Status = string(PluginInstallStatusServing)

	if err := r.setRedisStatus(ctx, installID, payload); err != nil {
		return fmt.Errorf("plugin registry heartbeat: update redis status: %w", err)
	}

	return nil
}

// ListInstalls implements PluginRegistry.
//
// It queries plugin_install for all rows matching (tenant_id, plugin_name),
// then checks each install's Redis status key. Only installs whose key exists
// and whose status is "serving" are returned.
func (r *postgresPluginRegistry) ListInstalls(ctx context.Context, tenant auth.TenantID, name string) ([]InstallInfo, error) {
	rows, err := r.queryInstalls(ctx, tenant, name)
	if err != nil {
		return nil, err
	}

	var active []InstallInfo
	for _, row := range rows {
		status, addr, heartbeat, ok := r.redisStatus(ctx, row.InstallID)
		if !ok || status != PluginInstallStatusServing {
			continue
		}
		row.Status = status
		row.Address = addr
		row.LastHeartbeatAt = heartbeat
		active = append(active, row)
	}
	return active, nil
}

// DispatchOne implements PluginRegistry.
//
// It selects a serving install via round-robin, enqueues a "plugin_invoke"
// WorkItem to the install's per-tenant work stream, and waits for the result.
// The payload bytes are stored verbatim in WorkItem.Payload; the result bytes
// from WorkResult.Result are returned to the caller.
func (r *postgresPluginRegistry) DispatchOne(
	ctx context.Context,
	tenant auth.TenantID,
	name, method string,
	payload []byte,
	deadline time.Duration,
) ([]byte, error) {
	installs, err := r.ListInstalls(ctx, tenant, name)
	if err != nil {
		return nil, fmt.Errorf("plugin dispatch: list installs for %s/%s: %w", tenant.String(), name, err)
	}
	if len(installs) == 0 {
		return nil, ErrPluginUnavailable
	}

	// Cap deadline.
	if deadline <= 0 || deadline > pluginDefaultDeadline {
		deadline = pluginDefaultDeadline
	}

	// Round-robin pick.
	key := tenant.String() + "/" + name
	idx := int(r.roundRobin.next(key)) % len(installs)
	install := installs[idx]

	workID := uuid.New().String()
	item := WorkItem{
		WorkID:    workID,
		WorkType:  pluginWorkType,
		Payload:   payload,
		TimeoutMs: deadline.Milliseconds(),
		Context: map[string]string{
			"method":     method,
			"install_id": install.InstallID,
		},
		CreatedAt: time.Now().UTC(),
	}

	if _, err := r.queue.Enqueue(ctx, tenant.String(), pluginKind, name, item); err != nil {
		return nil, fmt.Errorf("plugin dispatch: enqueue work for %s/%s: %w", tenant.String(), name, err)
	}

	result, err := r.queue.WaitForResult(ctx, workID, deadline)
	if err != nil {
		return nil, fmt.Errorf("plugin dispatch: wait for result %s: %w", workID, err)
	}

	if result.Error != nil {
		return nil, &PluginWorkError{
			Code:    result.Error.Code,
			Message: result.Error.Message,
		}
	}

	return result.Result, nil
}

// Status implements PluginRegistry.
//
// It returns a RegistryStatus with all installs (serving and unreachable) for
// the named plugin. Useful for dashboard rendering.
func (r *postgresPluginRegistry) Status(ctx context.Context, tenant auth.TenantID, name string) (RegistryStatus, error) {
	rows, err := r.queryInstalls(ctx, tenant, name)
	if err != nil {
		return RegistryStatus{}, err
	}

	for i := range rows {
		status, addr, heartbeat, ok := r.redisStatus(ctx, rows[i].InstallID)
		if ok {
			rows[i].Status = status
			rows[i].Address = addr
			rows[i].LastHeartbeatAt = heartbeat
		} else {
			rows[i].Status = PluginInstallStatusUnreachable
		}
	}

	return RegistryStatus{Installs: rows}, nil
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

// queryInstalls returns all plugin_install rows for (tenant_id, plugin_name)
// without filtering on Redis status. The returned InstallInfo.Status field is
// not populated (the caller enriches it from Redis).
func (r *postgresPluginRegistry) queryInstalls(ctx context.Context, tenant auth.TenantID, name string) ([]InstallInfo, error) {
	const q = `
SELECT id, tenant_id, component_name, version, declared_methods
FROM   component_install
WHERE  tenant_id      = $1
AND    component_name = $2
ORDER BY created_at`

	rows, err := r.db.QueryContext(ctx, q, tenant.String(), name)
	if err != nil {
		return nil, fmt.Errorf("plugin registry: query installs for %s/%s: %w", tenant, name, err)
	}
	defer rows.Close()

	var result []InstallInfo
	for rows.Next() {
		var info InstallInfo
		var methodsJSON []byte
		var tenantIDStr string
		if err := rows.Scan(&info.InstallID, &tenantIDStr, &info.Name, &info.Version, &methodsJSON); err != nil {
			return nil, fmt.Errorf("plugin registry: scan install row: %w", err)
		}
		tid, tidErr := auth.NewTenantID(tenantIDStr)
		if tidErr != nil {
			// Malformed row — skip rather than halting all installs.
			r.logger.WarnContext(ctx, "plugin registry: skipping install row with invalid tenant_id",
				slog.String("tenant_id", tenantIDStr),
				slog.String("error", tidErr.Error()),
			)
			continue
		}
		info.TenantID = tid
		if len(methodsJSON) > 0 {
			if err := json.Unmarshal(methodsJSON, &info.DeclaredMethods); err != nil {
				r.logger.WarnContext(ctx, "plugin registry: failed to unmarshal declared_methods",
					slog.String("install_id", info.InstallID),
					slog.String("error", err.Error()),
				)
			}
		}
		result = append(result, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("plugin registry: iterate install rows: %w", err)
	}
	return result, nil
}

// setRedisStatus serialises payload and stores it under pluginStatusKey(installID)
// with pluginInstallTTL.
func (r *postgresPluginRegistry) setRedisStatus(ctx context.Context, installID string, payload pluginStatusPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal status payload: %w", err)
	}
	return r.redis.Set(ctx, pluginStatusKey(installID), data, pluginInstallTTL).Err()
}

// redisStatus reads the transient status for installID. Returns false when the
// key is absent (expired or never written).
func (r *postgresPluginRegistry) redisStatus(ctx context.Context, installID string) (PluginInstallStatus, string, time.Time, bool) {
	data, err := r.redis.Get(ctx, pluginStatusKey(installID)).Bytes()
	if err != nil {
		return PluginInstallStatusUnreachable, "", time.Time{}, false
	}
	var payload pluginStatusPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return PluginInstallStatusUnreachable, "", time.Time{}, false
	}
	return PluginInstallStatus(payload.Status), payload.Address, payload.LastHeartbeatAt, true
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrPluginUnavailable is returned by DispatchOne when no serving installs exist.
var ErrPluginUnavailable = errors.New("plugin registry: no serving installs available")

// PluginWorkError wraps a structured error returned by a plugin install via SubmitResult.
type PluginWorkError struct {
	// Code is the structured error code from WorkError.Code.
	Code string
	// Message is the human-readable error message.
	Message string
}

func (e *PluginWorkError) Error() string {
	return fmt.Sprintf("plugin work error [%s]: %s", e.Code, e.Message)
}
