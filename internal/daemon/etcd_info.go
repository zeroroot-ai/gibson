package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/zero-day-ai/gibson/internal/observability"
)

// EtcdDaemonInfo provides etcd-based daemon discovery and registration.
//
// This replaces filesystem-based daemon.pid and daemon.json files with
// etcd entries that use leases for automatic cleanup on crash. Multiple
// daemons can run concurrently (e.g., in Kubernetes pods) with each daemon
// registering its own entry distinguished by InstanceID.
//
// Key pattern: /gibson/daemon/{instance_id}
// Lease TTL: 30 seconds with automatic keepalive
//
// Example usage:
//
//	etcdInfo := NewEtcdDaemonInfo(client, logger)
//	info := &DaemonInfo{
//	    PID:         os.Getpid(),
//	    GRPCAddress: "localhost:50002",
//	    Version:     "1.0.0",
//	}
//	if err := etcdInfo.Register(ctx, info); err != nil {
//	    log.Fatal(err)
//	}
//	defer etcdInfo.Deregister(ctx)
type EtcdDaemonInfo struct {
	client     *clientv3.Client
	logger     *observability.Logger
	namespace  string
	instanceID string
	leaseID    clientv3.LeaseID
	stopChan   chan struct{}
}

// EtcdDaemonInfoEntry is the structure stored in etcd for each daemon instance.
// It extends DaemonInfo with instance-specific fields needed for distributed coordination.
type EtcdDaemonInfoEntry struct {
	// InstanceID uniquely identifies this daemon instance (hostname-pid or UUID)
	InstanceID string `json:"instance_id"`

	// PID is the process ID of the daemon
	PID int `json:"pid"`

	// GRPCAddress is the TCP address for daemon gRPC API (e.g., "localhost:50002")
	GRPCAddress string `json:"grpc_address"`

	// HTTPAddress is the HTTP address for callbacks/webhooks (optional)
	HTTPAddress string `json:"http_address,omitempty"`

	// Version is the Gibson version that started the daemon
	Version string `json:"version"`

	// StartedAt is when the daemon instance was started
	StartedAt time.Time `json:"started_at"`

	// LastSeen is updated by keepalive heartbeats
	LastSeen time.Time `json:"last_seen"`

	// Hostname is the machine/pod hostname for debugging
	Hostname string `json:"hostname,omitempty"`
}

const (
	// DefaultDaemonLeaseTTL is the default lease TTL for daemon info entries (30 seconds)
	DefaultDaemonLeaseTTL = 30

	// DaemonKeyPrefix is the etcd key prefix for all daemon entries
	DaemonKeyPrefix = "/gibson/daemon/"
)

// NewEtcdDaemonInfo creates a new etcd-based daemon info manager.
//
// The instance ID is generated as "hostname-pid" to ensure uniqueness across
// multiple daemon processes and Kubernetes pods.
//
// Parameters:
//   - client: etcd client for storage operations
//   - logger: structured logger for diagnostics
//
// Returns:
//   - *EtcdDaemonInfo: Ready to use daemon info manager
func NewEtcdDaemonInfo(client *clientv3.Client, logger *observability.Logger) *EtcdDaemonInfo {
	// Generate instance ID from hostname and PID
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	instanceID := fmt.Sprintf("%s-%d", hostname, os.Getpid())

	return &EtcdDaemonInfo{
		client:     client,
		logger:     logger,
		namespace:  "gibson",
		instanceID: instanceID,
		stopChan:   make(chan struct{}),
	}
}

// Register stores daemon info in etcd with a lease for automatic cleanup.
//
// This method:
// 1. Creates a 30-second TTL lease
// 2. Stores daemon info at /gibson/daemon/{instance_id}
// 3. Starts a background keepalive goroutine to refresh the lease
//
// If the daemon crashes, the lease expires and etcd automatically removes the entry.
//
// Parameters:
//   - ctx: Context for the operation
//   - info: Daemon connection information to persist
//
// Returns:
//   - error: Non-nil if registration fails
func (e *EtcdDaemonInfo) Register(ctx context.Context, info *DaemonInfo) error {
	if e.client == nil {
		return fmt.Errorf("etcd client is nil")
	}

	// Create lease with 30-second TTL
	lease, err := e.client.Grant(ctx, DefaultDaemonLeaseTTL)
	if err != nil {
		return fmt.Errorf("failed to create lease: %w", err)
	}
	e.leaseID = lease.ID

	// Get hostname for debugging
	hostname, _ := os.Hostname()

	// Build etcd entry with instance-specific fields
	now := time.Now()
	entry := &EtcdDaemonInfoEntry{
		InstanceID:  e.instanceID,
		PID:         info.PID,
		GRPCAddress: info.GRPCAddress,
		HTTPAddress: "", // Reserved for future use (callback server address)
		Version:     info.Version,
		StartedAt:   now,
		LastSeen:    now,
		Hostname:    hostname,
	}

	// Serialize to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal daemon info: %w", err)
	}

	// Build etcd key
	key := e.daemonKey(e.instanceID)

	// Store with lease
	_, err = e.client.Put(ctx, key, string(data), clientv3.WithLease(lease.ID))
	if err != nil {
		// Revoke lease on failure
		e.client.Revoke(context.Background(), lease.ID)
		return fmt.Errorf("failed to register daemon info: %w", err)
	}

	// Start keepalive goroutine
	go e.keepAlive()

	e.logger.Info(ctx, "daemon info registered in etcd",
		"instance_id", e.instanceID,
		"key", key,
		"lease_id", lease.ID,
		"ttl_seconds", DefaultDaemonLeaseTTL,
	)

	return nil
}

// Deregister removes daemon info from etcd by revoking the lease.
//
// This immediately deletes the daemon entry and stops the keepalive goroutine.
// Called during graceful daemon shutdown.
//
// Parameters:
//   - ctx: Context for the operation
//
// Returns:
//   - error: Non-nil if deregistration fails
func (e *EtcdDaemonInfo) Deregister(ctx context.Context) error {
	if e.client == nil {
		return fmt.Errorf("etcd client is nil")
	}

	if e.leaseID == 0 {
		// Not registered, nothing to do
		return nil
	}

	// Stop keepalive goroutine
	close(e.stopChan)

	// Revoke lease (this deletes the key)
	_, err := e.client.Revoke(ctx, e.leaseID)
	if err != nil {
		return fmt.Errorf("failed to revoke daemon lease: %w", err)
	}

	e.logger.Info(ctx, "daemon info deregistered from etcd",
		"instance_id", e.instanceID,
		"lease_id", e.leaseID,
	)

	e.leaseID = 0
	return nil
}

// GetActive retrieves all currently registered daemon instances from etcd.
//
// This queries all keys under /gibson/daemon/ to discover running daemons.
// Useful for monitoring, debugging, and distributed coordination.
//
// Parameters:
//   - ctx: Context for the operation
//
// Returns:
//   - []*EtcdDaemonInfoEntry: List of active daemon instances
//   - error: Non-nil if query fails
func (e *EtcdDaemonInfo) GetActive(ctx context.Context) ([]*EtcdDaemonInfoEntry, error) {
	if e.client == nil {
		return nil, fmt.Errorf("etcd client is nil")
	}

	// Query all daemon entries with prefix
	resp, err := e.client.Get(ctx, DaemonKeyPrefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to query daemon entries: %w", err)
	}

	// Parse results
	entries := make([]*EtcdDaemonInfoEntry, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var entry EtcdDaemonInfoEntry
		if err := json.Unmarshal(kv.Value, &entry); err != nil {
			// Log warning but continue processing other entries
			e.logger.Warn(ctx, "failed to unmarshal daemon entry, skipping",
				"key", string(kv.Key),
				"error", err,
			)
			continue
		}
		entries = append(entries, &entry)
	}

	return entries, nil
}

// GetAny retrieves the first available daemon instance for client discovery.
//
// This is useful for clients that just need to connect to any running daemon
// without caring which specific instance. Returns nil if no daemons are running.
//
// Parameters:
//   - ctx: Context for the operation
//
// Returns:
//   - *EtcdDaemonInfoEntry: First available daemon instance, or nil if none found
//   - error: Non-nil if query fails
func (e *EtcdDaemonInfo) GetAny(ctx context.Context) (*EtcdDaemonInfoEntry, error) {
	entries, err := e.GetActive(ctx)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, nil
	}

	// Return the most recently started daemon
	// This helps with rolling updates where newer daemons should be preferred
	newest := entries[0]
	for _, entry := range entries[1:] {
		if entry.StartedAt.After(newest.StartedAt) {
			newest = entry
		}
	}

	return newest, nil
}

// GetByInstanceID retrieves a specific daemon instance by its instance ID.
//
// Parameters:
//   - ctx: Context for the operation
//   - instanceID: The unique instance identifier (e.g., "host-12345")
//
// Returns:
//   - *EtcdDaemonInfoEntry: Daemon instance info, or nil if not found
//   - error: Non-nil if query fails
func (e *EtcdDaemonInfo) GetByInstanceID(ctx context.Context, instanceID string) (*EtcdDaemonInfoEntry, error) {
	if e.client == nil {
		return nil, fmt.Errorf("etcd client is nil")
	}

	key := e.daemonKey(instanceID)

	resp, err := e.client.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get daemon entry: %w", err)
	}

	if len(resp.Kvs) == 0 {
		return nil, nil
	}

	var entry EtcdDaemonInfoEntry
	if err := json.Unmarshal(resp.Kvs[0].Value, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal daemon entry: %w", err)
	}

	return &entry, nil
}

// keepAlive maintains the lease for the registered daemon instance.
//
// This goroutine runs in the background and automatically refreshes the lease
// to prevent it from expiring. If the daemon crashes, the goroutine stops and
// the lease expires, causing etcd to automatically remove the daemon entry.
//
// The keepalive channel is consumed in a loop until the daemon is deregistered
// or the lease is revoked.
func (e *EtcdDaemonInfo) keepAlive() {
	// Create keepalive channel
	keepAliveChan, err := e.client.KeepAlive(context.Background(), e.leaseID)
	if err != nil {
		e.logger.Error(context.Background(), "failed to create keepalive channel",
			"error", err,
			"lease_id", e.leaseID,
		)
		return
	}

	// Consume keepalive responses
	for {
		select {
		case <-e.stopChan:
			e.logger.Debug(context.Background(), "stopping keepalive goroutine",
				"instance_id", e.instanceID,
			)
			return
		case ka, ok := <-keepAliveChan:
			if !ok {
				e.logger.Warn(context.Background(), "keepalive channel closed, lease expired",
					"instance_id", e.instanceID,
					"lease_id", e.leaseID,
				)
				return
			}
			if ka == nil {
				e.logger.Warn(context.Background(), "lease revoked or expired",
					"instance_id", e.instanceID,
					"lease_id", e.leaseID,
				)
				return
			}
			// Update LastSeen timestamp on successful keepalive
			e.updateLastSeen()
		}
	}
}

// updateLastSeen updates the LastSeen timestamp in etcd on each keepalive.
//
// This provides a heartbeat mechanism that shows when the daemon last
// successfully renewed its lease. Useful for monitoring and debugging.
func (e *EtcdDaemonInfo) updateLastSeen() {
	ctx := context.Background()

	// Get current entry
	key := e.daemonKey(e.instanceID)
	resp, err := e.client.Get(ctx, key)
	if err != nil || len(resp.Kvs) == 0 {
		return
	}

	// Unmarshal current entry
	var entry EtcdDaemonInfoEntry
	if err := json.Unmarshal(resp.Kvs[0].Value, &entry); err != nil {
		return
	}

	// Update LastSeen
	entry.LastSeen = time.Now()

	// Marshal and update
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	// Update with same lease
	_, err = e.client.Put(ctx, key, string(data), clientv3.WithLease(e.leaseID))
	if err != nil {
		e.logger.Debug(ctx, "failed to update last_seen timestamp",
			"error", err,
			"instance_id", e.instanceID,
		)
	}
}

// daemonKey constructs the etcd key for a daemon instance.
// Format: /gibson/daemon/{instance_id}
func (e *EtcdDaemonInfo) daemonKey(instanceID string) string {
	// Sanitize instance ID to prevent path traversal
	sanitized := strings.ReplaceAll(instanceID, "/", "-")
	return DaemonKeyPrefix + sanitized
}

// InstanceID returns the unique instance identifier for this daemon.
func (e *EtcdDaemonInfo) InstanceID() string {
	return e.instanceID
}
