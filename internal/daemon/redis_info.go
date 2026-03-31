package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/zero-day-ai/gibson/internal/observability"
)

// RedisDaemonInfo provides Redis-based daemon discovery and registration.
//
// This replaces EtcdDaemonInfo with an equivalent that stores daemon
// presence in Redis using a key with a TTL (auto-expires if daemon crashes).
// A background goroutine refreshes the TTL while the daemon is running.
//
// Key pattern: gibson:daemon:{instance_id}
// TTL: 30 seconds with automatic refresh every 10 seconds
type RedisDaemonInfo struct {
	client     goredis.UniversalClient
	logger     *observability.Logger
	instanceID string
	stopChan   chan struct{}
}

// RedisDaemonInfoEntry is the structure stored in Redis for each daemon instance.
type RedisDaemonInfoEntry struct {
	// InstanceID uniquely identifies this daemon instance (hostname-pid)
	InstanceID string `json:"instance_id"`

	// PID is the process ID of the daemon
	PID int `json:"pid"`

	// GRPCAddress is the TCP address for the daemon gRPC API
	GRPCAddress string `json:"grpc_address"`

	// Version is the Gibson version
	Version string `json:"version"`

	// StartedAt is when the daemon instance was started
	StartedAt time.Time `json:"started_at"`

	// LastSeen is refreshed by the background keepalive
	LastSeen time.Time `json:"last_seen"`

	// Hostname is the machine/pod hostname
	Hostname string `json:"hostname,omitempty"`
}

const (
	// redisDaemonKeyPrefix is the Redis key prefix for all daemon entries
	redisDaemonKeyPrefix = "gibson:daemon:"

	// redisDaemonTTL is the TTL for daemon presence keys
	redisDaemonTTL = 30 * time.Second

	// redisDaemonRefreshInterval is how often the background goroutine refreshes the TTL
	redisDaemonRefreshInterval = 10 * time.Second
)

// NewRedisDaemonInfo creates a new Redis-based daemon info manager.
func NewRedisDaemonInfo(client goredis.UniversalClient, logger *observability.Logger) *RedisDaemonInfo {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	instanceID := fmt.Sprintf("%s-%d", hostname, os.Getpid())

	return &RedisDaemonInfo{
		client:     client,
		logger:     logger,
		instanceID: instanceID,
		stopChan:   make(chan struct{}),
	}
}

// Register stores daemon info in Redis with a TTL, then starts a background
// goroutine that refreshes the TTL so the entry persists while the daemon runs.
func (r *RedisDaemonInfo) Register(ctx context.Context, info *DaemonInfo) error {
	if r.client == nil {
		return fmt.Errorf("redis client is nil")
	}

	hostname, _ := os.Hostname()
	now := time.Now()
	entry := &RedisDaemonInfoEntry{
		InstanceID:  r.instanceID,
		PID:         info.PID,
		GRPCAddress: info.GRPCAddress,
		Version:     info.Version,
		StartedAt:   now,
		LastSeen:    now,
		Hostname:    hostname,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal daemon info: %w", err)
	}

	key := r.daemonKey(r.instanceID)
	if err := r.client.Set(ctx, key, string(data), redisDaemonTTL).Err(); err != nil {
		return fmt.Errorf("failed to register daemon info in Redis: %w", err)
	}

	// Start background TTL refresh goroutine
	go r.keepAlive(key, data)

	r.logger.Info(ctx, "daemon info registered in Redis",
		"instance_id", r.instanceID,
		"key", key,
		"ttl_seconds", int(redisDaemonTTL.Seconds()),
	)

	return nil
}

// Deregister removes daemon info from Redis and stops the keepalive goroutine.
func (r *RedisDaemonInfo) Deregister(ctx context.Context) error {
	if r.client == nil {
		return fmt.Errorf("redis client is nil")
	}

	// Signal background goroutine to stop
	select {
	case <-r.stopChan:
		// already closed
	default:
		close(r.stopChan)
	}

	key := r.daemonKey(r.instanceID)
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to deregister daemon info from Redis: %w", err)
	}

	r.logger.Info(ctx, "daemon info deregistered from Redis",
		"instance_id", r.instanceID,
	)

	return nil
}

// InstanceID returns the unique instance identifier for this daemon.
func (r *RedisDaemonInfo) InstanceID() string {
	return r.instanceID
}

// daemonKey constructs the Redis key for a daemon instance.
func (r *RedisDaemonInfo) daemonKey(instanceID string) string {
	sanitized := strings.ReplaceAll(instanceID, "/", "-")
	return redisDaemonKeyPrefix + sanitized
}

// keepAlive periodically refreshes the Redis key TTL and updates LastSeen.
func (r *RedisDaemonInfo) keepAlive(key string, initialData []byte) {
	ticker := time.NewTicker(redisDaemonRefreshInterval)
	defer ticker.Stop()

	// Parse the initial data so we can update LastSeen
	var entry RedisDaemonInfoEntry
	_ = json.Unmarshal(initialData, &entry)

	for {
		select {
		case <-r.stopChan:
			r.logger.Debug(context.Background(), "stopping Redis daemon keepalive",
				"instance_id", r.instanceID,
			)
			return
		case <-ticker.C:
			ctx := context.Background()
			entry.LastSeen = time.Now()

			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}

			if err := r.client.Set(ctx, key, string(data), redisDaemonTTL).Err(); err != nil {
				r.logger.Warn(ctx, "failed to refresh daemon Redis TTL",
					"instance_id", r.instanceID,
					"error", err,
				)
			}
		}
	}
}
