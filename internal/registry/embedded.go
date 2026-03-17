// Package registry provides service discovery and registration infrastructure for Gibson.
//
// This package implements the SDK registry interface using etcd, supporting both
// embedded (in-process) and external etcd clusters.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"github.com/zero-day-ai/sdk/registry"
)

// EmbeddedRegistry implements the Registry interface using an embedded etcd server.
//
// This provides zero-ops local development with an in-process etcd instance that
// persists data to disk. The embedded server starts automatically on the configured
// listen address and shuts down gracefully when Close() is called.
//
// Example:
//
//	cfg := registry.Config{
//	    Type:          "embedded",
//	    DataDir:       "/tmp/gibson-etcd",
//	    ListenAddress: "localhost:2379",
//	    Namespace:     "gibson",
//	    TTL:           30,
//	}
//	reg, err := NewEmbeddedRegistry(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer reg.Close()
type EmbeddedRegistry struct {
	cfg      registry.Config
	server   *embed.Etcd
	client   *clientv3.Client
	mu       sync.RWMutex
	leases   map[string]clientv3.LeaseID // instance-id -> lease-id
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewEmbeddedRegistry creates and starts an embedded etcd server.
//
// The function will:
//  1. Create the data directory if it doesn't exist
//  2. Configure and start the embedded etcd server
//  3. Wait up to 3 seconds for the server to become ready
//  4. Create an etcd client connection
//  5. Return the initialized registry
//
// Returns an error if:
//   - The data directory cannot be created
//   - The etcd server fails to start
//   - The server doesn't become ready within 3 seconds
//   - The client connection fails
func NewEmbeddedRegistry(cfg registry.Config) (*EmbeddedRegistry, error) {
	// Set defaults
	if cfg.DataDir == "" {
		cfg.DataDir = "~/.gibson/etcd-data"
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "localhost:2379"
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "gibson"
	}
	if cfg.TTL == 0 {
		cfg.TTL = 30
	}

	// Expand home directory in DataDir
	dataDir := cfg.DataDir
	if strings.HasPrefix(dataDir, "~/") {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		dataDir = strings.Replace(dataDir, "~", homeDir, 1)
	}

	// Configure embedded etcd
	etcdCfg := embed.NewConfig()
	etcdCfg.Dir = dataDir
	etcdCfg.LogLevel = "error" // Suppress verbose etcd logs

	// Parse listen address
	host, port := cfg.ListenAddress, "2379"
	if idx := strings.LastIndex(cfg.ListenAddress, ":"); idx != -1 {
		host = cfg.ListenAddress[:idx]
		port = cfg.ListenAddress[idx+1:]
	}

	// For 0.0.0.0 bind address, use 127.0.0.1 for client connections
	// The server listens on all interfaces, but clients connect via loopback
	clientHost := host
	if host == "0.0.0.0" {
		clientHost = "127.0.0.1"
	}

	// Configure client and peer URLs
	// Listen URL uses the original host (0.0.0.0 to accept all connections)
	// Client URL uses clientHost (127.0.0.1 for actual client connections)
	listenClientURLStr := fmt.Sprintf("http://%s:%s", host, port)
	clientURLStr := fmt.Sprintf("http://%s:%s", clientHost, port)
	peerURLStr := fmt.Sprintf("http://%s:%s", clientHost, "2380") // peer uses loopback

	listenClientURL, err := url.Parse(listenClientURLStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse listen client URL: %w", err)
	}
	clientURL, err := url.Parse(clientURLStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client URL: %w", err)
	}
	peerURL, err := url.Parse(peerURLStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer URL: %w", err)
	}

	// Listen on the original address (e.g., 0.0.0.0:2379)
	// Advertise and peer on loopback (e.g., 127.0.0.1:2379)
	etcdCfg.ListenClientUrls = []url.URL{*listenClientURL}
	etcdCfg.AdvertiseClientUrls = []url.URL{*clientURL}
	etcdCfg.ListenPeerUrls = []url.URL{*peerURL}
	etcdCfg.AdvertisePeerUrls = []url.URL{*peerURL}
	etcdCfg.InitialCluster = fmt.Sprintf("default=%s", peerURLStr)

	// Start embedded etcd server
	e, err := embed.StartEtcd(etcdCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to start embedded etcd: %w", err)
	}

	// Wait for server to be ready (max 3 seconds)
	select {
	case <-e.Server.ReadyNotify():
		// Server is ready
	case <-time.After(3 * time.Second):
		e.Close()
		return nil, fmt.Errorf("embedded etcd failed to start within 3 seconds")
	}

	// Create etcd client
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{clientURLStr},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		e.Close()
		return nil, fmt.Errorf("failed to create etcd client: %w", err)
	}

	reg := &EmbeddedRegistry{
		cfg:      cfg,
		server:   e,
		client:   client,
		leases:   make(map[string]clientv3.LeaseID),
		stopChan: make(chan struct{}),
	}

	return reg, nil
}

// Register adds a service instance to the registry.
//
// The service is stored at the etcd key:
//
//	/{namespace}/{kind}/{name}/{instance-id}
//
// A lease is created with the configured TTL, and a background goroutine is
// started to renew the lease every TTL/3 seconds. If the lease renewal fails
// (e.g., due to network partition or component crash), the service entry will
// be automatically removed from etcd when the lease expires.
func (r *EmbeddedRegistry) Register(ctx context.Context, info registry.ServiceInfo) error {
	// Serialize ServiceInfo to JSON
	data, err := json.Marshal(info)
	if err != nil {
		return fmt.Errorf("failed to marshal service info: %w", err)
	}

	// Create lease with TTL
	ttlSeconds := int64(r.cfg.TTL)
	lease, err := r.client.Grant(ctx, ttlSeconds)
	if err != nil {
		return fmt.Errorf("failed to create lease: %w", err)
	}

	// Build etcd key
	key := buildKey(r.cfg.Namespace, info.Kind, info.Name, info.InstanceID)

	// Put service info with lease
	_, err = r.client.Put(ctx, key, string(data), clientv3.WithLease(lease.ID))
	if err != nil {
		return fmt.Errorf("failed to register service: %w", err)
	}

	// Track lease for this instance
	r.mu.Lock()
	r.leases[info.InstanceID] = lease.ID
	r.mu.Unlock()

	// Start keepalive goroutine
	r.wg.Add(1)
	go r.keepAlive(info.InstanceID, lease.ID)

	return nil
}

// Deregister removes a service instance from the registry.
//
// This revokes the associated lease, which causes etcd to immediately delete
// the service entry. The keepalive goroutine for this instance is also stopped.
func (r *EmbeddedRegistry) Deregister(ctx context.Context, info registry.ServiceInfo) error {
	// Get lease for this instance
	r.mu.Lock()
	leaseID, exists := r.leases[info.InstanceID]
	if !exists {
		r.mu.Unlock()
		// Not registered, nothing to do
		return nil
	}
	delete(r.leases, info.InstanceID)
	r.mu.Unlock()

	// Revoke lease (this deletes the key)
	_, err := r.client.Revoke(ctx, leaseID)
	if err != nil {
		return fmt.Errorf("failed to revoke lease: %w", err)
	}

	return nil
}

// Discover finds all instances of a service by kind and name.
//
// Example:
//
//	agents, err := reg.Discover(ctx, "agent", "k8skiller")
//
// Returns an empty slice if no instances are found.
func (r *EmbeddedRegistry) Discover(ctx context.Context, kind, name string) ([]registry.ServiceInfo, error) {
	// Build prefix for this kind/name
	prefix := buildPrefix(r.cfg.Namespace, kind, name)

	// Get all keys with this prefix
	resp, err := r.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to discover services: %w", err)
	}

	// Parse results
	var services []registry.ServiceInfo
	for _, kv := range resp.Kvs {
		var info registry.ServiceInfo
		if err := json.Unmarshal(kv.Value, &info); err != nil {
			// Skip invalid entries
			continue
		}
		services = append(services, info)
	}

	return services, nil
}

// DiscoverAll finds all instances of a given kind.
//
// Example:
//
//	allAgents, err := reg.DiscoverAll(ctx, "agent")
//
// Returns an empty slice if no instances are found.
func (r *EmbeddedRegistry) DiscoverAll(ctx context.Context, kind string) ([]registry.ServiceInfo, error) {
	// Build prefix for this kind
	prefix := fmt.Sprintf("/%s/%s/", r.cfg.Namespace, kind)

	// Get all keys with this prefix
	resp, err := r.client.Get(ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("failed to discover all services: %w", err)
	}

	// Parse results
	var services []registry.ServiceInfo
	for _, kv := range resp.Kvs {
		var info registry.ServiceInfo
		if err := json.Unmarshal(kv.Value, &info); err != nil {
			// Skip invalid entries
			continue
		}
		services = append(services, info)
	}

	return services, nil
}

// Watch returns a channel that receives updates when services change.
//
// The channel emits the current list of instances whenever:
//   - A new instance registers
//   - An existing instance deregisters
//   - An instance's lease expires
//
// The initial state is sent immediately. The channel is closed when the
// context is canceled or Close() is called.
//
// Example:
//
//	ch, err := reg.Watch(ctx, "agent", "davinci")
//	for instances := range ch {
//	    log.Printf("Davinci agents: %d", len(instances))
//	}
func (r *EmbeddedRegistry) Watch(ctx context.Context, kind, name string) (<-chan []registry.ServiceInfo, error) {
	prefix := buildPrefix(r.cfg.Namespace, kind, name)
	ch := make(chan []registry.ServiceInfo, 1)

	// Send initial state
	initial, err := r.Discover(ctx, kind, name)
	if err != nil {
		close(ch)
		return ch, err
	}
	ch <- initial

	// Start watch goroutine
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer close(ch)

		watchChan := r.client.Watch(ctx, prefix, clientv3.WithPrefix())
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopChan:
				return
			case wresp, ok := <-watchChan:
				if !ok {
					return
				}
				if wresp.Err() != nil {
					return
				}

				// Fetch current state after any change
				services, err := r.Discover(ctx, kind, name)
				if err != nil {
					return
				}

				select {
				case ch <- services:
				case <-ctx.Done():
					return
				case <-r.stopChan:
					return
				}
			}
		}
	}()

	return ch, nil
}

// Client returns the underlying etcd client for direct access.
// This is used by ComponentStore to share the same etcd connection.
func (r *EmbeddedRegistry) Client() *clientv3.Client {
	return r.client
}

// Close gracefully shuts down the embedded etcd server and stops all background goroutines.
//
// After Close() is called, all other methods will fail. All active watches will
// be terminated and their channels closed.
func (r *EmbeddedRegistry) Close() error {
	// Signal all goroutines to stop
	close(r.stopChan)

	// Wait for all goroutines to finish
	r.wg.Wait()

	// Close etcd client
	if r.client != nil {
		if err := r.client.Close(); err != nil {
			return fmt.Errorf("failed to close etcd client: %w", err)
		}
	}

	// Stop embedded etcd server
	if r.server != nil {
		r.server.Close()
		select {
		case <-r.server.Server.StopNotify():
			// Server stopped
		case <-time.After(5 * time.Second):
			return fmt.Errorf("embedded etcd failed to stop within 5 seconds")
		}
	}

	return nil
}

// keepAlive maintains the lease for a registered service instance.
//
// This goroutine runs in the background and renews the lease every TTL/3 seconds.
// If renewal fails, the lease will expire and etcd will automatically remove the
// service entry.
func (r *EmbeddedRegistry) keepAlive(instanceID string, leaseID clientv3.LeaseID) {
	defer r.wg.Done()

	// Create keepalive channel
	keepAliveChan, err := r.client.KeepAlive(context.Background(), leaseID)
	if err != nil {
		// Keepalive failed, lease will expire naturally
		return
	}

	// Consume keepalive responses
	for {
		select {
		case <-r.stopChan:
			return
		case ka, ok := <-keepAliveChan:
			if !ok {
				// Keepalive channel closed, lease expired
				r.mu.Lock()
				delete(r.leases, instanceID)
				r.mu.Unlock()
				return
			}
			if ka == nil {
				// Lease revoked or expired
				r.mu.Lock()
				delete(r.leases, instanceID)
				r.mu.Unlock()
				return
			}
		}
	}
}
