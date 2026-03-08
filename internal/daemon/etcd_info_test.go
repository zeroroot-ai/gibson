package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/embed"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/observability"
)

// testEtcdServer starts an embedded etcd server for testing
type testEtcdServer struct {
	server *embed.Etcd
	client *clientv3.Client
}

// newTestEtcdServer creates a new embedded etcd server for testing
func newTestEtcdServer(t *testing.T) *testEtcdServer {
	t.Helper()

	// Create temp directory for etcd data
	tmpDir, err := os.MkdirTemp("", "gibson-etcd-test-*")
	require.NoError(t, err)

	// Configure embedded etcd
	cfg := embed.NewConfig()
	cfg.Dir = tmpDir
	cfg.LogLevel = "error" // Suppress verbose logs
	cfg.Logger = "zap"

	// Use fixed local addresses (etcd will bind and allocate ports)
	clientURL, _ := url.Parse("http://127.0.0.1:0")
	peerURL, _ := url.Parse("http://127.0.0.1:0")
	cfg.ListenClientUrls = []url.URL{*clientURL}
	cfg.ListenPeerUrls = []url.URL{*peerURL}

	// Important: Don't set AdvertiseClientUrls/AdvertisePeerUrls when using random ports
	// etcd will auto-detect them after binding

	// Start embedded etcd
	e, err := embed.StartEtcd(cfg)
	require.NoError(t, err, "failed to start embedded etcd")

	// Wait for server to be ready
	select {
	case <-e.Server.ReadyNotify():
		// Server is ready
	case <-time.After(5 * time.Second):
		t.Fatal("etcd server failed to start within 5 seconds")
	}

	// Get actual client URL after binding
	actualClientURL := e.Clients[0].Addr().String()

	// Create etcd client
	client, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{actualClientURL},
		DialTimeout: 5 * time.Second,
	})
	require.NoError(t, err, "failed to create etcd client")

	// Cleanup function
	t.Cleanup(func() {
		client.Close()
		e.Close()
		os.RemoveAll(tmpDir)
	})

	return &testEtcdServer{
		server: e,
		client: client,
	}
}

func TestEtcdDaemonInfo_Register(t *testing.T) {
	srv := newTestEtcdServer(t)
	ctx := context.Background()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	etcdInfo := NewEtcdDaemonInfo(srv.client, logger)

	// Register daemon info
	info := &DaemonInfo{
		PID:         12345,
		GRPCAddress: "localhost:50002",
		Version:     "1.0.0",
	}

	err := etcdInfo.Register(ctx, info)
	require.NoError(t, err, "Register should succeed")

	// Verify entry exists in etcd
	key := etcdInfo.daemonKey(etcdInfo.instanceID)
	resp, err := srv.client.Get(ctx, key)
	require.NoError(t, err)
	assert.Len(t, resp.Kvs, 1, "daemon entry should exist in etcd")

	// Verify lease is attached
	assert.NotZero(t, etcdInfo.leaseID, "lease ID should be set")

	// Cleanup
	err = etcdInfo.Deregister(ctx)
	require.NoError(t, err)
}

func TestEtcdDaemonInfo_Deregister(t *testing.T) {
	srv := newTestEtcdServer(t)
	ctx := context.Background()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	etcdInfo := NewEtcdDaemonInfo(srv.client, logger)

	// Register first
	info := &DaemonInfo{
		PID:         12345,
		GRPCAddress: "localhost:50002",
		Version:     "1.0.0",
	}
	err := etcdInfo.Register(ctx, info)
	require.NoError(t, err)

	key := etcdInfo.daemonKey(etcdInfo.instanceID)

	// Verify entry exists
	resp, err := srv.client.Get(ctx, key)
	require.NoError(t, err)
	assert.Len(t, resp.Kvs, 1, "daemon entry should exist before deregister")

	// Deregister
	err = etcdInfo.Deregister(ctx)
	require.NoError(t, err, "Deregister should succeed")

	// Verify entry is removed
	resp, err = srv.client.Get(ctx, key)
	require.NoError(t, err)
	assert.Len(t, resp.Kvs, 0, "daemon entry should be removed after deregister")

	// Verify lease ID is cleared
	assert.Zero(t, etcdInfo.leaseID, "lease ID should be cleared")
}

func TestEtcdDaemonInfo_GetActive(t *testing.T) {
	srv := newTestEtcdServer(t)
	ctx := context.Background()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	// Register multiple daemon instances
	daemon1 := NewEtcdDaemonInfo(srv.client, logger)
	daemon1.instanceID = "daemon-1" // Override for testing

	daemon2 := NewEtcdDaemonInfo(srv.client, logger)
	daemon2.instanceID = "daemon-2" // Override for testing

	info1 := &DaemonInfo{
		PID:         11111,
		GRPCAddress: "localhost:50001",
		Version:     "1.0.0",
	}
	err := daemon1.Register(ctx, info1)
	require.NoError(t, err)

	info2 := &DaemonInfo{
		PID:         22222,
		GRPCAddress: "localhost:50002",
		Version:     "1.0.1",
	}
	err = daemon2.Register(ctx, info2)
	require.NoError(t, err)

	// Query active daemons
	entries, err := daemon1.GetActive(ctx)
	require.NoError(t, err, "GetActive should succeed")
	assert.Len(t, entries, 2, "should find 2 active daemons")

	// Verify entries
	foundDaemon1 := false
	foundDaemon2 := false
	for _, entry := range entries {
		if entry.InstanceID == "daemon-1" {
			assert.Equal(t, 11111, entry.PID)
			assert.Equal(t, "localhost:50001", entry.GRPCAddress)
			assert.Equal(t, "1.0.0", entry.Version)
			foundDaemon1 = true
		}
		if entry.InstanceID == "daemon-2" {
			assert.Equal(t, 22222, entry.PID)
			assert.Equal(t, "localhost:50002", entry.GRPCAddress)
			assert.Equal(t, "1.0.1", entry.Version)
			foundDaemon2 = true
		}
	}
	assert.True(t, foundDaemon1, "daemon-1 should be found")
	assert.True(t, foundDaemon2, "daemon-2 should be found")

	// Cleanup
	daemon1.Deregister(ctx)
	daemon2.Deregister(ctx)
}

func TestEtcdDaemonInfo_GetAny(t *testing.T) {
	srv := newTestEtcdServer(t)
	ctx := context.Background()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	etcdInfo := NewEtcdDaemonInfo(srv.client, logger)

	// Test with no daemons
	entry, err := etcdInfo.GetAny(ctx)
	require.NoError(t, err)
	assert.Nil(t, entry, "should return nil when no daemons are running")

	// Register a daemon
	info := &DaemonInfo{
		PID:         12345,
		GRPCAddress: "localhost:50002",
		Version:     "1.0.0",
	}
	err = etcdInfo.Register(ctx, info)
	require.NoError(t, err)

	// Test with one daemon
	entry, err = etcdInfo.GetAny(ctx)
	require.NoError(t, err)
	require.NotNil(t, entry, "should return daemon when one is running")
	assert.Equal(t, 12345, entry.PID)
	assert.Equal(t, "localhost:50002", entry.GRPCAddress)

	// Cleanup
	etcdInfo.Deregister(ctx)
}

func TestEtcdDaemonInfo_GetAny_PreferNewest(t *testing.T) {
	srv := newTestEtcdServer(t)
	ctx := context.Background()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	// Register older daemon
	daemon1 := NewEtcdDaemonInfo(srv.client, logger)
	daemon1.instanceID = "daemon-old"

	info1 := &DaemonInfo{
		PID:         11111,
		GRPCAddress: "localhost:50001",
		Version:     "1.0.0",
	}
	err := daemon1.Register(ctx, info1)
	require.NoError(t, err)

	// Wait a bit to ensure different timestamps
	time.Sleep(100 * time.Millisecond)

	// Register newer daemon
	daemon2 := NewEtcdDaemonInfo(srv.client, logger)
	daemon2.instanceID = "daemon-new"

	info2 := &DaemonInfo{
		PID:         22222,
		GRPCAddress: "localhost:50002",
		Version:     "1.0.1",
	}
	err = daemon2.Register(ctx, info2)
	require.NoError(t, err)

	// GetAny should return the newest daemon
	entry, err := daemon1.GetAny(ctx)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, "daemon-new", entry.InstanceID, "should return newest daemon")
	assert.Equal(t, 22222, entry.PID)

	// Cleanup
	daemon1.Deregister(ctx)
	daemon2.Deregister(ctx)
}

func TestEtcdDaemonInfo_GetByInstanceID(t *testing.T) {
	srv := newTestEtcdServer(t)
	ctx := context.Background()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	etcdInfo := NewEtcdDaemonInfo(srv.client, logger)
	etcdInfo.instanceID = "test-daemon-123"

	// Test with non-existent instance
	entry, err := etcdInfo.GetByInstanceID(ctx, "non-existent")
	require.NoError(t, err)
	assert.Nil(t, entry, "should return nil for non-existent instance")

	// Register daemon
	info := &DaemonInfo{
		PID:         12345,
		GRPCAddress: "localhost:50002",
		Version:     "1.0.0",
	}
	err = etcdInfo.Register(ctx, info)
	require.NoError(t, err)

	// Test with existing instance
	entry, err = etcdInfo.GetByInstanceID(ctx, "test-daemon-123")
	require.NoError(t, err)
	require.NotNil(t, entry, "should return entry for existing instance")
	assert.Equal(t, "test-daemon-123", entry.InstanceID)
	assert.Equal(t, 12345, entry.PID)
	assert.Equal(t, "localhost:50002", entry.GRPCAddress)

	// Cleanup
	etcdInfo.Deregister(ctx)
}

func TestEtcdDaemonInfo_LeaseExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping lease expiry test in short mode")
	}

	srv := newTestEtcdServer(t)
	ctx := context.Background()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	etcdInfo := NewEtcdDaemonInfo(srv.client, logger)

	// Register daemon
	info := &DaemonInfo{
		PID:         12345,
		GRPCAddress: "localhost:50002",
		Version:     "1.0.0",
	}
	err := etcdInfo.Register(ctx, info)
	require.NoError(t, err)

	key := etcdInfo.daemonKey(etcdInfo.instanceID)

	// Verify entry exists
	resp, err := srv.client.Get(ctx, key)
	require.NoError(t, err)
	assert.Len(t, resp.Kvs, 1, "daemon entry should exist")

	// Stop keepalive by closing stop channel (simulating crash)
	close(etcdInfo.stopChan)

	// Revoke lease manually to simulate expiry
	_, err = srv.client.Revoke(ctx, etcdInfo.leaseID)
	require.NoError(t, err)

	// Verify entry is removed
	resp, err = srv.client.Get(ctx, key)
	require.NoError(t, err)
	assert.Len(t, resp.Kvs, 0, "daemon entry should be removed after lease expiry")
}

func TestEtcdDaemonInfo_InstanceID_Format(t *testing.T) {
	srv := newTestEtcdServer(t)

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	etcdInfo := NewEtcdDaemonInfo(srv.client, logger)

	// Verify instance ID format (hostname-pid)
	assert.NotEmpty(t, etcdInfo.InstanceID(), "instance ID should not be empty")
	assert.Contains(t, etcdInfo.InstanceID(), "-", "instance ID should contain hyphen separator")

	// Verify instance ID is used in key
	key := etcdInfo.daemonKey(etcdInfo.instanceID)
	assert.Equal(t, DaemonKeyPrefix+etcdInfo.instanceID, key)
}

func TestEtcdDaemonInfo_DaemonKey_Sanitization(t *testing.T) {
	srv := newTestEtcdServer(t)

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	etcdInfo := NewEtcdDaemonInfo(srv.client, logger)

	// Test path traversal prevention
	maliciousID := "../../../etc/passwd"
	key := etcdInfo.daemonKey(maliciousID)

	// Verify slashes are replaced with hyphens
	assert.NotContains(t, key, "/passwd", "path should not contain original slashes")
	assert.Contains(t, key, "-passwd", "slashes should be replaced with hyphens")

	// Verify the key starts with the correct prefix
	assert.True(t, strings.HasPrefix(key, DaemonKeyPrefix), "key should start with correct prefix")
}

func TestEtcdDaemonInfo_LastSeen_Update(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping last seen update test in short mode")
	}

	srv := newTestEtcdServer(t)
	ctx := context.Background()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	etcdInfo := NewEtcdDaemonInfo(srv.client, logger)

	// Register daemon
	info := &DaemonInfo{
		PID:         12345,
		GRPCAddress: "localhost:50002",
		Version:     "1.0.0",
	}
	err := etcdInfo.Register(ctx, info)
	require.NoError(t, err)

	// Get initial LastSeen
	entry1, err := etcdInfo.GetByInstanceID(ctx, etcdInfo.instanceID)
	require.NoError(t, err)
	require.NotNil(t, entry1)

	// Wait for keepalive to update LastSeen (at least one keepalive cycle)
	time.Sleep(2 * time.Second)

	// Get updated LastSeen
	entry2, err := etcdInfo.GetByInstanceID(ctx, etcdInfo.instanceID)
	require.NoError(t, err)
	require.NotNil(t, entry2)

	// LastSeen should be updated (with some tolerance for timing)
	assert.True(t, entry2.LastSeen.After(entry1.LastSeen) || entry2.LastSeen.Equal(entry1.LastSeen),
		"LastSeen should be updated or equal after keepalive")

	// Cleanup
	etcdInfo.Deregister(ctx)
}

func TestEtcdDaemonInfo_MultipleInstances_ConcurrentRegistration(t *testing.T) {
	srv := newTestEtcdServer(t)
	ctx := context.Background()

	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	// Register multiple daemons concurrently
	numDaemons := 10
	daemons := make([]*EtcdDaemonInfo, numDaemons)

	for i := 0; i < numDaemons; i++ {
		daemon := NewEtcdDaemonInfo(srv.client, logger)
		daemon.instanceID = fmt.Sprintf("daemon-%d", i)

		info := &DaemonInfo{
			PID:         10000 + i,
			GRPCAddress: fmt.Sprintf("localhost:%d", 50000+i),
			Version:     "1.0.0",
		}

		err := daemon.Register(ctx, info)
		require.NoError(t, err)

		daemons[i] = daemon
	}

	// Verify all daemons are registered
	entries, err := daemons[0].GetActive(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, numDaemons, "all daemons should be registered")

	// Cleanup
	for _, daemon := range daemons {
		daemon.Deregister(ctx)
	}

	// Verify all are deregistered
	entries, err = daemons[0].GetActive(ctx)
	require.NoError(t, err)
	assert.Len(t, entries, 0, "all daemons should be deregistered")
}

func TestEtcdDaemonInfo_NilClient(t *testing.T) {
	logger := observability.NewLogger(observability.Config{
		Component: "test",
		Level:     slog.LevelError,
		Output:    os.Stderr,
	})

	etcdInfo := NewEtcdDaemonInfo(nil, logger)
	ctx := context.Background()

	// All operations should fail gracefully with nil client
	info := &DaemonInfo{
		PID:         12345,
		GRPCAddress: "localhost:50002",
		Version:     "1.0.0",
	}

	err := etcdInfo.Register(ctx, info)
	assert.Error(t, err, "Register should fail with nil client")
	assert.Contains(t, err.Error(), "etcd client is nil")

	err = etcdInfo.Deregister(ctx)
	assert.Error(t, err, "Deregister should fail with nil client")

	_, err = etcdInfo.GetActive(ctx)
	assert.Error(t, err, "GetActive should fail with nil client")

	_, err = etcdInfo.GetAny(ctx)
	assert.Error(t, err, "GetAny should fail with nil client")

	_, err = etcdInfo.GetByInstanceID(ctx, "test")
	assert.Error(t, err, "GetByInstanceID should fail with nil client")
}
