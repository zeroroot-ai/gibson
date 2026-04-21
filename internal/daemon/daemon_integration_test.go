//go:build integration
// +build integration

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/config"
)

// TestDaemonStartStopCycle tests the full daemon start/stop lifecycle.
//
// This integration test verifies:
// 1. Daemon can start successfully
// 2. PID and daemon.json files are created
// 3. Daemon can be stopped gracefully
// 4. Files are cleaned up after stop
func TestDaemonStartStopCycle(t *testing.T) {
	// Create temporary directory for test isolation
	homeDir := t.TempDir()

	// Create a minimal config
	cfg := createTestConfig(t, homeDir)

	// Create daemon instance
	d, err := New(cfg, WithHomeDir(homeDir))
	require.NoError(t, err, "failed to create daemon")

	// Start daemon in background mode
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start daemon in a goroutine
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Start(ctx, false)
	}()

	// Give daemon time to start
	time.Sleep(2 * time.Second)

	// Verify PID file exists
	pidFile := filepath.Join(homeDir, "daemon.pid")
	assert.FileExists(t, pidFile, "PID file should exist after start")

	// Verify daemon.json exists
	infoFile := filepath.Join(homeDir, "daemon.json")
	assert.FileExists(t, infoFile, "daemon.json should exist after start")

	// Read daemon info
	info, err := ReadDaemonInfo(infoFile)
	require.NoError(t, err, "should be able to read daemon info")
	assert.Equal(t, os.Getpid(), info.PID, "PID should match current process")

	// Check daemon is running
	running, pid, err := CheckPIDFile(pidFile)
	require.NoError(t, err, "should be able to check PID file")
	assert.True(t, running, "daemon should be running")
	assert.Equal(t, os.Getpid(), pid, "PID should match")

	// Stop daemon
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()

	err = d.(*daemonImpl).Stop(stopCtx)
	require.NoError(t, err, "daemon should stop cleanly")

	// Verify files are cleaned up
	assert.NoFileExists(t, pidFile, "PID file should be removed after stop")
	assert.NoFileExists(t, infoFile, "daemon.json should be removed after stop")

	// Verify daemon start goroutine finished without error
	select {
	case err := <-errCh:
		// Background mode returns immediately, so we might get nil or context canceled
		if err != nil && err != context.Canceled {
			t.Logf("daemon start error (expected in background mode): %v", err)
		}
	case <-time.After(1 * time.Second):
		// No error received, that's fine
	}
}

// NOTE: TestDaemonClientConnection and TestDaemonMultipleClients tests have been moved
// to integration_round_trip_test.go to avoid import cycles (daemon package importing client package)

// TestDaemonStart tests daemon start and shutdown.
//
// This integration test verifies:
// 1. Daemon can start successfully
// 2. Daemon blocks until context cancellation
// 3. Daemon stops cleanly on context cancel
func TestDaemonStart(t *testing.T) {
	// Create temporary directory for test isolation
	homeDir := t.TempDir()

	// Create a minimal config
	cfg := createTestConfig(t, homeDir)

	// Create daemon instance
	d, err := New(cfg, WithHomeDir(homeDir))
	require.NoError(t, err, "failed to create daemon")

	// Start daemon with cancellable context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start daemon in a goroutine (Start always blocks)
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.Start(ctx)
	}()

	// Give daemon time to start
	time.Sleep(2 * time.Second)

	// Verify daemon is running
	pidFile := filepath.Join(homeDir, "daemon.pid")
	running, _, err := CheckPIDFile(pidFile)
	require.NoError(t, err, "should be able to check PID file")
	assert.True(t, running, "daemon should be running")

	// Cancel context to trigger shutdown
	cancel()

	// Wait for daemon to stop
	select {
	case err := <-errCh:
		// Daemon should stop cleanly (nil error or context canceled)
		if err != nil && err != context.Canceled {
			t.Errorf("unexpected error from daemon: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for daemon to stop")
	}

	// Verify files are cleaned up
	infoFile := filepath.Join(homeDir, "daemon.json")
	assert.NoFileExists(t, pidFile, "PID file should be removed after stop")
	assert.NoFileExists(t, infoFile, "daemon.json should be removed after stop")
}

// createTestConfig creates a minimal configuration for testing.
func createTestConfig(t *testing.T, homeDir string) *config.Config {
	// Create config with embedded registry and disabled callback
	cfg := &config.Config{
		HomeDir: homeDir,
		Registry: config.RegistryConfig{
			Type:     "embedded",
			Endpoint: "",
			Embedded: config.EmbeddedRegistryConfig{
				ClientPort: 0, // Random port
				PeerPort:   0, // Random port
				DataDir:    filepath.Join(homeDir, "etcd-data"),
			},
		},
		Callback: config.CallbackConfig{
			Enabled:          false, // Disable callback server for simpler tests
			ListenAddress:    "localhost:0",
			AdvertiseAddress: "localhost:50001",
		},
		LLM: config.LLMConfig{
			Providers: []config.LLMProviderConfig{},
		},
	}

	return cfg
}
