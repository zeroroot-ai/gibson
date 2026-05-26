//go:build integration
// +build integration

package daemon_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/config"
	"github.com/zeroroot-ai/gibson/internal/daemon"
	daemonclient "github.com/zeroroot-ai/sdk/daemonclient"
)

// TestDaemonClientListAgentsRoundTrip tests the full round trip of client connecting and calling ListAgents.
//
// This integration test verifies:
// 1. Daemon can start with embedded etcd
// 2. Client can connect to the daemon
// 3. Client can call ListAgents via gRPC
// 4. Response is properly converted from proto to domain types
// 5. Empty list is handled correctly (no agents registered)
func TestDaemonClientListAgentsRoundTrip(t *testing.T) {
	// Create temporary directory for test isolation
	homeDir := t.TempDir()

	// Create a minimal config
	cfg := createTestConfig(t, homeDir)

	// Create and start daemon
	d, err := daemon.New(cfg, daemon.WithHomeDir(homeDir))
	require.NoError(t, err, "failed to create daemon")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// Start daemon in a goroutine
	go func() {
		d.Start(ctx, false)
	}()

	// Give daemon more time to start and initialize embedded etcd
	time.Sleep(4 * time.Second)

	// Clean up daemon on test exit
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		// Stop is a method on the concrete type, need to access it via interface
		if impl, ok := d.(interface{ Stop(context.Context) error }); ok {
			impl.Stop(stopCtx)
		}
	}()

	// Connect client
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer clientCancel()

	c, err := daemonclient.Connect(clientCtx, daemonclient.DefaultDaemonAddress)
	require.NoError(t, err, "client should connect to daemon")
	require.NotNil(t, c, "client should not be nil")
	defer c.Close()

	// Call ListAgents - should succeed even with no agents registered
	listCtx, listCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer listCancel()

	agents, err := c.ListAgents(listCtx)
	require.NoError(t, err, "ListAgents should succeed")
	require.NotNil(t, agents, "agents list should not be nil")

	// No agents registered initially, so list should be empty
	assert.Empty(t, agents, "agents list should be empty when no agents registered")

	t.Logf("Successfully completed daemon-client round trip: ListAgents returned empty list")
}

// TestDaemonClientListToolsAndPlugins tests listing tools and plugins via client.
//
// This integration test verifies:
// 1. Client can list tools and plugins
// 2. Empty lists are handled correctly
func TestDaemonClientListToolsAndPlugins(t *testing.T) {
	// Create temporary directory for test isolation
	homeDir := t.TempDir()

	// Create a minimal config
	cfg := createTestConfig(t, homeDir)

	// Create and start daemon
	d, err := daemon.New(cfg, daemon.WithHomeDir(homeDir))
	require.NoError(t, err, "failed to create daemon")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// Start daemon in a goroutine
	go func() {
		d.Start(ctx, false)
	}()

	// Give daemon more time to start and initialize embedded etcd
	time.Sleep(4 * time.Second)

	// Clean up daemon on test exit
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		if impl, ok := d.(interface{ Stop(context.Context) error }); ok {
			impl.Stop(stopCtx)
		}
	}()

	// Connect client
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer clientCancel()

	c, err := daemonclient.Connect(clientCtx, daemonclient.DefaultDaemonAddress)
	require.NoError(t, err, "client should connect to daemon")
	require.NotNil(t, c, "client should not be nil")
	defer c.Close()

	// Call ListTools (should return empty list initially)
	toolsCtx, toolsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer toolsCancel()

	tools, err := c.ListTools(toolsCtx)
	require.NoError(t, err, "ListTools should succeed")
	require.NotNil(t, tools, "tools list should not be nil")
	assert.Empty(t, tools, "tools list should be empty initially")

	// Call ListPlugins (should return empty list initially)
	pluginsCtx, pluginsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer pluginsCancel()

	plugins, err := c.ListPlugins(pluginsCtx)
	require.NoError(t, err, "ListPlugins should succeed")
	require.NotNil(t, plugins, "plugins list should not be nil")
	assert.Empty(t, plugins, "plugins list should be empty initially")

	t.Logf("Successfully tested ListTools and ListPlugins with empty results")
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
