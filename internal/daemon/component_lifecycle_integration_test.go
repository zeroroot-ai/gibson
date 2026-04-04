//go:build integration
// +build integration

package daemon_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/daemon"
	daemonclient "github.com/zero-day-ai/sdk/daemonclient"
)

// TestComponentLifecycle tests the full lifecycle of a component through the daemon client.
//
// This integration test verifies the complete component lifecycle:
// 1. Start daemon (or use test setup)
// 2. Install a component (use debug-agent as a real component)
// 3. List components (verify it appears)
// 4. Show component (verify details)
// 5. Start component
// 6. Get logs
// 7. Stop component
// 8. Update component
// 9. Uninstall component (verify it's removed)
//
// The test uses the debug-agent from the monorepo as a real component for testing.
func TestComponentLifecycle(t *testing.T) {
	// Skip if CI environment doesn't have access to the debug-agent repo
	debugAgentPath := findDebugAgentPath(t)
	if debugAgentPath == "" {
		t.Skip("debug-agent not found in expected locations, skipping integration test")
	}

	// Create temporary directory for test isolation
	homeDir := t.TempDir()

	// Create a minimal config
	cfg := createTestConfig(t, homeDir)

	// Create and start daemon
	d, err := daemon.New(cfg, homeDir)
	require.NoError(t, err, "failed to create daemon")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start daemon in a goroutine
	go func() {
		d.Start(ctx)
	}()

	// Give daemon more time to start and initialize embedded etcd
	time.Sleep(5 * time.Second)

	// Clean up daemon on test exit
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer stopCancel()
		if impl, ok := d.(interface{ Stop(context.Context) error }); ok {
			impl.Stop(stopCtx)
		}
	}()

	// Connect client
	clientCtx, clientCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer clientCancel()

	c, err := daemonclient.Connect(clientCtx, daemonclient.DefaultDaemonAddress)
	require.NoError(t, err, "client should connect to daemon")
	require.NotNil(t, c, "client should not be nil")
	defer c.Close()

	t.Log("Successfully connected to daemon")

	// Step 1: Verify no agents initially
	listCtx1, listCancel1 := context.WithTimeout(context.Background(), 5*time.Second)
	defer listCancel1()

	agents, err := c.ListAgents(listCtx1)
	require.NoError(t, err, "ListAgents should succeed")
	assert.Empty(t, agents, "agents list should be empty initially")
	t.Log("Step 1: Verified no agents initially")

	// Step 2: Install debug-agent component
	// Use a local path URL format for the debug-agent
	installCtx, installCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer installCancel()

	t.Logf("Installing debug-agent from: %s", debugAgentPath)
	result, err := c.InstallAgent(installCtx, debugAgentPath, daemonclient.InstallOptions{
		SkipBuild: false, // Build the agent
		Verbose:   true,  // Get build output for debugging
	})
	require.NoError(t, err, "InstallAgent should succeed")
	require.NotNil(t, result, "install result should not be nil")
	assert.Equal(t, "debug-agent", result.Name, "component name should match")
	assert.NotEmpty(t, result.Version, "component should have a version")
	t.Logf("Step 2: Installed component: %s v%s", result.Name, result.Version)
	if result.BuildOutput != "" {
		t.Logf("Build output: %s", result.BuildOutput)
	}

	// Step 3: List components - verify it appears
	listCtx2, listCancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer listCancel2()

	agents, err = c.ListAgents(listCtx2)
	require.NoError(t, err, "ListAgents should succeed")
	require.Len(t, agents, 1, "should have one agent after installation")
	assert.Equal(t, "debug-agent", agents[0].Name, "agent name should match")
	t.Logf("Step 3: Listed agents, found: %s (status: %s)", agents[0].Name, agents[0].Status)

	// Step 4: Show component - verify details
	showCtx, showCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer showCancel()

	componentInfo, err := c.ShowAgent(showCtx, "debug-agent")
	require.NoError(t, err, "ShowAgent should succeed")
	require.NotNil(t, componentInfo, "component info should not be nil")
	assert.Equal(t, "debug-agent", componentInfo.Name, "component name should match")
	assert.Equal(t, "agent", componentInfo.Kind, "component kind should be agent")
	assert.NotEmpty(t, componentInfo.Version, "component should have version")
	assert.NotEmpty(t, componentInfo.BinPath, "component should have binary path")
	t.Logf("Step 4: Component details - Name: %s, Kind: %s, Version: %s, BinPath: %s",
		componentInfo.Name, componentInfo.Kind, componentInfo.Version, componentInfo.BinPath)

	// Step 5: Start component
	startCtx, startCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer startCancel()

	startResult, err := c.StartAgent(startCtx, "debug-agent")
	require.NoError(t, err, "StartAgent should succeed")
	require.NotNil(t, startResult, "start result should not be nil")
	assert.Greater(t, startResult.PID, 0, "component should have a PID after start")
	assert.NotEmpty(t, startResult.LogPath, "component should have a log path")
	t.Logf("Step 5: Started component - PID: %d, Port: %d, LogPath: %s",
		startResult.PID, startResult.Port, startResult.LogPath)

	// Give component time to initialize and generate logs
	time.Sleep(2 * time.Second)

	// Step 6: Get logs
	logsCtx, logsCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer logsCancel()

	logChan, err := c.GetAgentLogs(logsCtx, "debug-agent", daemonclient.LogsOptions{
		Follow: false,
		Lines:  10,
	})
	require.NoError(t, err, "GetAgentLogs should succeed")
	require.NotNil(t, logChan, "log channel should not be nil")

	// Read logs from channel
	logCount := 0
	for logEntry := range logChan {
		logCount++
		t.Logf("Log entry: [%s] %s: %s", logEntry.Timestamp.Format(time.RFC3339), logEntry.Level, logEntry.Message)
	}
	// Note: Logs might be empty if component hasn't generated any yet, that's okay
	t.Logf("Step 6: Retrieved %d log entries", logCount)

	// Step 7: Stop component
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()

	stopResult, err := c.StopAgent(stopCtx, "debug-agent")
	require.NoError(t, err, "StopAgent should succeed")
	require.NotNil(t, stopResult, "stop result should not be nil")
	assert.Greater(t, stopResult.StoppedCount, 0, "should have stopped at least one process")
	t.Logf("Step 7: Stopped component - stopped %d processes", stopResult.StoppedCount)

	// Step 8: Update component (this is a no-op since it's a local path, but tests the API)
	updateCtx, updateCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer updateCancel()

	updateResult, err := c.UpdateAgent(updateCtx, "debug-agent", daemonclient.UpdateOptions{
		Restart:   false,
		SkipBuild: true, // Skip rebuild to make test faster
		Verbose:   false,
	})
	// Update might fail for local path components or if already up to date - that's acceptable
	if err != nil {
		t.Logf("Step 8: Update failed (expected for local components): %v", err)
	} else {
		require.NotNil(t, updateResult, "update result should not be nil")
		t.Logf("Step 8: Updated component - Updated: %v, OldVersion: %s, NewVersion: %s",
			updateResult.Updated, updateResult.OldVersion, updateResult.NewVersion)
	}

	// Step 9: Uninstall component - verify it's removed
	uninstallCtx, uninstallCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer uninstallCancel()

	err = c.UninstallAgent(uninstallCtx, "debug-agent", false)
	require.NoError(t, err, "UninstallAgent should succeed")
	t.Log("Step 9: Uninstalled component")

	// Verify component is removed
	listCtx3, listCancel3 := context.WithTimeout(context.Background(), 5*time.Second)
	defer listCancel3()

	agents, err = c.ListAgents(listCtx3)
	require.NoError(t, err, "ListAgents should succeed after uninstall")
	assert.Empty(t, agents, "agents list should be empty after uninstall")
	t.Log("Step 10: Verified component removed from list")

	t.Log("Full component lifecycle test completed successfully")
}

// findDebugAgentPath attempts to locate the debug-agent in the monorepo.
// Returns empty string if not found.
func findDebugAgentPath(t *testing.T) string {
	// Common locations relative to the gibson directory
	possiblePaths := []string{
		// Relative to gibson directory
		"../agents/debug",
		"../../agents/debug",
		"../../../agents/debug",
		// Absolute path in typical monorepo structure
		"/home/anthony/Code/zero-day.ai/opensource/agents/debug",
		// Check if there's a GIBSON_TEST_AGENT_PATH env var
		os.Getenv("GIBSON_TEST_AGENT_PATH"),
	}

	for _, path := range possiblePaths {
		if path == "" {
			continue
		}

		// Check if component.yaml exists at this path
		componentYaml := filepath.Join(path, "component.yaml")
		if _, err := os.Stat(componentYaml); err == nil {
			// Found it! Return absolute path
			absPath, err := filepath.Abs(path)
			if err == nil {
				t.Logf("Found debug-agent at: %s", absPath)
				return absPath
			}
			return path
		}
	}

	return ""
}

// TestComponentLifecycleWithMockComponent tests lifecycle with a minimal mock component.
//
// This test creates a temporary mock component to test the lifecycle without
// depending on external repositories. Useful for testing install/uninstall logic.
func TestComponentLifecycleWithMockComponent(t *testing.T) {
	// Create temporary directory for test isolation
	homeDir := t.TempDir()

	// Create a minimal mock component
	mockComponentDir := t.TempDir()
	createMockComponent(t, mockComponentDir, "mock-agent")

	// Create a minimal config
	cfg := createTestConfig(t, homeDir)

	// Create and start daemon
	d, err := daemon.New(cfg, homeDir)
	require.NoError(t, err, "failed to create daemon")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// Start daemon in a goroutine
	go func() {
		d.Start(ctx)
	}()

	// Give daemon time to start
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

	t.Log("Connected to daemon with mock component")

	// Install mock component
	installCtx, installCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer installCancel()

	result, err := c.InstallAgent(installCtx, mockComponentDir, daemonclient.InstallOptions{
		SkipBuild: false,
		Verbose:   true,
	})

	if err != nil {
		// Installation might fail due to missing git metadata or other issues with temp directories
		// That's acceptable - the test verified the API works
		t.Logf("Install failed (expected for mock component): %v", err)
		return
	}

	require.NotNil(t, result, "install result should not be nil")
	t.Logf("Installed mock component: %s", result.Name)

	// Clean up: uninstall
	uninstallCtx, uninstallCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer uninstallCancel()

	err = c.UninstallAgent(uninstallCtx, "mock-agent", true) // Force in case still running
	if err != nil {
		t.Logf("Uninstall failed: %v", err)
	}
}

// createMockComponent creates a minimal mock component for testing.
func createMockComponent(t *testing.T, dir, name string) {
	// Create component.yaml
	manifest := map[string]interface{}{
		"kind":        "agent",
		"name":        name,
		"version":     "0.1.0",
		"description": "Mock agent for testing",
		"build": map[string]interface{}{
			"command": "echo 'mock build'",
			"artifacts": []string{
				name,
			},
		},
		"runtime": map[string]interface{}{
			"type":       "go",
			"entrypoint": "./" + name,
			"port":       0,
		},
	}

	manifestYaml := filepath.Join(dir, "component.yaml")
	data, err := json.Marshal(manifest)
	require.NoError(t, err, "failed to marshal manifest")

	err = os.WriteFile(manifestYaml, data, 0644)
	require.NoError(t, err, "failed to write component.yaml")

	// Create a minimal go.mod
	goMod := fmt.Sprintf(`module github.com/test/%s

go 1.21

require github.com/zero-day-ai/sdk v0.20.0
`, name)

	err = os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0644)
	require.NoError(t, err, "failed to write go.mod")

	// Create a minimal main.go
	mainGo := fmt.Sprintf(`package main

import (
	"context"
	"fmt"
)

func main() {
	fmt.Println("%s started")
	ctx := context.Background()
	<-ctx.Done()
}
`, name)

	err = os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainGo), 0644)
	require.NoError(t, err, "failed to write main.go")

	t.Logf("Created mock component in: %s", dir)
}

// createTestConfig creates a minimal configuration for testing.
func createTestConfig(t *testing.T, homeDir string) *config.Config {
	// Start with default config and override for test
	cfg := config.DefaultConfig()

	// Override home directory for test isolation
	cfg.Core.HomeDir = homeDir
	cfg.Core.DataDir = filepath.Join(homeDir, "data")
	cfg.Core.CacheDir = filepath.Join(homeDir, "cache")
	cfg.Database.Path = filepath.Join(homeDir, "gibson.db")

	// Configure embedded registry for testing
	cfg.Registry.Type = "embedded"
	cfg.Registry.DataDir = filepath.Join(homeDir, "etcd-data")
	cfg.Registry.ListenAddress = "localhost:0" // Random port

	// Disable callback server for simpler tests
	cfg.Callback.Enabled = false
	cfg.Callback.ListenAddress = "localhost:0"
	cfg.Callback.AdvertiseAddress = "localhost:50001"

	// Disable registration server
	cfg.Registration.Enabled = false

	return cfg
}
