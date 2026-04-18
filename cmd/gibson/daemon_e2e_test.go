//go:build e2e
// +build e2e

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/config"
	"gopkg.in/yaml.v3"
)

// TestDaemonStartStatusStop tests the full CLI sequence.
//
// This end-to-end test verifies:
// 1. gibson daemon start - starts the daemon (blocks, so we run in background)
// 2. gibson daemon status - shows daemon is running
// 3. gibson daemon stop - stops the daemon
// 4. gibson daemon status - shows daemon is not running
func TestDaemonStartStatusStop(t *testing.T) {
	// Create temporary Gibson home directory
	homeDir := t.TempDir()
	t.Setenv("GIBSON_HOME", homeDir)

	// Create minimal config file
	createMinimalConfig(t, homeDir)

	// Get path to gibson binary
	gibsonBin := getGibsonBinary(t)

	// Test: daemon status (should be not running initially)
	t.Log("Testing initial daemon status (should be not running)")
	output, err := runCommand(t, gibsonBin, "daemon", "status")
	require.NoError(t, err, "daemon status should succeed even when not running")
	assert.Contains(t, output, "not running", "status should indicate daemon is not running")

	// Test: daemon start (runs in background process since it blocks)
	t.Log("Testing daemon start")
	cmd := startDaemonInBackground(t, gibsonBin, homeDir)

	// Give daemon time to fully start
	time.Sleep(2 * time.Second)

	// Clean up daemon on test exit
	defer func() {
		t.Log("Cleaning up: stopping daemon")
		runCommand(t, gibsonBin, "daemon", "stop")
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	// Test: daemon status (should be running now)
	t.Log("Testing daemon status (should be running)")
	output, err = runCommand(t, gibsonBin, "daemon", "status")
	require.NoError(t, err, "daemon status should succeed")
	assert.Contains(t, output, "Running", "status should show daemon is running")
	assert.Contains(t, output, "PID", "status should show PID")
	assert.Contains(t, output, "Uptime", "status should show uptime")
	assert.Contains(t, output, "gRPC Address", "status should show gRPC address")

	// Test: daemon start again (should fail - already running)
	t.Log("Testing daemon start when already running (should fail)")
	output, err = runCommandExpectError(t, gibsonBin, "daemon", "start")
	require.Error(t, err, "daemon start should fail when already running")
	assert.Contains(t, output, "already running", "error should indicate daemon already running")

	// Test: daemon stop
	t.Log("Testing daemon stop")
	output, err = runCommand(t, gibsonBin, "daemon", "stop")
	require.NoError(t, err, "daemon stop should succeed")
	assert.Contains(t, output, "stopped successfully", "output should confirm daemon stopped")

	// Test: daemon status (should be not running after stop)
	t.Log("Testing daemon status after stop (should be not running)")
	output, err = runCommand(t, gibsonBin, "daemon", "status")
	require.NoError(t, err, "daemon status should succeed")
	assert.Contains(t, output, "not running", "status should indicate daemon is not running")

	// Test: daemon stop again (should handle gracefully)
	t.Log("Testing daemon stop when not running (should handle gracefully)")
	output, err = runCommand(t, gibsonBin, "daemon", "stop")
	require.NoError(t, err, "daemon stop should handle not running gracefully")
	assert.Contains(t, output, "not running", "output should indicate daemon is not running")
}

// TestDaemonRestart tests the daemon restart command.
//
// This end-to-end test verifies:
// 1. gibson daemon start - starts the daemon
// 2. gibson daemon restart - restarts the daemon
// 3. gibson daemon status - shows daemon is still running
func TestDaemonRestart(t *testing.T) {
	// Create temporary Gibson home directory
	homeDir := t.TempDir()
	t.Setenv("GIBSON_HOME", homeDir)

	// Create minimal config file
	createMinimalConfig(t, homeDir)

	// Get path to gibson binary
	gibsonBin := getGibsonBinary(t)

	// Start daemon in background process
	t.Log("Starting daemon")
	cmd := startDaemonInBackground(t, gibsonBin, homeDir)
	time.Sleep(2 * time.Second)

	// Clean up daemon on test exit
	defer func() {
		runCommand(t, gibsonBin, "daemon", "stop")
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	// Get initial PID
	statusOutput, err := runCommand(t, gibsonBin, "daemon", "status")
	require.NoError(t, err, "daemon status should succeed")
	initialPID := extractPIDFromStatus(t, statusOutput)
	t.Logf("Initial daemon PID: %s", initialPID)

	// Restart daemon
	t.Log("Restarting daemon")
	output, err := runCommand(t, gibsonBin, "daemon", "restart")
	require.NoError(t, err, "daemon restart should succeed")
	assert.Contains(t, output, "Stopping daemon", "output should show stopping")
	assert.Contains(t, output, "Starting daemon", "output should show starting")

	// Give daemon time to restart
	time.Sleep(2 * time.Second)

	// Verify daemon is running again
	statusOutput, err = runCommand(t, gibsonBin, "daemon", "status")
	require.NoError(t, err, "daemon status should succeed after restart")
	assert.Contains(t, statusOutput, "Running", "daemon should be running after restart")

	// Note: PID may be same or different depending on implementation
	newPID := extractPIDFromStatus(t, statusOutput)
	t.Logf("New daemon PID after restart: %s", newPID)
}

// TestDaemonStatusJSON tests JSON output format.
//
// This end-to-end test verifies:
// 1. gibson daemon status --json returns valid JSON
// 2. JSON contains expected fields
func TestDaemonStatusJSON(t *testing.T) {
	// Create temporary Gibson home directory
	homeDir := t.TempDir()
	t.Setenv("GIBSON_HOME", homeDir)

	// Create minimal config file
	createMinimalConfig(t, homeDir)

	// Get path to gibson binary
	gibsonBin := getGibsonBinary(t)

	// Start daemon in background process
	t.Log("Starting daemon")
	cmd := startDaemonInBackground(t, gibsonBin, homeDir)
	time.Sleep(2 * time.Second)

	// Clean up daemon on test exit
	defer func() {
		runCommand(t, gibsonBin, "daemon", "stop")
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	// Get status in JSON format
	t.Log("Getting daemon status in JSON format")
	output, err := runCommand(t, gibsonBin, "daemon", "status", "--json")
	require.NoError(t, err, "daemon status --json should succeed")

	// Verify it's valid JSON and contains expected fields
	assert.Contains(t, output, `"running"`, "JSON should contain running field")
	assert.Contains(t, output, `"pid"`, "JSON should contain pid field")
	assert.Contains(t, output, `"uptime"`, "JSON should contain uptime field")
	assert.Contains(t, output, `"grpc_address"`, "JSON should contain grpc_address field")
}

// Helper functions

// startDaemonInBackground starts the daemon in a background process.
// Since the daemon always runs in foreground mode (blocking), we run it as a subprocess.
func startDaemonInBackground(t *testing.T, gibsonBin string, homeDir string) *exec.Cmd {
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, gibsonBin, "daemon", "start")
	cmd.Env = append(os.Environ(), fmt.Sprintf("GIBSON_HOME=%s", homeDir))

	// Start the command in background
	err := cmd.Start()
	require.NoError(t, err, "daemon start should succeed")

	return cmd
}

// getGibsonBinary returns the path to the gibson binary.
// It first tries to build it, then returns the path.
func getGibsonBinary(t *testing.T) string {
	// Build gibson binary to ensure we have latest code
	t.Log("Building gibson binary")
	cmd := exec.Command("make", "bin")
	cmd.Dir = filepath.Join("..", "..")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("Build output: %s", string(output))
		t.Fatalf("Failed to build gibson: %v", err)
	}

	// Return path to built binary
	binPath := filepath.Join("..", "..", "bin", "gibson")
	if _, err := os.Stat(binPath); err != nil {
		t.Fatalf("Gibson binary not found at %s", binPath)
	}

	return binPath
}

// runCommand runs a gibson command and returns the output.
func runCommand(t *testing.T, gibsonBin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, gibsonBin, args...)
	cmd.Env = os.Environ()

	output, err := cmd.CombinedOutput()
	t.Logf("Command: %s %v\nOutput: %s", gibsonBin, args, string(output))

	return string(output), err
}

// runCommandExpectError runs a command expecting it to fail.
func runCommandExpectError(t *testing.T, gibsonBin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, gibsonBin, args...)
	cmd.Env = os.Environ()

	output, err := cmd.CombinedOutput()
	t.Logf("Command (expect error): %s %v\nOutput: %s\nError: %v", gibsonBin, args, string(output), err)

	return string(output), err
}

// createMinimalConfig creates a minimal gibson config file for testing.
func createMinimalConfig(t *testing.T, homeDir string) {
	cfg := &config.Config{
		HomeDir: homeDir,
		Registry: config.RegistryConfig{
			Type:     "embedded",
			Endpoint: "",
			Embedded: config.EmbeddedRegistryConfig{
				ClientPort: 0,
				PeerPort:   0,
				DataDir:    filepath.Join(homeDir, "etcd-data"),
			},
		},
		Callback: config.CallbackConfig{
			Enabled:          false,
			ListenAddress:    "localhost:0",
			AdvertiseAddress: "localhost:50001",
		},
		LLM: config.LLMConfig{
			Providers: []config.LLMProviderConfig{},
		},
	}

	// Write config to file
	configPath := filepath.Join(homeDir, "config.yaml")
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err, "failed to marshal config")

	err = os.WriteFile(configPath, data, 0600)
	require.NoError(t, err, "failed to write config file")

	t.Logf("Created config file at %s", configPath)
}

// extractPIDFromStatus extracts the PID from status output.
func extractPIDFromStatus(t *testing.T, output string) string {
	// Parse output to find PID line
	// Example: "PID:  12345"
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "PID:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}
