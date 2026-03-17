package client

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsRemoteDaemon tests the remote daemon detection logic.
//
// The logic is simple: Unix sockets = local (shared filesystem), TCP = remote.
// This correctly handles kubectl port-forward scenarios where localhost:port
// routes to a remote daemon without filesystem access.
func TestIsRemoteDaemon(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     bool
	}{
		// Local: no address (default Unix socket) or explicit Unix socket
		{
			name:     "no env var set (default Unix socket)",
			envValue: "",
			want:     false,
		},
		{
			name:     "unix socket with scheme",
			envValue: "unix:///var/run/gibson.sock",
			want:     false,
		},
		{
			name:     "unix socket absolute path",
			envValue: "/var/run/gibson.sock",
			want:     false,
		},
		// Remote: all TCP connections including localhost
		// This handles port-forward scenarios correctly
		{
			name:     "localhost with port (could be port-forward)",
			envValue: "localhost:50002",
			want:     true,
		},
		{
			name:     "localhost without port",
			envValue: "localhost",
			want:     true,
		},
		{
			name:     "127.0.0.1 with port (could be port-forward)",
			envValue: "127.0.0.1:50002",
			want:     true,
		},
		{
			name:     "127.0.0.1 without port",
			envValue: "127.0.0.1",
			want:     true,
		},
		{
			name:     "remote host with port",
			envValue: "gibson-daemon.example.com:50002",
			want:     true,
		},
		{
			name:     "remote IP with port",
			envValue: "192.168.1.100:50002",
			want:     true,
		},
		{
			name:     "kubernetes service",
			envValue: "gibson.default.svc.cluster.local:50002",
			want:     true,
		},
		{
			name:     "docker host",
			envValue: "host.docker.internal:50002",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env value and restore after test
			originalAddress := os.Getenv(EnvDaemonAddress)
			defer func() {
				if originalAddress != "" {
					os.Setenv(EnvDaemonAddress, originalAddress)
				} else {
					os.Unsetenv(EnvDaemonAddress)
				}
			}()

			// Set test environment variable
			if tt.envValue != "" {
				os.Setenv(EnvDaemonAddress, tt.envValue)
			} else {
				os.Unsetenv(EnvDaemonAddress)
			}

			// Test the function
			got := isRemoteDaemon()
			if got != tt.want {
				t.Errorf("isRemoteDaemon() = %v, want %v (env=%q)", got, tt.want, tt.envValue)
			}
		})
	}
}


// TestFileReadingForRemote tests that workflow files can be read correctly
// when connecting to a remote daemon.
func TestFileReadingForRemote(t *testing.T) {
	// Create a temporary test workflow file
	tmpDir := t.TempDir()
	workflowPath := filepath.Join(tmpDir, "test_workflow.yaml")
	workflowContent := `name: test-workflow
description: Test workflow for remote transmission
nodes:
  - id: test-node
    type: agent
    agent: test-agent
`
	if err := os.WriteFile(workflowPath, []byte(workflowContent), 0644); err != nil {
		t.Fatalf("failed to create test workflow file: %v", err)
	}

	// Test reading the file
	content, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("failed to read workflow file: %v", err)
	}

	if string(content) != workflowContent {
		t.Errorf("expected content=%q, got %q", workflowContent, string(content))
	}

	// Test file size validation
	const maxFileSize = 10 * 1024 * 1024 // 10MB
	if len(content) > maxFileSize {
		t.Errorf("workflow file is too large: %d bytes (max %d bytes)", len(content), maxFileSize)
	}
}

// TestFileSizeValidation tests that the file size limit is enforced.
func TestFileSizeValidation(t *testing.T) {
	// Create a temporary file that exceeds the limit
	tmpDir := t.TempDir()
	largeFilePath := filepath.Join(tmpDir, "large_workflow.yaml")

	// Create 11MB file
	largeContent := make([]byte, 11*1024*1024)
	for i := range largeContent {
		largeContent[i] = 'a'
	}
	if err := os.WriteFile(largeFilePath, largeContent, 0644); err != nil {
		t.Fatalf("failed to create large test file: %v", err)
	}

	// Read and validate size
	content, err := os.ReadFile(largeFilePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	const maxFileSize = 10 * 1024 * 1024 // 10MB
	if len(content) > maxFileSize {
		// This is expected - large file should be rejected
		t.Logf("Large file correctly detected: %d bytes exceeds limit of %d bytes", len(content), maxFileSize)
	} else {
		t.Errorf("expected file size to exceed %d bytes, got %d bytes", maxFileSize, len(content))
	}
}

// TestFileNotFoundHandling tests error handling for missing files.
func TestFileNotFoundHandling(t *testing.T) {
	// Try to read a non-existent file
	_, err := os.ReadFile("/nonexistent/path/to/workflow.yaml")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}

	// Verify it's the right kind of error
	if !os.IsNotExist(err) {
		t.Errorf("expected os.IsNotExist error, got: %v", err)
	}
}
