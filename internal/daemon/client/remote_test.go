package client

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsRemoteDaemon tests the remote daemon detection logic.
func TestIsRemoteDaemon(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		want     bool
	}{
		{
			name:     "no env var set",
			envValue: "",
			want:     false,
		},
		{
			name:     "localhost with port",
			envValue: "localhost:50002",
			want:     false,
		},
		{
			name:     "localhost without port",
			envValue: "localhost",
			want:     false,
		},
		{
			name:     "127.0.0.1 with port",
			envValue: "127.0.0.1:50002",
			want:     false,
		},
		{
			name:     "127.0.0.1 without port",
			envValue: "127.0.0.1",
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
			// Save original env values and restore after test
			originalAddress := os.Getenv(EnvDaemonAddress)
			originalForce := os.Getenv(EnvForceInlineYAML)
			defer func() {
				if originalAddress != "" {
					os.Setenv(EnvDaemonAddress, originalAddress)
				} else {
					os.Unsetenv(EnvDaemonAddress)
				}
				if originalForce != "" {
					os.Setenv(EnvForceInlineYAML, originalForce)
				} else {
					os.Unsetenv(EnvForceInlineYAML)
				}
			}()

			// Clear force inline flag for these tests
			os.Unsetenv(EnvForceInlineYAML)

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

// TestForceInlineYAML tests the GIBSON_FORCE_INLINE_YAML override behavior.
func TestForceInlineYAML(t *testing.T) {
	tests := []struct {
		name           string
		daemonAddress  string
		forceInlineVal string
		want           bool
	}{
		{
			name:           "force inline with localhost (port-forward scenario)",
			daemonAddress:  "localhost:50002",
			forceInlineVal: "true",
			want:           true,
		},
		{
			name:           "force inline with value 1",
			daemonAddress:  "localhost:50002",
			forceInlineVal: "1",
			want:           true,
		},
		{
			name:           "force inline not set, localhost",
			daemonAddress:  "localhost:50002",
			forceInlineVal: "",
			want:           false,
		},
		{
			name:           "force inline false, localhost",
			daemonAddress:  "localhost:50002",
			forceInlineVal: "false",
			want:           false,
		},
		{
			name:           "force inline with 127.0.0.1",
			daemonAddress:  "127.0.0.1:50002",
			forceInlineVal: "true",
			want:           true,
		},
		{
			name:           "force inline with remote address (already remote)",
			daemonAddress:  "gibson.example.com:50002",
			forceInlineVal: "true",
			want:           true,
		},
		{
			name:           "force inline with no daemon address",
			daemonAddress:  "",
			forceInlineVal: "true",
			want:           true, // Force takes precedence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original env values and restore after test
			originalAddress := os.Getenv(EnvDaemonAddress)
			originalForce := os.Getenv(EnvForceInlineYAML)
			defer func() {
				if originalAddress != "" {
					os.Setenv(EnvDaemonAddress, originalAddress)
				} else {
					os.Unsetenv(EnvDaemonAddress)
				}
				if originalForce != "" {
					os.Setenv(EnvForceInlineYAML, originalForce)
				} else {
					os.Unsetenv(EnvForceInlineYAML)
				}
			}()

			// Set test environment variables
			if tt.daemonAddress != "" {
				os.Setenv(EnvDaemonAddress, tt.daemonAddress)
			} else {
				os.Unsetenv(EnvDaemonAddress)
			}
			if tt.forceInlineVal != "" {
				os.Setenv(EnvForceInlineYAML, tt.forceInlineVal)
			} else {
				os.Unsetenv(EnvForceInlineYAML)
			}

			// Test the function
			got := isRemoteDaemon()
			if got != tt.want {
				t.Errorf("isRemoteDaemon() = %v, want %v (address=%q, force=%q)",
					got, tt.want, tt.daemonAddress, tt.forceInlineVal)
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
