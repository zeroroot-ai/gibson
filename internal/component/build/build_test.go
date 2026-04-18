package build

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewDefaultBuildExecutor tests creating a new DefaultBuildExecutor.
func TestNewDefaultBuildExecutor(t *testing.T) {
	executor := NewDefaultBuildExecutor()
	assert.NotNil(t, executor)
	assert.Implements(t, (*BuildExecutor)(nil), executor)
}

// TestDefaultBuildExecutor_Build tests the Build method.
func TestDefaultBuildExecutor_Build(t *testing.T) {
	tests := []struct {
		name             string
		config           BuildConfig
		componentName    string
		componentVersion string
		gibsonVersion    string
		setupFunc        func(t *testing.T) string // Returns temp dir
		cleanupFunc      func(t *testing.T, dir string)
		expectError      bool
		expectSuccess    bool
		validateResult   func(t *testing.T, result *BuildResult)
	}{
		{
			name: "successful build with echo command",
			config: BuildConfig{
				Command: "echo",
				Args:    []string{"build successful"},
			},
			componentName:    "test-component",
			componentVersion: "1.0.0",
			gibsonVersion:    "0.1.0",
			setupFunc: func(t *testing.T) string {
				dir := t.TempDir()
				return dir
			},
			expectError:   false,
			expectSuccess: true,
			validateResult: func(t *testing.T, result *BuildResult) {
				assert.True(t, result.Success)
				assert.Contains(t, result.Stdout, "build successful")
				assert.Empty(t, result.Stderr)
				assert.Greater(t, result.Duration, time.Duration(0))
				assert.Nil(t, result.Error)
			},
		},
		{
			name: "build with output verification",
			config: BuildConfig{
				Command:    "touch",
				Args:       []string{"test-binary"},
				OutputPath: "test-binary",
			},
			componentName:    "test-component",
			componentVersion: "1.0.0",
			gibsonVersion:    "0.1.0",
			setupFunc: func(t *testing.T) string {
				dir := t.TempDir()
				return dir
			},
			expectError:   false,
			expectSuccess: true,
			validateResult: func(t *testing.T, result *BuildResult) {
				assert.True(t, result.Success)
				assert.NotEmpty(t, result.OutputPath)
				assert.FileExists(t, result.OutputPath)
			},
		},
		{
			name: "build with missing output binary",
			config: BuildConfig{
				Command:    "echo",
				Args:       []string{"no binary created"},
				OutputPath: "nonexistent-binary",
			},
			componentName:    "test-component",
			componentVersion: "1.0.0",
			gibsonVersion:    "0.1.0",
			setupFunc: func(t *testing.T) string {
				dir := t.TempDir()
				return dir
			},
			expectError:   true,
			expectSuccess: false,
			validateResult: func(t *testing.T, result *BuildResult) {
				assert.False(t, result.Success)
				assert.NotNil(t, result.Error)
				assert.Contains(t, result.Error.Error(), "output binary not found")
			},
		},
		{
			name: "build with nonexistent work directory",
			config: BuildConfig{
				WorkDir: "/nonexistent/directory",
				Command: "echo",
				Args:    []string{"test"},
			},
			componentName:    "test-component",
			componentVersion: "1.0.0",
			gibsonVersion:    "0.1.0",
			setupFunc:        func(t *testing.T) string { return "" },
			expectError:      true,
			expectSuccess:    false,
			validateResult: func(t *testing.T, result *BuildResult) {
				assert.False(t, result.Success)
				assert.NotNil(t, result.Error)
				assert.Contains(t, result.Error.Error(), "work directory does not exist")
			},
		},
		{
			name: "build with empty work directory",
			config: BuildConfig{
				WorkDir: "",
				Command: "echo",
				Args:    []string{"test"},
			},
			componentName:    "test-component",
			componentVersion: "1.0.0",
			gibsonVersion:    "0.1.0",
			setupFunc:        func(t *testing.T) string { return "" },
			expectError:      true,
			expectSuccess:    false,
			validateResult:   nil,
		},
		{
			name: "build with empty command",
			config: BuildConfig{
				Command: "",
			},
			componentName:    "test-component",
			componentVersion: "1.0.0",
			gibsonVersion:    "0.1.0",
			setupFunc: func(t *testing.T) string {
				return t.TempDir()
			},
			expectError:    true,
			expectSuccess:  false,
			validateResult: nil,
		},
		{
			name: "build with failing command",
			config: BuildConfig{
				Command: "sh",
				Args:    []string{"-c", "echo 'error output' >&2; exit 1"},
			},
			componentName:    "test-component",
			componentVersion: "1.0.0",
			gibsonVersion:    "0.1.0",
			setupFunc: func(t *testing.T) string {
				return t.TempDir()
			},
			expectError:   true,
			expectSuccess: false,
			validateResult: func(t *testing.T, result *BuildResult) {
				assert.False(t, result.Success)
				assert.NotNil(t, result.Error)
				assert.Contains(t, result.Error.Error(), "build command failed")
				assert.Contains(t, result.Stderr, "error output")
			},
		},
		{
			name: "build with custom environment variables",
			config: BuildConfig{
				Command: "sh",
				Args:    []string{"-c", "echo $CUSTOM_VAR"},
				Env: map[string]string{
					"CUSTOM_VAR": "custom_value",
				},
			},
			componentName:    "test-component",
			componentVersion: "1.0.0",
			gibsonVersion:    "0.1.0",
			setupFunc: func(t *testing.T) string {
				return t.TempDir()
			},
			expectError:   false,
			expectSuccess: true,
			validateResult: func(t *testing.T, result *BuildResult) {
				assert.True(t, result.Success)
				assert.Contains(t, result.Stdout, "custom_value")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewDefaultBuildExecutor()
			ctx := context.Background()

			// Setup
			dir := tt.setupFunc(t)
			if dir != "" {
				tt.config.WorkDir = dir
			}

			// Execute
			result, err := executor.Build(ctx, tt.config, tt.componentName, tt.componentVersion, tt.gibsonVersion)

			// Verify error expectation
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Validate result if validation function is provided
			if tt.validateResult != nil {
				require.NotNil(t, result)
				tt.validateResult(t, result)
			}
		})
	}
}

// TestDefaultBuildExecutor_Build_Context tests context cancellation during build.
func TestDefaultBuildExecutor_Build_Context(t *testing.T) {
	executor := NewDefaultBuildExecutor()
	dir := t.TempDir()

	config := BuildConfig{
		WorkDir: dir,
		Command: "sleep",
		Args:    []string{"10"},
	}

	// Create a context with immediate cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := executor.Build(ctx, config, "test", "1.0.0", "0.1.0")

	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestDefaultBuildExecutor_Build_Timeout tests build timeout.
func TestDefaultBuildExecutor_Build_Timeout(t *testing.T) {
	executor := NewDefaultBuildExecutor()
	dir := t.TempDir()

	config := BuildConfig{
		WorkDir: dir,
		Command: "sleep",
		Args:    []string{"5"},
	}

	// Create a context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result, err := executor.Build(ctx, config, "test", "1.0.0", "0.1.0")

	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
	// Context cancellation can result in either "context deadline exceeded" or "signal: killed"
	assert.NotNil(t, result.Error)
}

// TestDefaultBuildExecutor_Clean tests the Clean method.
func TestDefaultBuildExecutor_Clean(t *testing.T) {
	tests := []struct {
		name           string
		workDir        string
		setupFunc      func(t *testing.T) string
		expectError    bool
		expectSuccess  bool
		validateResult func(t *testing.T, result *CleanResult)
	}{
		{
			name:    "clean with valid directory (no Makefile)",
			workDir: "",
			setupFunc: func(t *testing.T) string {
				dir := t.TempDir()
				// Create a simple script instead of make
				return dir
			},
			expectError:   true, // No Makefile, so make clean will fail
			expectSuccess: false,
			validateResult: func(t *testing.T, result *CleanResult) {
				assert.False(t, result.Success)
				assert.NotNil(t, result.Error)
			},
		},
		{
			name:          "clean with nonexistent directory",
			workDir:       "/nonexistent/directory",
			setupFunc:     func(t *testing.T) string { return "" },
			expectError:   true,
			expectSuccess: false,
			validateResult: func(t *testing.T, result *CleanResult) {
				assert.False(t, result.Success)
				assert.NotNil(t, result.Error)
				assert.Contains(t, result.Error.Error(), "work directory does not exist")
			},
		},
		{
			name:           "clean with empty work directory",
			workDir:        "",
			setupFunc:      func(t *testing.T) string { return "" },
			expectError:    true,
			expectSuccess:  false,
			validateResult: nil, // Result will be nil when validation happens before result creation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewDefaultBuildExecutor()
			ctx := context.Background()

			// Setup
			workDir := tt.workDir
			if tt.setupFunc != nil {
				dir := tt.setupFunc(t)
				if dir != "" {
					workDir = dir
				}
			}

			// Execute
			result, err := executor.Clean(ctx, workDir)

			// Verify error expectation
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Validate result
			if tt.validateResult != nil {
				require.NotNil(t, result)
				tt.validateResult(t, result)
			}
		})
	}
}

// TestDefaultBuildExecutor_Clean_Context tests context cancellation during clean.
func TestDefaultBuildExecutor_Clean_Context(t *testing.T) {
	executor := NewDefaultBuildExecutor()
	dir := t.TempDir()

	// Create a context with immediate cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := executor.Clean(ctx, dir)

	// Clean might fail due to context or no Makefile
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestDefaultBuildExecutor_Test tests the Test method.
func TestDefaultBuildExecutor_Test(t *testing.T) {
	tests := []struct {
		name           string
		workDir        string
		setupFunc      func(t *testing.T) string
		expectError    bool
		expectSuccess  bool
		validateResult func(t *testing.T, result *TestResult)
	}{
		{
			name:    "test with valid directory (no Makefile)",
			workDir: "",
			setupFunc: func(t *testing.T) string {
				dir := t.TempDir()
				return dir
			},
			expectError:   true, // No Makefile, so make test will fail
			expectSuccess: false,
			validateResult: func(t *testing.T, result *TestResult) {
				assert.False(t, result.Success)
				assert.NotNil(t, result.Error)
			},
		},
		{
			name:          "test with nonexistent directory",
			workDir:       "/nonexistent/directory",
			setupFunc:     func(t *testing.T) string { return "" },
			expectError:   true,
			expectSuccess: false,
			validateResult: func(t *testing.T, result *TestResult) {
				assert.False(t, result.Success)
				assert.NotNil(t, result.Error)
				assert.Contains(t, result.Error.Error(), "work directory does not exist")
			},
		},
		{
			name:           "test with empty work directory",
			workDir:        "",
			setupFunc:      func(t *testing.T) string { return "" },
			expectError:    true,
			expectSuccess:  false,
			validateResult: nil, // Result will be nil when validation happens before result creation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewDefaultBuildExecutor()
			ctx := context.Background()

			// Setup
			workDir := tt.workDir
			if tt.setupFunc != nil {
				dir := tt.setupFunc(t)
				if dir != "" {
					workDir = dir
				}
			}

			// Execute
			result, err := executor.Test(ctx, workDir)

			// Verify error expectation
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			// Validate result
			if tt.validateResult != nil {
				require.NotNil(t, result)
				tt.validateResult(t, result)
			}
		})
	}
}

// TestDefaultBuildExecutor_Test_Context tests context cancellation during test.
func TestDefaultBuildExecutor_Test_Context(t *testing.T) {
	executor := NewDefaultBuildExecutor()
	dir := t.TempDir()

	// Create a context with immediate cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := executor.Test(ctx, dir)

	// Test might fail due to context or no Makefile
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.Success)
}

// TestDefaultBuildExecutor_Integration tests a complete build mission.
func TestDefaultBuildExecutor_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	executor := NewDefaultBuildExecutor()
	ctx := context.Background()

	// Create a temporary directory with a simple build script
	dir := t.TempDir()

	// Create a simple shell script to act as a build command
	buildScript := filepath.Join(dir, "build.sh")
	scriptContent := `#!/bin/bash
echo "Building component..."
echo "GIBSON_VERSION: $GIBSON_VERSION"
echo "COMPONENT_NAME: $COMPONENT_NAME"
echo "COMPONENT_VERSION: $COMPONENT_VERSION"
echo "binary content" > output
echo "Build complete"
`
	err := os.WriteFile(buildScript, []byte(scriptContent), 0755)
	require.NoError(t, err)

	config := BuildConfig{
		WorkDir:    dir,
		Command:    "bash",
		Args:       []string{"build.sh"},
		OutputPath: "output",
	}

	// Execute build
	result, err := executor.Build(ctx, config, "test-component", "1.0.0", "0.1.0")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Success)
	assert.Contains(t, result.Stdout, "Building component")
	assert.Contains(t, result.Stdout, "GIBSON_VERSION: 0.1.0")
	assert.Contains(t, result.Stdout, "COMPONENT_NAME: test-component")
	assert.Contains(t, result.Stdout, "COMPONENT_VERSION: 1.0.0")
	assert.FileExists(t, filepath.Join(dir, "output"))
	assert.Greater(t, result.Duration, time.Duration(0))
}

// TestBuildResult_Fields tests BuildResult structure.
func TestBuildResult_Fields(t *testing.T) {
	result := &BuildResult{
		Success:    true,
		OutputPath: "/tmp/binary",
		Duration:   100 * time.Millisecond,
		Stdout:     "build output",
		Stderr:     "",
		Error:      nil,
	}

	assert.True(t, result.Success)
	assert.Equal(t, "/tmp/binary", result.OutputPath)
	assert.Equal(t, 100*time.Millisecond, result.Duration)
	assert.Equal(t, "build output", result.Stdout)
	assert.Empty(t, result.Stderr)
	assert.Nil(t, result.Error)
}

// TestTestResult_Fields tests TestResult structure.
func TestTestResult_Fields(t *testing.T) {
	result := &TestResult{
		Success:  true,
		Passed:   10,
		Failed:   2,
		Duration: 500 * time.Millisecond,
		Output:   "test output",
		Error:    nil,
	}

	assert.True(t, result.Success)
	assert.Equal(t, 10, result.Passed)
	assert.Equal(t, 2, result.Failed)
	assert.Equal(t, 500*time.Millisecond, result.Duration)
	assert.Equal(t, "test output", result.Output)
	assert.Nil(t, result.Error)
}

// TestCleanResult_Fields tests CleanResult structure.
func TestCleanResult_Fields(t *testing.T) {
	result := &CleanResult{
		Success:  true,
		Duration: 50 * time.Millisecond,
		Output:   "clean output",
		Error:    nil,
	}

	assert.True(t, result.Success)
	assert.Equal(t, 50*time.Millisecond, result.Duration)
	assert.Equal(t, "clean output", result.Output)
	assert.Nil(t, result.Error)
}

// TestBuildConfig_Fields tests BuildConfig structure.
func TestBuildConfig_Fields(t *testing.T) {
	config := BuildConfig{
		WorkDir:    "/tmp/work",
		Command:    "make",
		Args:       []string{"build"},
		OutputPath: "bin/output",
		Env: map[string]string{
			"KEY": "value",
		},
	}

	assert.Equal(t, "/tmp/work", config.WorkDir)
	assert.Equal(t, "make", config.Command)
	assert.Equal(t, []string{"build"}, config.Args)
	assert.Equal(t, "bin/output", config.OutputPath)
	assert.Equal(t, "value", config.Env["KEY"])
}

// Benchmark tests for performance measurement

func BenchmarkDefaultBuildExecutor_Build(b *testing.B) {
	executor := NewDefaultBuildExecutor()
	ctx := context.Background()
	dir := b.TempDir()

	config := BuildConfig{
		WorkDir: dir,
		Command: "echo",
		Args:    []string{"build"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = executor.Build(ctx, config, "test", "1.0.0", "0.1.0")
	}
}

func BenchmarkDefaultBuildExecutor_Clean(b *testing.B) {
	executor := NewDefaultBuildExecutor()
	ctx := context.Background()
	dir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = executor.Clean(ctx, dir)
	}
}

func BenchmarkDefaultBuildExecutor_Test(b *testing.B) {
	executor := NewDefaultBuildExecutor()
	ctx := context.Background()
	dir := b.TempDir()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = executor.Test(ctx, dir)
	}
}
