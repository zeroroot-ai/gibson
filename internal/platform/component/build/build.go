// Package build provides build execution functionality for external components.
package build

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// BuildConfig contains configuration for building a component.
type BuildConfig struct {
	// WorkDir is the working directory where build commands are executed
	WorkDir string
	// Command is the build command to execute (e.g., "make build")
	Command string
	// Args are additional arguments for the build command
	Args []string
	// OutputPath is the expected path to the built binary (relative to WorkDir)
	OutputPath string
	// Env contains additional environment variables for the build
	Env map[string]string
	// Verbose enables real-time streaming of build output to stdout/stderr
	Verbose bool
}

// BuildResult contains the result of a build operation.
type BuildResult struct {
	// Success indicates whether the build succeeded
	Success bool
	// OutputPath is the path to the built binary
	OutputPath string
	// Duration is how long the build took
	Duration time.Duration
	// Stdout contains the standard output from the build
	Stdout string
	// Stderr contains the standard error from the build
	Stderr string
	// Error contains any error that occurred during the build
	Error error
}

// TestResult contains the result of a test operation.
type TestResult struct {
	// Success indicates whether all tests passed
	Success bool
	// Passed is the number of tests that passed
	Passed int
	// Failed is the number of tests that failed
	Failed int
	// Duration is how long the tests took
	Duration time.Duration
	// Output contains the test output
	Output string
	// Error contains any error that occurred during testing
	Error error
}

// CleanResult contains the result of a clean operation.
type CleanResult struct {
	// Success indicates whether the clean succeeded
	Success bool
	// Duration is how long the clean took
	Duration time.Duration
	// Output contains the clean output
	Output string
	// Error contains any error that occurred during cleaning
	Error error
}

// BuildExecutor defines the interface for building components.
type BuildExecutor interface {
	// Build executes the build command and returns the result.
	Build(ctx context.Context, config BuildConfig, componentName, componentVersion, gibsonVersion string) (*BuildResult, error)

	// Clean executes "make clean" to clean build artifacts.
	Clean(ctx context.Context, workDir string) (*CleanResult, error)

	// Test executes "make test" to run component tests.
	Test(ctx context.Context, workDir string) (*TestResult, error)
}

// DefaultBuildExecutor is the default implementation of BuildExecutor using os/exec.
type DefaultBuildExecutor struct{}

// NewDefaultBuildExecutor creates a new DefaultBuildExecutor.
func NewDefaultBuildExecutor() *DefaultBuildExecutor {
	return &DefaultBuildExecutor{}
}

// Build executes the build command and returns the result.
func (e *DefaultBuildExecutor) Build(ctx context.Context, config BuildConfig, componentName, componentVersion, gibsonVersion string) (*BuildResult, error) {
	if config.WorkDir == "" {
		return nil, fmt.Errorf("work directory is required")
	}
	if config.Command == "" {
		return nil, fmt.Errorf("build command is required")
	}

	start := time.Now()
	result := &BuildResult{}

	// Verify work directory exists
	if _, err := os.Stat(config.WorkDir); os.IsNotExist(err) {
		result.Success = false
		result.Duration = time.Since(start)
		result.Error = fmt.Errorf("work directory does not exist: %s", config.WorkDir)
		return result, result.Error
	}

	// Prepare command
	cmd := exec.CommandContext(ctx, config.Command, config.Args...)
	cmd.Dir = config.WorkDir

	// Set environment variables
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("GIBSON_VERSION=%s", gibsonVersion))
	cmd.Env = append(cmd.Env, fmt.Sprintf("COMPONENT_NAME=%s", componentName))
	cmd.Env = append(cmd.Env, fmt.Sprintf("COMPONENT_VERSION=%s", componentVersion))

	// Add custom environment variables
	for key, value := range config.Env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", key, value))
	}

	// Capture stdout and stderr, optionally streaming to console
	var stdout, stderr bytes.Buffer
	if config.Verbose {
		// Stream to console while also capturing
		cmd.Stdout = io.MultiWriter(&stdout, os.Stdout)
		cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	// Execute build command
	err := cmd.Run()
	duration := time.Since(start)

	result.Duration = duration
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("build command failed: %w", err)
		return result, result.Error
	}

	// Verify output binary exists if OutputPath is specified
	if config.OutputPath != "" {
		outputPath := filepath.Join(config.WorkDir, config.OutputPath)
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			result.Success = false
			result.Error = fmt.Errorf("output binary not found at %s", outputPath)
			return result, result.Error
		}
		result.OutputPath = outputPath
	}

	result.Success = true
	return result, nil
}

// Clean executes "make clean" to clean build artifacts.
func (e *DefaultBuildExecutor) Clean(ctx context.Context, workDir string) (*CleanResult, error) {
	if workDir == "" {
		return nil, fmt.Errorf("work directory is required")
	}

	start := time.Now()
	result := &CleanResult{}

	// Verify work directory exists
	if _, err := os.Stat(workDir); os.IsNotExist(err) {
		result.Success = false
		result.Duration = time.Since(start)
		result.Error = fmt.Errorf("work directory does not exist: %s", workDir)
		return result, result.Error
	}

	// Prepare clean command
	cmd := exec.CommandContext(ctx, "make", "clean")
	cmd.Dir = workDir
	cmd.Env = os.Environ()

	// Capture output
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	// Execute clean command
	err := cmd.Run()
	duration := time.Since(start)

	result.Duration = duration
	result.Output = output.String()

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("clean command failed: %w", err)
		return result, result.Error
	}

	result.Success = true
	return result, nil
}

// Test executes "make test" to run component tests.
func (e *DefaultBuildExecutor) Test(ctx context.Context, workDir string) (*TestResult, error) {
	if workDir == "" {
		return nil, fmt.Errorf("work directory is required")
	}

	start := time.Now()
	result := &TestResult{}

	// Verify work directory exists
	if _, err := os.Stat(workDir); os.IsNotExist(err) {
		result.Success = false
		result.Duration = time.Since(start)
		result.Error = fmt.Errorf("work directory does not exist: %s", workDir)
		return result, result.Error
	}

	// Prepare test command
	cmd := exec.CommandContext(ctx, "make", "test")
	cmd.Dir = workDir
	cmd.Env = os.Environ()

	// Capture output
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	// Execute test command
	err := cmd.Run()
	duration := time.Since(start)

	result.Duration = duration
	result.Output = output.String()

	if err != nil {
		result.Success = false
		result.Error = fmt.Errorf("test command failed: %w", err)
		return result, result.Error
	}

	// For now, we assume success means all tests passed
	// In a real implementation, we would parse the test output
	// to determine the number of passed/failed tests
	result.Success = true
	result.Passed = 0 // Would parse from output
	result.Failed = 0

	return result, nil
}
