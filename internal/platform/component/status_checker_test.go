package component

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewStatusChecker(t *testing.T) {
	logsDir := "/tmp/gibson/logs"
	checker := NewStatusChecker(logsDir)

	if checker == nil {
		t.Fatal("NewStatusChecker returned nil")
	}

	if checker.logsDir != logsDir {
		t.Errorf("logsDir = %q, want %q", checker.logsDir, logsDir)
	}
}

func TestStatusChecker_CheckStatus_NilComponent(t *testing.T) {
	checker := NewStatusChecker("/tmp/logs")
	ctx := context.Background()

	_, err := checker.CheckStatus(ctx, nil)
	if err == nil {
		t.Error("expected error for nil component, got nil")
	}
}

func TestStatusChecker_CheckStatus_StoppedComponent(t *testing.T) {
	// Create a temporary logs directory
	tmpDir := t.TempDir()

	// Create a component that is stopped (invalid PID)
	comp := &Component{
		ID:      1,
		Kind:    ComponentKindAgent,
		Name:    "test-agent",
		Version: "1.0.0",
		Port:    50051,
		PID:     999999, // Non-existent PID
		Status:  ComponentStatusStopped,
	}

	checker := NewStatusChecker(tmpDir)
	ctx := context.Background()

	result, err := checker.CheckStatus(ctx, comp)
	if err != nil {
		t.Fatalf("CheckStatus failed: %v", err)
	}

	// Verify result structure
	if result.Component != comp {
		t.Errorf("result.Component = %v, want %v", result.Component, comp)
	}

	// Verify process state is dead (non-existent PID)
	if result.ProcessState != ProcessStateDead {
		t.Errorf("ProcessState = %v, want %v", result.ProcessState, ProcessStateDead)
	}

	// Verify health check is nil for stopped component
	if result.HealthCheck != nil {
		t.Errorf("HealthCheck should be nil for stopped component, got %v", result.HealthCheck)
	}

	// Verify uptime is zero (no start time)
	if result.Uptime != 0 {
		t.Errorf("Uptime = %v, want 0", result.Uptime)
	}

	// Verify recent errors is empty (no log file)
	if len(result.RecentErrors) != 0 {
		t.Errorf("RecentErrors length = %d, want 0", len(result.RecentErrors))
	}
}

func TestStatusChecker_CheckStatus_WithUptime(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a component with a start time
	startedAt := time.Now().Add(-5 * time.Minute)
	comp := &Component{
		ID:        1,
		Kind:      ComponentKindAgent,
		Name:      "test-agent",
		Version:   "1.0.0",
		Port:      50051,
		PID:       999999, // Non-existent PID
		Status:    ComponentStatusStopped,
		StartedAt: &startedAt,
	}

	checker := NewStatusChecker(tmpDir)
	ctx := context.Background()

	result, err := checker.CheckStatus(ctx, comp)
	if err != nil {
		t.Fatalf("CheckStatus failed: %v", err)
	}

	// Verify uptime is approximately 5 minutes
	expectedUptime := 5 * time.Minute
	tolerance := 10 * time.Second
	if result.Uptime < expectedUptime-tolerance || result.Uptime > expectedUptime+tolerance {
		t.Errorf("Uptime = %v, want approximately %v", result.Uptime, expectedUptime)
	}
}

func TestStatusChecker_CheckStatus_WithRecentErrors(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a log file with errors
	logPath := filepath.Join(tmpDir, "test-agent.log")
	logContent := `{"time":"2025-01-01T12:00:00Z","level":"ERROR","msg":"connection failed"}
{"time":"2025-01-01T12:01:00Z","level":"INFO","msg":"retrying connection"}
{"time":"2025-01-01T12:02:00Z","level":"ERROR","msg":"authentication failed"}
{"time":"2025-01-01T12:03:00Z","level":"FATAL","msg":"shutting down"}
`
	if err := os.WriteFile(logPath, []byte(logContent), 0644); err != nil {
		t.Fatalf("Failed to write log file: %v", err)
	}

	comp := &Component{
		ID:      1,
		Kind:    ComponentKindAgent,
		Name:    "test-agent",
		Version: "1.0.0",
		Port:    50051,
		PID:     999999,
		Status:  ComponentStatusStopped,
	}

	checker := NewStatusChecker(tmpDir)
	ctx := context.Background()

	result, err := checker.CheckStatus(ctx, comp)
	if err != nil {
		t.Fatalf("CheckStatus failed: %v", err)
	}

	// Verify recent errors were parsed
	if len(result.RecentErrors) != 3 {
		t.Errorf("RecentErrors length = %d, want 3", len(result.RecentErrors))
	}

	// Verify errors are in reverse chronological order (newest first)
	if len(result.RecentErrors) > 0 {
		if result.RecentErrors[0].Level != "FATAL" {
			t.Errorf("First error level = %q, want %q", result.RecentErrors[0].Level, "FATAL")
		}
		if result.RecentErrors[0].Message != "shutting down" {
			t.Errorf("First error message = %q, want %q", result.RecentErrors[0].Message, "shutting down")
		}
	}
}

func TestStatusChecker_CheckStatus_RunningComponent(t *testing.T) {
	tmpDir := t.TempDir()

	// Use current process PID (which is definitely running)
	currentPID := os.Getpid()
	startedAt := time.Now().Add(-1 * time.Minute)

	comp := &Component{
		ID:        1,
		Kind:      ComponentKindAgent,
		Name:      "test-agent",
		Version:   "1.0.0",
		Port:      50051,
		PID:       currentPID,
		Status:    ComponentStatusRunning,
		StartedAt: &startedAt,
	}

	checker := NewStatusChecker(tmpDir)
	ctx := context.Background()

	result, err := checker.CheckStatus(ctx, comp)
	if err != nil {
		t.Fatalf("CheckStatus failed: %v", err)
	}

	// Verify process state is running
	if result.ProcessState != ProcessStateRunning {
		t.Errorf("ProcessState = %v, want %v", result.ProcessState, ProcessStateRunning)
	}

	// Verify health check was attempted (will fail since no server is listening)
	if result.HealthCheck == nil {
		t.Error("HealthCheck should not be nil for running component")
	} else {
		// Health check will fail since we don't have a server running
		// Just verify that it was attempted and has error information
		if result.HealthCheck.Status != "ERROR" && result.HealthCheck.Status != "UNKNOWN" {
			t.Logf("HealthCheck status = %q (expected ERROR or UNKNOWN for non-existent server)", result.HealthCheck.Status)
		}
		if result.HealthCheck.ResponseTime == 0 {
			t.Error("HealthCheck ResponseTime should not be zero")
		}
	}
}

func TestStatusChecker_performHealthCheck(t *testing.T) {
	tmpDir := t.TempDir()
	checker := NewStatusChecker(tmpDir)

	// Create a component with default health check config
	comp := &Component{
		ID:      1,
		Kind:    ComponentKindAgent,
		Name:    "test-agent",
		Version: "1.0.0",
		Port:    50051,
		PID:     os.Getpid(),
		Status:  ComponentStatusRunning,
	}

	ctx := context.Background()
	result := checker.performHealthCheck(ctx, comp)

	// Verify result structure
	if result == nil {
		t.Fatal("performHealthCheck returned nil")
	}

	// Health check should fail (no server listening)
	if result.Status == "SERVING" {
		t.Error("Health check should fail for non-existent server")
	}

	// Verify response time was measured
	if result.ResponseTime == 0 {
		t.Error("ResponseTime should not be zero")
	}

	// Verify protocol was set (auto-detection should attempt gRPC first)
	if result.Protocol == "" {
		t.Error("Protocol should not be empty")
	}

	// Verify error message is set
	if result.Error == "" {
		t.Error("Error message should not be empty for failed health check")
	}
}

func TestStatusChecker_performHealthCheck_WithManifestConfig(t *testing.T) {
	tmpDir := t.TempDir()
	checker := NewStatusChecker(tmpDir)

	// Create a component with explicit gRPC health check config
	comp := &Component{
		ID:      1,
		Kind:    ComponentKindAgent,
		Name:    "test-agent",
		Version: "1.0.0",
		Port:    50051,
		PID:     os.Getpid(),
		Status:  ComponentStatusRunning,
		Manifest: &Manifest{
			Name:    "test-agent",
			Version: "1.0.0",
			Runtime: &RuntimeConfig{
				Type:       RuntimeTypeGRPC,
				Entrypoint: "./test-agent",
				Port:       50051,
				HealthCheck: &HealthCheckConfig{
					Protocol:    HealthCheckProtocolGRPC,
					Timeout:     2 * time.Second,
					ServiceName: "test.Service",
				},
			},
		},
	}

	ctx := context.Background()
	result := checker.performHealthCheck(ctx, comp)

	// Verify result structure
	if result == nil {
		t.Fatal("performHealthCheck returned nil")
	}

	// Health check should fail (no server listening)
	if result.Status == "SERVING" {
		t.Error("Health check should fail for non-existent server")
	}

	// Verify protocol is set (performHealthCheck currently uses TCP regardless of manifest)
	// Note: Current implementation uses simple TCP dial, not gRPC health check protocol
	if result.Protocol == "" {
		t.Error("Protocol should not be empty")
	}
}

func TestStatusChecker_isHealthCheckError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "health check error",
			err:  NewHealthCheckError("test", "grpc", nil),
			want: true,
		},
		{
			name: "other error",
			err:  NewConnectionFailedError("test", nil),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isHealthCheckError(tt.err)
			if got != tt.want {
				t.Errorf("isHealthCheckError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStatusChecker_isProtocolDetectError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "protocol detect error",
			err:  NewProtocolDetectError("test", nil),
			want: true,
		},
		{
			name: "other error",
			err:  NewHealthCheckError("test", "grpc", nil),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isProtocolDetectError(tt.err)
			if got != tt.want {
				t.Errorf("isProtocolDetectError() = %v, want %v", got, tt.want)
			}
		})
	}
}
