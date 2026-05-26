package resolver

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/component"
)

func TestValidationResult_JSON(t *testing.T) {
	node := &DependencyNode{
		Kind:    component.ComponentKindAgent,
		Name:    "test-agent",
		Version: "1.0.0",
	}

	result := &ValidationResult{
		Valid:           false,
		Summary:         "validation failed",
		TotalComponents: 5,
		InstalledCount:  4,
		RunningCount:    3,
		HealthyCount:    2,
		NotInstalled: []*DependencyNode{
			node,
		},
		NotRunning: []*DependencyNode{},
		Unhealthy:  []*DependencyNode{},
		VersionMismatch: []*VersionMismatchInfo{
			{
				Node:            node,
				RequiredVersion: ">=2.0.0",
				ActualVersion:   "1.0.0",
			},
		},
		ValidatedAt: time.Now(),
		Duration:    500 * time.Millisecond,
	}

	// Test JSON marshaling
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal ValidationResult: %v", err)
	}

	// Verify duration is formatted as string
	jsonStr := string(data)
	if !strings.Contains(jsonStr, `"duration":"`) {
		t.Errorf("expected duration to be formatted as string, got: %s", jsonStr)
	}

	// Test JSON unmarshaling
	var decoded ValidationResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ValidationResult: %v", err)
	}
}

func TestDependencyError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *DependencyError
		contains []string
	}{
		{
			name: "error with code only",
			err: &DependencyError{
				Code:    ErrValidationFailed,
				Message: "validation failed",
			},
			contains: []string{"VALIDATION_FAILED", "validation failed"},
		},
		{
			name: "error with node",
			err: &DependencyError{
				Code:    ErrStartFailed,
				Message: "failed to start",
				Node: &DependencyNode{
					Kind: component.ComponentKindAgent,
					Name: "test-agent",
				},
			},
			contains: []string{"START_FAILED", "component=agent/test-agent", "failed to start"},
		},
		{
			name: "error with cause",
			err: &DependencyError{
				Code:    ErrManifestNotFound,
				Message: "manifest not found",
				Cause:   errors.New("file not found"),
			},
			contains: []string{"MANIFEST_NOT_FOUND", "manifest not found", "file not found"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errMsg := tt.err.Error()
			for _, substr := range tt.contains {
				if !strings.Contains(errMsg, substr) {
					t.Errorf("error message should contain %q, got: %s", substr, errMsg)
				}
			}
		})
	}
}

func TestDependencyError_Unwrap(t *testing.T) {
	cause := errors.New("underlying error")
	err := &DependencyError{
		Code:    ErrStartFailed,
		Message: "start failed",
		Cause:   cause,
	}

	if !errors.Is(err, cause) {
		t.Error("errors.Is should work with wrapped errors")
	}

	unwrapped := errors.Unwrap(err)
	if unwrapped != cause {
		t.Errorf("Unwrap should return cause, got: %v", unwrapped)
	}
}

func TestNewCircularDependencyError(t *testing.T) {
	cyclePath := []string{"agent-a", "tool-b", "plugin-c", "agent-a"}
	err := NewCircularDependencyError(cyclePath)

	if err.Code != ErrCircularDependency {
		t.Errorf("expected code %s, got %s", ErrCircularDependency, err.Code)
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "agent-a -> tool-b -> plugin-c -> agent-a") {
		t.Errorf("error should contain cycle path, got: %s", errMsg)
	}
}

func TestNewManifestNotFoundError(t *testing.T) {
	err := NewManifestNotFoundError("agent", "test-agent")

	if err.Code != ErrManifestNotFound {
		t.Errorf("expected code %s, got %s", ErrManifestNotFound, err.Code)
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "agent/test-agent") {
		t.Errorf("error should contain component kind and name, got: %s", errMsg)
	}
}

func TestNewVersionConstraintError(t *testing.T) {
	node := &DependencyNode{
		Kind: component.ComponentKindTool,
		Name: "test-tool",
	}

	err := NewVersionConstraintError(node, ">=2.0.0", "1.5.0")

	if err.Code != ErrVersionConstraintViolation {
		t.Errorf("expected code %s, got %s", ErrVersionConstraintViolation, err.Code)
	}

	if err.Node != node {
		t.Error("error should contain the node")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, ">=2.0.0") || !strings.Contains(errMsg, "1.5.0") {
		t.Errorf("error should contain version info, got: %s", errMsg)
	}
}

func TestNewStartFailedError(t *testing.T) {
	node := &DependencyNode{
		Kind: component.ComponentKindPlugin,
		Name: "test-plugin",
	}

	cause := errors.New("connection refused")
	err := NewStartFailedError(node, cause)

	if err.Code != ErrStartFailed {
		t.Errorf("expected code %s, got %s", ErrStartFailed, err.Code)
	}

	if err.Node != node {
		t.Error("error should contain the node")
	}

	if err.Cause != cause {
		t.Error("error should contain the cause")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "plugin/test-plugin") || !strings.Contains(errMsg, "connection refused") {
		t.Errorf("error should contain component and cause, got: %s", errMsg)
	}
}

func TestNewValidationFailedError(t *testing.T) {
	result := &ValidationResult{
		Valid:           false,
		TotalComponents: 10,
		NotInstalled: []*DependencyNode{
			{Kind: component.ComponentKindAgent, Name: "agent1"},
		},
		NotRunning: []*DependencyNode{
			{Kind: component.ComponentKindTool, Name: "tool1"},
			{Kind: component.ComponentKindTool, Name: "tool2"},
		},
		Unhealthy: []*DependencyNode{},
		VersionMismatch: []*VersionMismatchInfo{
			{RequiredVersion: ">=2.0.0", ActualVersion: "1.0.0"},
		},
	}

	err := NewValidationFailedError(result)

	if err.Code != ErrValidationFailed {
		t.Errorf("expected code %s, got %s", ErrValidationFailed, err.Code)
	}

	errMsg := err.Error()

	// Should contain counts of each issue type
	expectedSubstrings := []string{
		"1 component(s) not installed",
		"2 component(s) not running",
		"1 version mismatch(es)",
	}

	for _, substr := range expectedSubstrings {
		if !strings.Contains(errMsg, substr) {
			t.Errorf("error message should contain %q, got: %s", substr, errMsg)
		}
	}
}

func TestVersionMismatchInfo(t *testing.T) {
	node := &DependencyNode{
		Kind:    component.ComponentKindAgent,
		Name:    "test-agent",
		Version: ">=2.0.0",
	}

	info := &VersionMismatchInfo{
		Node:            node,
		RequiredVersion: ">=2.0.0",
		ActualVersion:   "1.5.0",
	}

	// Test that info can be marshaled to JSON
	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("failed to marshal VersionMismatchInfo: %v", err)
	}

	// Verify JSON contains expected fields
	jsonStr := string(data)
	if !strings.Contains(jsonStr, "requiredVersion") {
		t.Errorf("JSON should contain requiredVersion field, got: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, "actualVersion") {
		t.Errorf("JSON should contain actualVersion field, got: %s", jsonStr)
	}
}

func TestDependencyErrorCode_String(t *testing.T) {
	tests := []struct {
		code     DependencyErrorCode
		expected string
	}{
		{ErrCircularDependency, "CIRCULAR_DEPENDENCY"},
		{ErrManifestNotFound, "MANIFEST_NOT_FOUND"},
		{ErrVersionConstraintViolation, "VERSION_CONSTRAINT_VIOLATION"},
		{ErrStartFailed, "START_FAILED"},
		{ErrValidationFailed, "VALIDATION_FAILED"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if tt.code.String() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.code.String())
			}
		})
	}
}
