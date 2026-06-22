package resolver

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ValidationResult contains the outcome of dependency validation.
// It provides comprehensive information about the state of all components
// in a dependency tree, including counts, problem components, and version mismatches.
type ValidationResult struct {
	// Valid is true if all dependencies are satisfied and running
	Valid bool `json:"valid" yaml:"valid"`

	// Summary is a human-readable summary of the validation result
	Summary string `json:"summary" yaml:"summary"`

	// TotalComponents is the total number of components in the dependency tree
	TotalComponents int `json:"totalComponents" yaml:"totalComponents"`

	// InstalledCount is the number of components that are installed
	InstalledCount int `json:"installedCount" yaml:"installedCount"`

	// RunningCount is the number of components that are currently running
	RunningCount int `json:"runningCount" yaml:"runningCount"`

	// HealthyCount is the number of components that are healthy
	HealthyCount int `json:"healthyCount" yaml:"healthyCount"`

	// NotInstalled contains components that are not installed
	NotInstalled []*DependencyNode `json:"notInstalled,omitempty" yaml:"notInstalled,omitempty"`

	// NotRunning contains components that are installed but not running
	NotRunning []*DependencyNode `json:"notRunning,omitempty" yaml:"notRunning,omitempty"`

	// Unhealthy contains components that are running but not healthy
	Unhealthy []*DependencyNode `json:"unhealthy,omitempty" yaml:"unhealthy,omitempty"`

	// VersionMismatch contains components with version constraint violations
	VersionMismatch []*VersionMismatchInfo `json:"versionMismatch,omitempty" yaml:"versionMismatch,omitempty"`

	// ValidatedAt is the timestamp when validation was performed
	ValidatedAt time.Time `json:"validatedAt" yaml:"validatedAt"`

	// Duration is how long the validation took
	Duration time.Duration `json:"duration" yaml:"duration"`
}

// MarshalJSON implements custom JSON marshaling to format the duration as a string.
func (v *ValidationResult) MarshalJSON() ([]byte, error) {
	type Alias ValidationResult
	return json.Marshal(&struct {
		Duration string `json:"duration"`
		*Alias
	}{
		Duration: v.Duration.String(),
		Alias:    (*Alias)(v),
	})
}

// UnmarshalJSON implements custom JSON unmarshaling to parse duration from string.
func (v *ValidationResult) UnmarshalJSON(data []byte) error {
	type Alias ValidationResult
	aux := &struct {
		Duration string `json:"duration"`
		*Alias
	}{
		Alias: (*Alias)(v),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Duration != "" {
		duration, err := time.ParseDuration(aux.Duration)
		if err != nil {
			return fmt.Errorf("invalid duration format: %w", err)
		}
		v.Duration = duration
	}

	return nil
}

// VersionMismatchInfo describes a version constraint violation.
// It contains information about which component has a version mismatch,
// what version was required, and what version is actually installed.
type VersionMismatchInfo struct {
	// Node is the dependency node with the version mismatch
	Node *DependencyNode `json:"node" yaml:"node"`

	// RequiredVersion is the version constraint that was specified
	RequiredVersion string `json:"requiredVersion" yaml:"requiredVersion"`

	// ActualVersion is the version that is actually installed
	ActualVersion string `json:"actualVersion" yaml:"actualVersion"`
}

// DependencyError represents a structured error for dependency resolution operations.
// It provides detailed context about what went wrong during dependency resolution,
// including error codes, the component involved, and the underlying cause.
type DependencyError struct {
	// Code is the specific error code for programmatic handling
	Code DependencyErrorCode `json:"code" yaml:"code"`

	// Message is a human-readable error message
	Message string `json:"message" yaml:"message"`

	// Node is the component involved in the error (may be nil for graph-level errors)
	Node *DependencyNode `json:"node,omitempty" yaml:"node,omitempty"`

	// Cause is the underlying error that caused this error (if any)
	Cause error `json:"-" yaml:"-"`
}

// Error implements the error interface, returning a formatted error message.
// Format: "[CODE] message" or "[CODE] message: cause" if cause exists.
// If a node is associated, includes component details.
func (e *DependencyError) Error() string {
	var parts []string

	// Start with error code
	parts = append(parts, fmt.Sprintf("[%s]", e.Code))

	// Add component context if available
	if e.Node != nil {
		parts = append(parts, fmt.Sprintf("component=%s/%s", e.Node.Kind, e.Node.Name))
	}

	// Add message
	parts = append(parts, e.Message)

	msg := strings.Join(parts, " ")

	// Append cause if present
	if e.Cause != nil {
		msg += fmt.Sprintf(": %v", e.Cause)
	}

	return msg
}

// Unwrap returns the underlying cause error for error unwrapping chains.
// This enables using errors.Is() and errors.As() with wrapped errors.
func (e *DependencyError) Unwrap() error {
	return e.Cause
}

// DependencyErrorCode represents specific error codes for dependency resolution operations.
type DependencyErrorCode string

// Dependency error codes
const (
	// ErrCircularDependency indicates a circular dependency was detected in the dependency graph
	ErrCircularDependency DependencyErrorCode = "CIRCULAR_DEPENDENCY"

	// ErrManifestNotFound indicates a component manifest could not be found
	ErrManifestNotFound DependencyErrorCode = "MANIFEST_NOT_FOUND"

	// ErrVersionConstraintViolation indicates a version constraint is not satisfied
	ErrVersionConstraintViolation DependencyErrorCode = "VERSION_CONSTRAINT_VIOLATION"

	// ErrStartFailed indicates a component failed to start
	ErrStartFailed DependencyErrorCode = "START_FAILED"

	// ErrValidationFailed indicates validation of the dependency tree failed
	ErrValidationFailed DependencyErrorCode = "VALIDATION_FAILED"
)

// String returns the string representation of the error code.
func (c DependencyErrorCode) String() string {
	return string(c)
}

// NewCircularDependencyError creates a dependency error for circular dependency detection.
// The cyclePath parameter should contain the sequence of component names that form the cycle,
// e.g., ["agent-a", "tool-b", "plugin-c", "agent-a"].
func NewCircularDependencyError(cyclePath []string) *DependencyError {
	cycleStr := strings.Join(cyclePath, " -> ")
	return &DependencyError{
		Code:    ErrCircularDependency,
		Message: fmt.Sprintf("circular dependency detected: %s", cycleStr),
		Node:    nil, // Circular dependencies involve multiple nodes
	}
}

// NewManifestNotFoundError creates a dependency error for missing component manifests.
// This error is non-fatal for validation but indicates that the dependency tree may be incomplete.
func NewManifestNotFoundError(kind, name string) *DependencyError {
	return &DependencyError{
		Code:    ErrManifestNotFound,
		Message: fmt.Sprintf("manifest not found for %s/%s - dependency tree may be incomplete", kind, name),
		Node:    nil, // Node can be set by caller if available
	}
}

// NewVersionConstraintError creates a dependency error for version constraint violations.
// This is used when an installed component version does not satisfy the required version constraint.
func NewVersionConstraintError(node *DependencyNode, required, actual string) *DependencyError {
	return &DependencyError{
		Code: ErrVersionConstraintViolation,
		Message: fmt.Sprintf(
			"version constraint not satisfied: required %s, got %s",
			required, actual,
		),
		Node: node,
	}
}

// NewStartFailedError creates a dependency error for component start failures.
// This is used by EnsureRunning when a component fails to start.
func NewStartFailedError(node *DependencyNode, cause error) *DependencyError {
	return &DependencyError{
		Code:    ErrStartFailed,
		Message: fmt.Sprintf("failed to start component %s/%s", node.Kind, node.Name),
		Node:    node,
		Cause:   cause,
	}
}

// NewValidationFailedError creates a dependency error for validation failures.
// This wraps a ValidationResult that contains detailed information about what failed.
func NewValidationFailedError(result *ValidationResult) *DependencyError {
	// Build a detailed message summarizing the issues
	var issues []string

	if len(result.NotInstalled) > 0 {
		issues = append(issues, fmt.Sprintf("%d component(s) not installed", len(result.NotInstalled)))
	}
	if len(result.NotRunning) > 0 {
		issues = append(issues, fmt.Sprintf("%d component(s) not running", len(result.NotRunning)))
	}
	if len(result.Unhealthy) > 0 {
		issues = append(issues, fmt.Sprintf("%d component(s) unhealthy", len(result.Unhealthy)))
	}
	if len(result.VersionMismatch) > 0 {
		issues = append(issues, fmt.Sprintf("%d version mismatch(es)", len(result.VersionMismatch)))
	}

	message := "validation failed"
	if len(issues) > 0 {
		message = fmt.Sprintf("validation failed: %s", strings.Join(issues, ", "))
	}

	return &DependencyError{
		Code:    ErrValidationFailed,
		Message: message,
		Node:    nil, // Validation errors can involve multiple nodes
	}
}
