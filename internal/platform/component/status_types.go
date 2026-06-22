package component

import (
	"time"
)

// ProcessState represents the state of a component's process.
type ProcessState string

const (
	// ProcessStateRunning indicates the process is currently running
	ProcessStateRunning ProcessState = "running"

	// ProcessStateDead indicates the process has terminated
	ProcessStateDead ProcessState = "dead"

	// ProcessStateZombie indicates the process is in a zombie state
	// (terminated but not yet reaped by parent)
	ProcessStateZombie ProcessState = "zombie"
)

// String returns the string representation of the ProcessState.
func (p ProcessState) String() string {
	return string(p)
}

// IsValid checks if the ProcessState is a valid enum value.
func (p ProcessState) IsValid() bool {
	switch p {
	case ProcessStateRunning, ProcessStateDead, ProcessStateZombie:
		return true
	default:
		return false
	}
}

// HealthCheckResult represents the result of a health check operation.
// It contains detailed information about the health check status,
// protocol used, timing, and any errors encountered.
type HealthCheckResult struct {
	// Status indicates the health check result.
	// Valid values: "SERVING", "NOT_SERVING", "UNKNOWN", "ERROR"
	Status string

	// Protocol is the health check protocol that was used
	Protocol HealthCheckProtocol

	// ResponseTime is the duration of the health check operation
	ResponseTime time.Duration

	// Error contains the error message if the health check failed.
	// Empty string if the health check succeeded.
	Error string
}

// IsHealthy returns true if the health check status is SERVING.
func (h *HealthCheckResult) IsHealthy() bool {
	return h.Status == "SERVING"
}

// HasError returns true if the health check resulted in an error.
func (h *HealthCheckResult) HasError() bool {
	return h.Error != ""
}

// LogError represents an error found in component logs.
// This is used to track recent errors for debugging purposes.
type LogError struct {
	// Timestamp is when the log error occurred
	Timestamp time.Time

	// Message is the error message content
	Message string

	// Level is the log level (e.g., "ERROR", "WARN", "FATAL")
	Level string
}

// StatusResult represents the comprehensive status of a component.
// This includes process state, health check results, recent errors,
// and uptime information.
type StatusResult struct {
	// Component is the component being checked
	Component *Component

	// ProcessState indicates the current state of the component's process
	ProcessState ProcessState

	// HealthCheck contains the health check result, or nil if health check was not performed
	HealthCheck *HealthCheckResult

	// RecentErrors contains recent errors from component logs
	RecentErrors []LogError

	// Uptime is the duration the component has been running.
	// Zero if the component is not running.
	Uptime time.Duration
}

// IsRunning returns true if the component process is in running state.
func (s *StatusResult) IsRunning() bool {
	return s.ProcessState == ProcessStateRunning
}

// IsHealthy returns true if the component is running and healthy.
func (s *StatusResult) IsHealthy() bool {
	return s.IsRunning() && s.HealthCheck != nil && s.HealthCheck.IsHealthy()
}

// HasRecentErrors returns true if there are any recent errors.
func (s *StatusResult) HasRecentErrors() bool {
	return len(s.RecentErrors) > 0
}
