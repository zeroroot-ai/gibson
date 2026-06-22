package component

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"time"
)

// StatusChecker orchestrates status gathering for components.
// It combines process state checking, health checks, log parsing,
// and uptime calculation to provide comprehensive component status.
type StatusChecker struct {
	logsDir string // Path to logs directory (e.g., ~/.gibson/logs)
}

// NewStatusChecker creates a new StatusChecker with the specified logs directory.
// The logsDir should point to the directory where component logs are stored
// (typically ~/.gibson/logs).
func NewStatusChecker(logsDir string) *StatusChecker {
	return &StatusChecker{
		logsDir: logsDir,
	}
}

// CheckStatus performs a comprehensive status check on a component.
// It gathers information about:
//   - Process state (running, dead, zombie)
//   - Uptime (duration since component started)
//   - Health check (if component is running)
//   - Recent errors from logs
//
// The health check is only performed if the component is running.
// For stopped components, the health check result is nil.
//
// Returns a StatusResult containing all gathered information,
// or an error if the status check fails.
func (s *StatusChecker) CheckStatus(ctx context.Context, comp *Component) (*StatusResult, error) {
	if comp == nil {
		return nil, fmt.Errorf("component cannot be nil")
	}

	// 1. Check process state
	processState := CheckProcessState(comp.PID)

	// 2. Calculate uptime
	var uptime time.Duration
	if comp.StartedAt != nil {
		uptime = time.Since(*comp.StartedAt)
		// Ensure uptime is not negative (in case of clock skew)
		if uptime < 0 {
			uptime = 0
		}
	}

	// 3. Perform health check (only if component is running)
	var healthCheck *HealthCheckResult
	if processState == ProcessStateRunning {
		healthCheck = s.performHealthCheck(ctx, comp)
	}

	// 4. Parse recent errors from logs
	logPath := filepath.Join(s.logsDir, comp.Name+".log")
	recentErrors, err := ParseRecentErrors(logPath, 5)
	if err != nil {
		// Don't fail the entire status check if log parsing fails
		// Just use empty slice and continue
		recentErrors = []LogError{}
	}

	// 5. Build and return StatusResult
	return &StatusResult{
		Component:    comp,
		ProcessState: processState,
		HealthCheck:  healthCheck,
		RecentErrors: recentErrors,
		Uptime:       uptime,
	}, nil
}

// performHealthCheck performs a simple port connectivity check on the component.
// Returns a HealthCheckResult with the status, response time,
// and any error that occurred during the health check.
func (s *StatusChecker) performHealthCheck(ctx context.Context, comp *Component) *HealthCheckResult {
	// Measure response time
	startTime := time.Now()

	// Simple TCP connection check
	addr := fmt.Sprintf("localhost:%d", comp.Port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	responseTime := time.Since(startTime)

	// Build result based on error
	result := &HealthCheckResult{
		Protocol:     "tcp",
		ResponseTime: responseTime,
	}

	if err != nil {
		// Connection failed
		result.Error = err.Error()
		result.Status = "ERROR"
	} else {
		// Connection succeeded
		conn.Close()
		result.Status = "SERVING"
	}

	return result
}

// isHealthCheckError checks if the error is a HealthCheckError.
// This indicates the component responded but reported unhealthy status.
func isHealthCheckError(err error) bool {
	if err == nil {
		return false
	}
	var compErr *ComponentError
	if errors.As(err, &compErr) {
		return compErr.Code == ErrCodeHealthCheckFailed
	}
	return false
}

// isProtocolDetectError checks if the error is a ProtocolDetectError.
// This indicates protocol auto-detection failed.
func isProtocolDetectError(err error) bool {
	if err == nil {
		return false
	}
	var compErr *ComponentError
	if errors.As(err, &compErr) {
		return compErr.Code == ErrCodeProtocolDetectFailed
	}
	return false
}
