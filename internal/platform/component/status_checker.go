// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// StatusChecker orchestrates status gathering for components.
// It combines process state checking, health checks, log parsing,
// and uptime calculation to provide comprehensive component status.
type StatusChecker struct {
	logsDir string // Path to logs directory (e.g., ~/.gibson/logs)
}

// 1. Check process state

// 2. Calculate uptime

// Ensure uptime is not negative (in case of clock skew)

// 3. Perform health check (only if component is running)

// 4. Parse recent errors from logs

// Don't fail the entire status check if log parsing fails
// Just use empty slice and continue

// 5. Build and return StatusResult

// Measure response time

// Simple TCP connection check

// Build result based on error

// Connection failed

// Connection succeeded
