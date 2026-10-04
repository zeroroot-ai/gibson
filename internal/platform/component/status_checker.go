// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

// StatusChecker orchestrates status gathering for components.
// It combines process state checking, health checks, log parsing,
// and uptime calculation to provide comprehensive component status.
type StatusChecker struct {
	logsDir string // Path to logs directory (e.g., ~/.gibson/logs)
}
