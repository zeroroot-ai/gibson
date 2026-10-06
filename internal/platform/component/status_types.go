// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

// HealthCheckProtocol is the protocol a health check used. It lived in the
// component.yaml schema until gibson#555; the status checker is its one
// remaining producer.
type HealthCheckProtocol string

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
