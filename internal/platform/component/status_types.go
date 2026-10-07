// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

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
