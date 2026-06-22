package daemon

import (
	"sync"
	"time"
)

// ShutdownMetrics tracks metrics and statistics about the shutdown process.
// This data is used for observability and debugging shutdown behavior.
type ShutdownMetrics struct {
	// StartTime records when the shutdown process began
	StartTime time.Time

	// PhasesDuration tracks the duration of each shutdown phase
	PhasesDuration map[string]time.Duration

	// MissionsCheckpointed counts how many missions were checkpointed
	MissionsCheckpointed int

	// AgentsDisconnected counts how many agents were disconnected
	AgentsDisconnected int

	// RequestsDrained counts how many requests were drained
	RequestsDrained int

	// Errors collects any errors that occurred during shutdown
	Errors []error

	// ForcedExit indicates whether shutdown was forced due to timeout
	ForcedExit bool

	// mu protects concurrent access to metrics
	mu sync.Mutex
}

// NewShutdownMetrics creates a new ShutdownMetrics instance.
func NewShutdownMetrics() *ShutdownMetrics {
	return &ShutdownMetrics{
		StartTime:      time.Now(),
		PhasesDuration: make(map[string]time.Duration),
		Errors:         make([]error, 0),
	}
}

// RecordPhase records the duration of a shutdown phase.
// This is safe for concurrent use.
func (m *ShutdownMetrics) RecordPhase(phaseName string, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.PhasesDuration[phaseName] = duration
}

// AddError records an error that occurred during shutdown.
// This is safe for concurrent use.
func (m *ShutdownMetrics) AddError(err error) {
	if err == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Errors = append(m.Errors, err)
}

// TotalDuration returns the total time spent in shutdown.
func (m *ShutdownMetrics) TotalDuration() time.Duration {
	return time.Since(m.StartTime)
}

// ErrorCount returns the number of errors encountered during shutdown.
func (m *ShutdownMetrics) ErrorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.Errors)
}
