// Package component provides circuit breaker functionality for component health management.
//
// This file implements a circuit breaker pattern to prevent cascading failures when
// components become unhealthy. The circuit breaker tracks failures per endpoint and
// temporarily blocks requests to failing endpoints.
package component

import (
	"fmt"
	"sync"
	"time"
)

// CircuitState represents the current state of a circuit breaker.
type CircuitState int

const (
	// StateClosed means the circuit is closed (normal operation, requests allowed)
	StateClosed CircuitState = iota

	// StateOpen means the circuit is open (too many failures, requests blocked)
	StateOpen

	// StateHalfOpen means the circuit is testing if the endpoint has recovered
	StateHalfOpen
)

// String returns a human-readable representation of the circuit state.
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// CircuitBreakerConfig holds configuration for circuit breaker behavior.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures before opening the circuit.
	// Default: 5
	FailureThreshold int

	// OpenTimeout is the duration to wait before transitioning from Open to Half-Open.
	// During this time, all requests to the endpoint are blocked.
	// Default: 30 seconds
	OpenTimeout time.Duration

	// HalfOpenMaxRequests is the number of requests allowed in Half-Open state to test recovery.
	// If any of these fail, the circuit reopens. If all succeed, the circuit closes.
	// Default: 1 (single request test)
	HalfOpenMaxRequests int
}

// DefaultCircuitBreakerConfig returns a configuration with sensible defaults.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		FailureThreshold:    5,
		OpenTimeout:         30 * time.Second,
		HalfOpenMaxRequests: 1,
	}
}

// endpointCircuit tracks the circuit breaker state for a single endpoint.
type endpointCircuit struct {
	// endpoint is the network address this circuit protects
	endpoint string

	// state is the current circuit state
	state CircuitState

	// failures counts consecutive failures in Closed state
	failures int

	// openedAt records when the circuit was opened
	openedAt time.Time

	// halfOpenTests counts successful tests in Half-Open state
	halfOpenTests int

	// lastFailure records the most recent failure time
	lastFailure time.Time
}

// CircuitBreaker manages circuit breakers for multiple endpoints.
//
// The circuit breaker pattern prevents cascading failures by temporarily blocking
// requests to endpoints that are failing. Each endpoint has its own circuit with
// three states:
//
//   - Closed: Normal operation, requests allowed, failures counted
//   - Open: Too many failures, all requests blocked, waiting for timeout
//   - Half-Open: Testing recovery, limited requests allowed
//
// State transitions:
//   - Closed -> Open: After N consecutive failures (FailureThreshold)
//   - Open -> Half-Open: After timeout (OpenTimeout)
//   - Half-Open -> Closed: If test request succeeds
//   - Half-Open -> Open: If test request fails
//
// Thread-safe: All methods can be called concurrently.
//
// Example usage:
//
//	cb := NewCircuitBreaker(DefaultCircuitBreakerConfig())
//
//	// Before making a request
//	if err := cb.Allow("localhost:50051"); err != nil {
//	    log.Printf("Circuit open: %v", err)
//	    return err
//	}
//
//	// After request completes
//	if err := makeRequest(); err != nil {
//	    cb.RecordFailure("localhost:50051", err)
//	} else {
//	    cb.RecordSuccess("localhost:50051")
//	}
type CircuitBreaker struct {
	config   CircuitBreakerConfig
	mu       sync.RWMutex
	circuits map[string]*endpointCircuit
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration.
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		config:   config,
		circuits: make(map[string]*endpointCircuit),
	}
}

// Allow checks if a request to the endpoint is allowed.
//
// Returns nil if the request should proceed, or an error if the circuit is open.
// If the circuit is in Half-Open state, this may transition to Closed after
// successful requests or back to Open after a failure.
//
// This method should be called before attempting to connect to an endpoint.
func (cb *CircuitBreaker) Allow(endpoint string) error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	circuit := cb.getOrCreateCircuit(endpoint)

	switch circuit.state {
	case StateClosed:
		// Normal operation - allow request
		return nil

	case StateOpen:
		// Check if we should transition to Half-Open
		if time.Since(circuit.openedAt) >= cb.config.OpenTimeout {
			// Timeout expired - transition to Half-Open
			circuit.state = StateHalfOpen
			circuit.halfOpenTests = 0
			return nil
		}
		// Still in timeout period - reject request
		return &CircuitOpenError{
			Endpoint:   endpoint,
			OpenedAt:   circuit.openedAt,
			RetryAfter: circuit.openedAt.Add(cb.config.OpenTimeout),
		}

	case StateHalfOpen:
		// Allow limited requests in Half-Open state
		if circuit.halfOpenTests < cb.config.HalfOpenMaxRequests {
			circuit.halfOpenTests++
			return nil
		}
		// Already at max half-open requests - reject
		return &CircuitOpenError{
			Endpoint:   endpoint,
			OpenedAt:   circuit.openedAt,
			RetryAfter: circuit.openedAt.Add(cb.config.OpenTimeout),
		}

	default:
		// Unknown state - allow request (fail-safe)
		return nil
	}
}

// RecordSuccess records a successful request to the endpoint.
//
// This resets the failure counter in Closed state or transitions Half-Open to Closed.
func (cb *CircuitBreaker) RecordSuccess(endpoint string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	circuit := cb.getOrCreateCircuit(endpoint)

	switch circuit.state {
	case StateClosed:
		// Reset failure counter on success
		circuit.failures = 0

	case StateHalfOpen:
		// Success in Half-Open - transition to Closed
		circuit.state = StateClosed
		circuit.failures = 0
		circuit.halfOpenTests = 0

	case StateOpen:
		// Success in Open state shouldn't happen (requests are blocked)
		// But if it does, treat it like Half-Open success
		circuit.state = StateClosed
		circuit.failures = 0
	}
}

// RecordFailure records a failed request to the endpoint.
//
// This increments the failure counter and may open the circuit if the threshold is reached.
func (cb *CircuitBreaker) RecordFailure(endpoint string, err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	circuit := cb.getOrCreateCircuit(endpoint)
	circuit.lastFailure = time.Now()

	switch circuit.state {
	case StateClosed:
		// Increment failure counter
		circuit.failures++
		// Check if we should open the circuit
		if circuit.failures >= cb.config.FailureThreshold {
			circuit.state = StateOpen
			circuit.openedAt = time.Now()
		}

	case StateHalfOpen:
		// Failure in Half-Open - reopen the circuit
		circuit.state = StateOpen
		circuit.openedAt = time.Now()
		circuit.failures = cb.config.FailureThreshold // Already at threshold
		circuit.halfOpenTests = 0

	case StateOpen:
		// Already open - record failure but don't increment counter
		// (counter is already at threshold)
	}
}

// GetState returns the current state of the circuit for the given endpoint.
//
// This is primarily useful for monitoring and debugging.
func (cb *CircuitBreaker) GetState(endpoint string) CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	circuit, exists := cb.circuits[endpoint]
	if !exists {
		return StateClosed // No circuit = closed (healthy)
	}

	// Check if Open circuit should transition to Half-Open
	if circuit.state == StateOpen && time.Since(circuit.openedAt) >= cb.config.OpenTimeout {
		// Note: We don't actually transition here (read-only operation)
		// The transition happens in Allow()
		return StateHalfOpen
	}

	return circuit.state
}

// Reset resets the circuit for the given endpoint to Closed state.
//
// This is useful for manual recovery or when an endpoint has been confirmed healthy.
func (cb *CircuitBreaker) Reset(endpoint string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if circuit, exists := cb.circuits[endpoint]; exists {
		circuit.state = StateClosed
		circuit.failures = 0
		circuit.halfOpenTests = 0
	}
}

// ResetAll resets all circuits to Closed state.
//
// This is useful for testing or when recovering from a system-wide outage.
func (cb *CircuitBreaker) ResetAll() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	for _, circuit := range cb.circuits {
		circuit.state = StateClosed
		circuit.failures = 0
		circuit.halfOpenTests = 0
	}
}

// Stats returns statistics about all circuits.
//
// This is useful for monitoring dashboards and health checks.
func (cb *CircuitBreaker) Stats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	stats := CircuitBreakerStats{
		Total:         len(cb.circuits),
		ClosedCount:   0,
		OpenCount:     0,
		HalfOpenCount: 0,
		Endpoints:     make(map[string]EndpointStats),
	}

	for endpoint, circuit := range cb.circuits {
		state := circuit.state
		// Check if Open circuit should be considered Half-Open
		if state == StateOpen && time.Since(circuit.openedAt) >= cb.config.OpenTimeout {
			state = StateHalfOpen
		}

		switch state {
		case StateClosed:
			stats.ClosedCount++
		case StateOpen:
			stats.OpenCount++
		case StateHalfOpen:
			stats.HalfOpenCount++
		}

		stats.Endpoints[endpoint] = EndpointStats{
			State:       state,
			Failures:    circuit.failures,
			OpenedAt:    circuit.openedAt,
			LastFailure: circuit.lastFailure,
		}
	}

	return stats
}

// getOrCreateCircuit returns the circuit for the endpoint, creating it if needed.
// Must be called with mu locked.
func (cb *CircuitBreaker) getOrCreateCircuit(endpoint string) *endpointCircuit {
	circuit, exists := cb.circuits[endpoint]
	if !exists {
		circuit = &endpointCircuit{
			endpoint: endpoint,
			state:    StateClosed,
			failures: 0,
		}
		cb.circuits[endpoint] = circuit
	}
	return circuit
}

// CircuitBreakerStats provides aggregate statistics about all circuits.
type CircuitBreakerStats struct {
	// Total number of tracked endpoints
	Total int

	// ClosedCount is the number of circuits in Closed state
	ClosedCount int

	// OpenCount is the number of circuits in Open state
	OpenCount int

	// HalfOpenCount is the number of circuits in Half-Open state
	HalfOpenCount int

	// Endpoints maps endpoint addresses to their individual stats
	Endpoints map[string]EndpointStats
}

// EndpointStats provides statistics about a single endpoint circuit.
type EndpointStats struct {
	// State is the current circuit state
	State CircuitState

	// Failures is the consecutive failure count
	Failures int

	// OpenedAt is when the circuit was opened (zero if never opened)
	OpenedAt time.Time

	// LastFailure is when the most recent failure occurred (zero if never failed)
	LastFailure time.Time
}

// CircuitOpenError is returned when a circuit is open and requests are blocked.
type CircuitOpenError struct {
	Endpoint   string
	OpenedAt   time.Time
	RetryAfter time.Time
}

// Error implements the error interface.
func (e *CircuitOpenError) Error() string {
	return fmt.Sprintf("circuit open for endpoint %s (opened at %s, retry after %s)",
		e.Endpoint, e.OpenedAt.Format(time.RFC3339), e.RetryAfter.Format(time.RFC3339))
}
