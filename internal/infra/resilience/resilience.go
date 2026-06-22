// Package resilience provides shared circuit-breaker configuration and
// factory helpers for platform-clients consumers.
//
// All circuit-breaking in the platform (secrets, pools/redis, authz) is
// backed by github.com/sony/gobreaker. This package centralises the
// CircuitConfig type and the NewBreaker factory so every consumer uses
// identical defaults and wiring.
package resilience

import (
	"time"

	"github.com/sony/gobreaker"
)

// CircuitConfig holds the configurable knobs for a sony/gobreaker-backed
// circuit breaker. The zero value is invalid; use DefaultCircuitConfig() to
// obtain production-safe defaults.
type CircuitConfig struct {
	// ConsecutiveFailures is the number of consecutive failures that trip
	// the circuit to the Open state. Must be > 0.
	ConsecutiveFailures uint32

	// Interval is the cyclic period during which failure counts are
	// accumulated. At the end of each interval the counts are cleared.
	// A zero value disables the cyclic clear (counts accumulate until a
	// state transition).
	Interval time.Duration

	// Timeout is how long the circuit stays Open before transitioning to
	// Half-Open to admit one probe request.
	Timeout time.Duration
}

// DefaultCircuitConfig returns production-safe defaults:
//   - 5 consecutive failures to open
//   - 60 s accumulation interval
//   - 30 s open/cool-down timeout
func DefaultCircuitConfig() CircuitConfig {
	return CircuitConfig{
		ConsecutiveFailures: 5,
		Interval:            60 * time.Second,
		Timeout:             30 * time.Second,
	}
}

// NewBreaker constructs a *gobreaker.CircuitBreaker from cfg.
//
// If cfg.ConsecutiveFailures is zero, DefaultCircuitConfig() is substituted
// so callers can safely pass a zero CircuitConfig and still get a working
// breaker.
//
// name identifies the breaker in logs and metrics. onStateChange is called
// on every state transition; pass nil to disable.
func NewBreaker(
	name string,
	cfg CircuitConfig,
	onStateChange func(string, gobreaker.State, gobreaker.State),
) *gobreaker.CircuitBreaker {
	if cfg.ConsecutiveFailures == 0 {
		cfg = DefaultCircuitConfig()
	}

	settings := gobreaker.Settings{
		Name:        name,
		MaxRequests: 1,
		Interval:    cfg.Interval,
		Timeout:     cfg.Timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= cfg.ConsecutiveFailures
		},
		OnStateChange: onStateChange,
	}

	return gobreaker.NewCircuitBreaker(settings)
}
