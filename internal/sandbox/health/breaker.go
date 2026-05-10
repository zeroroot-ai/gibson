// Package health — breaker.go
//
// CircuitBreaker is a process-wide (tenant-agnostic) circuit breaker for
// Setec dial failures (Task 44, setec-sandbox-prod-default R5.5).
//
// State machine:
//
//	Closed  →(N consecutive failures)→  Open
//	Open    →(cooldown elapsed)→        HalfOpen
//	HalfOpen →(probe succeeds)→         Closed
//	HalfOpen →(probe fails)→            Open (reset cooldown)
//
// The breaker state is observable via the `gibson_sandbox_circuit_breaker`
// Prometheus gauge (0=closed, 1=half-open, 2=open).
//
// Spec: setec-sandbox-prod-default R5.5.
package health

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// BreakerState is the circuit-breaker state enum.
type BreakerState int32

const (
	// BreakerClosed means normal operation: requests pass through.
	BreakerClosed BreakerState = 0

	// BreakerHalfOpen means the cooldown has elapsed and the next probe
	// attempt may close the breaker.
	BreakerHalfOpen BreakerState = 1

	// BreakerOpen means the breaker has tripped: SANDBOXED dispatches are
	// rejected with sandbox_unavailable until the cooldown elapses.
	BreakerOpen BreakerState = 2
)

// BreakerConfig controls the circuit-breaker thresholds.
type BreakerConfig struct {
	// ConsecutiveFailureThreshold is the number of consecutive health-check
	// failures required to open the breaker. Defaults to 3 when zero.
	ConsecutiveFailureThreshold int

	// CooldownWindow is the duration the breaker stays Open before
	// transitioning to HalfOpen. Defaults to 30s when zero.
	CooldownWindow time.Duration
}

// CircuitBreaker is the production sandbox circuit breaker.
// It is safe for concurrent use. All methods are lock-free via atomic ops
// except state transitions that update multiple fields simultaneously (those
// use a mutex for consistency).
type CircuitBreaker struct {
	cfg BreakerConfig

	mu          sync.Mutex
	state       BreakerState
	failures    int       // consecutive failures (reset on success or breaker close)
	openedAt    time.Time // when the breaker last transitioned to Open
	now         func() time.Time

	// Prometheus gauge: 0=closed, 1=half-open, 2=open.
	breakerGauge prometheus.Gauge
}

// NewCircuitBreaker constructs a CircuitBreaker with the given config.
// The breaker starts in the Closed state.
func NewCircuitBreaker(cfg BreakerConfig) *CircuitBreaker {
	if cfg.ConsecutiveFailureThreshold <= 0 {
		cfg.ConsecutiveFailureThreshold = 3
	}
	if cfg.CooldownWindow <= 0 {
		cfg.CooldownWindow = 30 * time.Second
	}

	initHealthMetrics()

	return &CircuitBreaker{
		cfg:          cfg,
		state:        BreakerClosed,
		now:          time.Now,
		breakerGauge: circuitBreakerGauge,
	}
}

// IsOpen returns true when the breaker has tripped and SANDBOXED dispatches
// should be rejected. It also handles the Closed→Open transition when the
// cooldown has elapsed (HalfOpen state is reported as "not open").
func (b *CircuitBreaker) IsOpen() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == BreakerClosed {
		return false
	}
	if b.state == BreakerOpen {
		// Check whether the cooldown has elapsed.
		if b.now().After(b.openedAt.Add(b.cfg.CooldownWindow)) {
			b.setState(BreakerHalfOpen)
			return false // half-open: let one probe through
		}
		return true
	}
	// HalfOpen: allow the probe (not open).
	return false
}

// RecordFailure increments the consecutive-failure counter and opens the
// breaker when the threshold is reached.
func (b *CircuitBreaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures++
	if b.failures >= b.cfg.ConsecutiveFailureThreshold || b.state == BreakerHalfOpen {
		b.setState(BreakerOpen)
		b.openedAt = b.now()
	}
}

// RecordSuccess closes the breaker and resets the failure counter.
func (b *CircuitBreaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.failures = 0
	b.setState(BreakerClosed)
}

// State returns the current breaker state. Callers use this for metrics
// and tracing — dispatch decisions should use IsOpen() to handle cooldown.
func (b *CircuitBreaker) State() BreakerState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// setState is the internal state transition helper. Must be called under b.mu.
func (b *CircuitBreaker) setState(s BreakerState) {
	b.state = s
	if b.breakerGauge != nil {
		b.breakerGauge.Set(float64(s))
	}
}

// ── Prometheus metrics ────────────────────────────────────────────────────────

var (
	healthMetricsOnce   sync.Once
	sandboxHealthGauge  *prometheus.GaugeVec
	circuitBreakerGauge prometheus.Gauge
)

func initHealthMetrics() {
	healthMetricsOnce.Do(func() {
		sandboxHealthGauge = promauto.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gibson_sandbox_health",
				Help: "Current sandbox reachability status: 1=up, 0=down. " +
					"The `status` label carries 'up', 'down', or 'degraded'. " +
					"For the numeric gauge use the label-less variant or filter by status=up.",
			},
			[]string{"status"},
		)
		// Initialise all known label values to zero so the time series exist
		// from the first scrape rather than appearing after the first state change.
		sandboxHealthGauge.WithLabelValues("up").Set(0)
		sandboxHealthGauge.WithLabelValues("down").Set(0)
		sandboxHealthGauge.WithLabelValues("degraded").Set(0)

		circuitBreakerGauge = promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "gibson_sandbox_circuit_breaker",
				Help: "Circuit-breaker state: 0=closed (normal), " +
					"1=half-open (cooldown elapsed; next probe decides), " +
					"2=open (dispatches rejected).",
			},
		)
	})
}

// SetSandboxHealthStatus updates the gibson_sandbox_health gauge.
// Status must be "up", "down", or "degraded".
// All label values are reset to 0 then the active one is set to 1.
func SetSandboxHealthStatus(status string) {
	if sandboxHealthGauge == nil {
		return
	}
	sandboxHealthGauge.WithLabelValues("up").Set(0)
	sandboxHealthGauge.WithLabelValues("down").Set(0)
	sandboxHealthGauge.WithLabelValues("degraded").Set(0)
	sandboxHealthGauge.WithLabelValues(status).Set(1)
}
