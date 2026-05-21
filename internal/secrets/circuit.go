package secrets

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	sdksecrets "github.com/zero-day-ai/platform-clients/secrets"
)

// circuitState is the state of a single (tenant, provider) circuit.
type circuitState int

const (
	circuitClosed   circuitState = 0 // normal operation
	circuitOpen     circuitState = 1 // fast-failing all requests
	circuitHalfOpen circuitState = 2 // allowing one probe request
)

func (s circuitState) String() string {
	switch s {
	case circuitClosed:
		return "closed"
	case circuitOpen:
		return "open"
	case circuitHalfOpen:
		return "half_open"
	default:
		return "unknown"
	}
}

// circuitBreakerConfig holds the configurable thresholds for the circuit
// breaker. The values below match the requirements spec exactly and are not
// exported — production code uses NewCircuitBreaker which applies them.
const (
	// cbFailureThreshold is the number of consecutive failures within
	// cbFailureWindow that open the circuit.
	cbFailureThreshold = 5

	// cbFailureWindow is the time window in which cbFailureThreshold
	// failures must occur to open the circuit.
	cbFailureWindow = 60 * time.Second

	// cbOpenDuration is how long the circuit stays open before it
	// transitions to half-open to admit a single probe call.
	cbOpenDuration = 30 * time.Second
)

// circuitEntry holds the per-(tenant, provider) state for the circuit breaker.
type circuitEntry struct {
	mu sync.Mutex

	state circuitState

	// consecutiveFailures counts failures that have occurred within the
	// current failure window starting at windowStart.
	consecutiveFailures int
	windowStart         time.Time

	// openedAt is when the circuit last transitioned to open.
	openedAt time.Time

	// halfOpenInFlight is true while a single probe attempt is in flight
	// in the half-open state. It prevents a second caller from slipping
	// through before the probe resolves.
	halfOpenInFlight bool
}

// circuitKey is the map key for the per-(tenant, provider) circuit entries.
type circuitKey struct {
	tenant   string
	provider string
}

// Prometheus metrics for circuit breaker state.
var (
	circuitOpenTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_secrets_circuit_open_total",
			Help: "Total number of times a secrets circuit breaker has transitioned to the open state, labeled by tenant and provider.",
		},
		[]string{"tenant", "provider"},
	)

	circuitStateGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gibson_secrets_circuit_state",
			Help: "Current state of a secrets circuit breaker: 0=closed, 1=open, 2=half_open.",
		},
		[]string{"tenant", "provider"},
	)
)

// CircuitBreaker provides per-(tenant, provider) circuit-breaking for
// secrets backend calls. It tracks consecutive failures within a rolling
// 60-second window and opens the circuit after 5 failures. The open period
// is 30 seconds; after that a single probe is admitted (half-open); the
// circuit closes on probe success.
//
// CircuitBreaker is safe for concurrent use.
type CircuitBreaker struct {
	mu      sync.RWMutex
	entries map[circuitKey]*circuitEntry
	clock   func() time.Time // injectable for tests
	logger  *slog.Logger
}

// NewCircuitBreaker constructs a CircuitBreaker. logger must be non-nil.
// The clock function is used to obtain the current time; pass nil to use
// time.Now (production).
func NewCircuitBreaker(logger *slog.Logger, clock func() time.Time) *CircuitBreaker {
	if logger == nil {
		panic("circuit breaker: slog.Logger must not be nil")
	}
	if clock == nil {
		clock = time.Now
	}
	return &CircuitBreaker{
		entries: make(map[circuitKey]*circuitEntry),
		clock:   clock,
		logger:  logger.With("component", "secrets_circuit_breaker"),
	}
}

// Allow returns nil when the circuit is closed or half-open (admitting a
// probe). It returns sdksecrets.ErrUnavailable when the circuit is open.
//
// When the circuit is half-open and no probe is currently in flight, Allow
// marks the probe as in-flight and returns nil so the caller can attempt
// the probe. If a probe is already in flight, subsequent callers receive
// ErrUnavailable until the probe completes.
func (cb *CircuitBreaker) Allow(tenant, provider string) error {
	entry := cb.getOrCreate(tenant, provider)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := cb.clock()

	switch entry.state {
	case circuitClosed:
		return nil

	case circuitOpen:
		if now.Sub(entry.openedAt) >= cbOpenDuration {
			// Transition to half-open: admit one probe.
			entry.state = circuitHalfOpen
			entry.halfOpenInFlight = true
			circuitStateGauge.WithLabelValues(tenant, provider).Set(float64(circuitHalfOpen))
			return nil
		}
		return fmt.Errorf("circuit breaker: open for tenant=%s provider=%s: %w", tenant, provider, sdksecrets.ErrUnavailable)

	case circuitHalfOpen:
		if !entry.halfOpenInFlight {
			// Admit the probe.
			entry.halfOpenInFlight = true
			return nil
		}
		// Probe already in flight — fast-fail this caller.
		return fmt.Errorf("circuit breaker: half-open probe in flight for tenant=%s provider=%s: %w", tenant, provider, sdksecrets.ErrUnavailable)
	}
	return nil
}

// RecordSuccess records a successful operation. If the circuit is half-open,
// this closes it (probe succeeded). In closed state it resets the consecutive
// failure count.
func (cb *CircuitBreaker) RecordSuccess(tenant, provider string) {
	entry := cb.getOrCreate(tenant, provider)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.state == circuitHalfOpen {
		cb.logger.InfoContext(nil, "secrets circuit closed after successful probe",
			slog.String("tenant", tenant),
			slog.String("provider", provider),
		)
	}

	entry.state = circuitClosed
	entry.consecutiveFailures = 0
	entry.halfOpenInFlight = false
	circuitStateGauge.WithLabelValues(tenant, provider).Set(float64(circuitClosed))
}

// RecordFailure records a failed operation. If this failure crosses the
// threshold within the failure window, the circuit transitions to open.
func (cb *CircuitBreaker) RecordFailure(tenant, provider string) {
	entry := cb.getOrCreate(tenant, provider)
	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := cb.clock()

	// Reset the window if the previous failure was outside the window.
	if now.Sub(entry.windowStart) > cbFailureWindow {
		entry.consecutiveFailures = 0
		entry.windowStart = now
	}

	entry.consecutiveFailures++
	entry.halfOpenInFlight = false

	if entry.state == circuitHalfOpen {
		// Probe failed — re-open the circuit.
		entry.state = circuitOpen
		entry.openedAt = now
		circuitOpenTotal.WithLabelValues(tenant, provider).Inc()
		circuitStateGauge.WithLabelValues(tenant, provider).Set(float64(circuitOpen))
		cb.logger.WarnContext(nil, "secrets circuit re-opened after probe failure",
			slog.String("tenant", tenant),
			slog.String("provider", provider),
		)
		return
	}

	if entry.consecutiveFailures >= cbFailureThreshold && entry.state == circuitClosed {
		entry.state = circuitOpen
		entry.openedAt = now
		circuitOpenTotal.WithLabelValues(tenant, provider).Inc()
		circuitStateGauge.WithLabelValues(tenant, provider).Set(float64(circuitOpen))
		cb.logger.WarnContext(nil, "secrets circuit opened",
			slog.String("tenant", tenant),
			slog.String("provider", provider),
			slog.Int("consecutive_failures", entry.consecutiveFailures),
			slog.Duration("window", cbFailureWindow),
		)
	}
}

// State returns the current circuit state for the given (tenant, provider)
// pair. This is used by the registry's Health() and by tests.
func (cb *CircuitBreaker) State(tenant, provider string) circuitState {
	entry := cb.getOrCreate(tenant, provider)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	return entry.state
}

// getOrCreate returns the circuitEntry for the given (tenant, provider) key,
// creating it if it does not yet exist.
func (cb *CircuitBreaker) getOrCreate(tenant, provider string) *circuitEntry {
	key := circuitKey{tenant: tenant, provider: provider}

	cb.mu.RLock()
	e, ok := cb.entries[key]
	cb.mu.RUnlock()
	if ok {
		return e
	}

	cb.mu.Lock()
	defer cb.mu.Unlock()
	// Double-check after acquiring write lock.
	if e, ok := cb.entries[key]; ok {
		return e
	}
	e = &circuitEntry{
		state:       circuitClosed,
		windowStart: cb.clock(),
	}
	cb.entries[key] = e
	// Initialise the gauge to 0 (closed) so it appears in Prometheus even
	// before any state change.
	circuitStateGauge.WithLabelValues(tenant, provider).Set(float64(circuitClosed))
	return e
}
