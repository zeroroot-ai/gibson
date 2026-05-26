package secrets

import (
	"errors"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sony/gobreaker"
	"github.com/zeroroot-ai/platform-clients/resilience"
	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
)

// circuitExecutor is the narrow interface Service needs to execute a
// secrets backend call with per-(tenant, provider) circuit-breaking applied.
type circuitExecutor interface {
	Execute(tenant, provider string, fn func() error) error
}

// ErrCircuitOpen is returned by gobreakerExecutor.Execute when the circuit
// breaker for a (tenant, provider) pair is in the Open or HalfOpen-busy
// state. It wraps sdksecrets.ErrUnavailable so service.go's toGRPCError
// maps it to codes.Unavailable.
var ErrCircuitOpen = fmt.Errorf("secrets circuit open: %w", sdksecrets.ErrUnavailable)

// Prometheus metrics for gobreakerExecutor state transitions.
//
// NOTE: platform-clients/secrets also registers gibson_secrets_circuit_open_total
// and gibson_secrets_circuit_state (for its own gobreaker-backed circuit).
// This daemon-local executor uses _svc_ names to avoid a duplicate-
// registration panic when both packages are linked into the same binary.
var (
	circuitOpenTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gibson_secrets_svc_circuit_open_total",
			Help: "Total number of times the daemon-local secrets service circuit breaker has transitioned to the open state.",
		},
		[]string{"tenant", "provider"},
	)

	circuitStateGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gibson_secrets_svc_circuit_state",
			Help: "Current state of the daemon-local secrets service circuit breaker: 0=closed, 1=open, 2=half_open.",
		},
		[]string{"tenant", "provider"},
	)
)

// gobreakerExecutor is a circuitExecutor backed by sony/gobreaker. It
// maintains one *gobreaker.CircuitBreaker per (tenant, provider) pair,
// created lazily on first use.
//
// gobreakerExecutor is safe for concurrent use.
type gobreakerExecutor struct {
	mu       sync.Mutex // protects breakers for double-checked init
	breakers sync.Map   // key: "tenant/provider" -> *gobreaker.CircuitBreaker
	cfg      resilience.CircuitConfig
}

// NewGobreakerExecutor constructs a gobreakerExecutor using the supplied
// CircuitConfig. Pass resilience.DefaultCircuitConfig() for production.
func NewGobreakerExecutor(cfg resilience.CircuitConfig) *gobreakerExecutor {
	return &gobreakerExecutor{cfg: cfg}
}

// Execute runs fn inside the circuit breaker for (tenant, provider). If the
// circuit is Open or the HalfOpen probe slot is taken, it returns
// ErrCircuitOpen immediately without calling fn. On fn success or failure,
// the underlying gobreaker updates its state automatically.
//
// If gobreaker returns ErrOpenState or ErrTooManyRequests, Execute maps the
// error to ErrCircuitOpen so service.go's toGRPCError yields codes.Unavailable.
func (g *gobreakerExecutor) Execute(tenant, provider string, fn func() error) error {
	cb := g.getOrCreate(tenant, provider)

	_, err := cb.Execute(func() (any, error) {
		return nil, fn()
	})
	if errors.Is(err, gobreaker.ErrOpenState) || errors.Is(err, gobreaker.ErrTooManyRequests) {
		return ErrCircuitOpen
	}
	return err
}

// getOrCreate returns the *gobreaker.CircuitBreaker for the given
// (tenant, provider) key, constructing it if it does not exist.
func (g *gobreakerExecutor) getOrCreate(tenant, provider string) *gobreaker.CircuitBreaker {
	key := tenant + "/" + provider

	// Fast path: already stored.
	if val, ok := g.breakers.Load(key); ok {
		return val.(*gobreaker.CircuitBreaker)
	}

	// Slow path: construct and store, guarding against a concurrent
	// constructor race with the mutex so onStateChange callbacks are only
	// registered once.
	g.mu.Lock()
	defer g.mu.Unlock()

	// Double-check after acquiring the lock.
	if val, ok := g.breakers.Load(key); ok {
		return val.(*gobreaker.CircuitBreaker)
	}

	cb := resilience.NewBreaker(key, g.cfg, func(_ string, from, to gobreaker.State) {
		circuitStateGauge.WithLabelValues(tenant, provider).Set(float64(gobreakerStateToInt(to)))
		if to == gobreaker.StateOpen {
			circuitOpenTotal.WithLabelValues(tenant, provider).Inc()
		}
	})

	// Initialise the gauge to 0 (closed) so it appears in Prometheus even
	// before any state change.
	circuitStateGauge.WithLabelValues(tenant, provider).Set(0)

	g.breakers.Store(key, cb)
	return cb
}

// gobreakerStateToInt maps gobreaker.State to the integer encoding used by
// the Prometheus gauge (0=closed, 1=open, 2=half_open) to preserve
// compatibility with the previous homegrown circuit breaker's metric values.
func gobreakerStateToInt(s gobreaker.State) int {
	switch s {
	case gobreaker.StateClosed:
		return 0
	case gobreaker.StateOpen:
		return 1
	case gobreaker.StateHalfOpen:
		return 2
	default:
		return 0
	}
}
