package resilience_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"github.com/zeroroot-ai/gibson/internal/infra/resilience"
)

var errFake = errors.New("fake error")

// executeOK runs fn through the breaker and expects no error.
func executeOK(t *testing.T, cb *gobreaker.CircuitBreaker) {
	t.Helper()
	_, err := cb.Execute(func() (interface{}, error) { return nil, nil })
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

// executeFail runs fn through the breaker returning an error.
func executeFail(t *testing.T, cb *gobreaker.CircuitBreaker) error {
	t.Helper()
	_, err := cb.Execute(func() (interface{}, error) { return nil, errFake })
	return err
}

// ---------------------------------------------------------------------------
// DefaultCircuitConfig
// ---------------------------------------------------------------------------

func TestDefaultCircuitConfig_Values(t *testing.T) {
	t.Parallel()

	cfg := resilience.DefaultCircuitConfig()

	if cfg.ConsecutiveFailures != 5 {
		t.Errorf("ConsecutiveFailures: got %d, want 5", cfg.ConsecutiveFailures)
	}
	if cfg.Interval != 60*time.Second {
		t.Errorf("Interval: got %v, want 60s", cfg.Interval)
	}
	if cfg.Timeout != 30*time.Second {
		t.Errorf("Timeout: got %v, want 30s", cfg.Timeout)
	}
}

// ---------------------------------------------------------------------------
// Zero config fallback
// ---------------------------------------------------------------------------

func TestNewBreaker_ZeroConfigUsesDefaults(t *testing.T) {
	t.Parallel()

	// A zero CircuitConfig should be substituted with defaults, meaning
	// the breaker trips after 5 consecutive failures, not 0.
	cb := resilience.NewBreaker("zero-cfg", resilience.CircuitConfig{}, nil)
	if cb == nil {
		t.Fatal("expected non-nil CircuitBreaker")
	}

	def := resilience.DefaultCircuitConfig()

	// Inject (ConsecutiveFailures - 1) failures; circuit should stay Closed.
	for range def.ConsecutiveFailures - 1 {
		_ = executeFail(t, cb)
	}
	if cb.State() != gobreaker.StateClosed {
		t.Fatalf("expected Closed after %d failures, got %s", def.ConsecutiveFailures-1, cb.State())
	}

	// One more failure trips it Open.
	_ = executeFail(t, cb)
	if cb.State() != gobreaker.StateOpen {
		t.Fatalf("expected Open after %d failures, got %s", def.ConsecutiveFailures, cb.State())
	}
}

// ---------------------------------------------------------------------------
// Breaker opens after N consecutive failures
// ---------------------------------------------------------------------------

func TestNewBreaker_OpensAfterNConsecutiveFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name                string
		consecutiveFailures uint32
	}{
		{"threshold-3", 3},
		{"threshold-5", 5},
		{"threshold-1", 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := resilience.CircuitConfig{
				ConsecutiveFailures: tc.consecutiveFailures,
				Interval:            10 * time.Second,
				Timeout:             100 * time.Millisecond,
			}
			cb := resilience.NewBreaker(tc.name, cfg, nil)

			// Drive (threshold - 1) failures — circuit must remain Closed.
			for range tc.consecutiveFailures - 1 {
				_ = executeFail(t, cb)
			}
			if cb.State() != gobreaker.StateClosed {
				t.Fatalf("premature Open after %d failures (threshold=%d)", tc.consecutiveFailures-1, tc.consecutiveFailures)
			}

			// The N-th failure opens the circuit.
			_ = executeFail(t, cb)
			if cb.State() != gobreaker.StateOpen {
				t.Fatalf("circuit not Open after %d failures", tc.consecutiveFailures)
			}

			// Further calls are rejected without executing the function.
			_, err := cb.Execute(func() (interface{}, error) { return nil, nil })
			if !errors.Is(err, gobreaker.ErrOpenState) {
				t.Fatalf("expected ErrOpenState, got: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Half-open probe is admitted after Timeout
// ---------------------------------------------------------------------------

func TestNewBreaker_HalfOpenProbeAdmittedAfterTimeout(t *testing.T) {
	t.Parallel()

	cfg := resilience.CircuitConfig{
		ConsecutiveFailures: 1,
		Interval:            10 * time.Second,
		Timeout:             50 * time.Millisecond, // short for test speed
	}
	cb := resilience.NewBreaker("half-open-probe", cfg, nil)

	// Trip open.
	_ = executeFail(t, cb)
	if cb.State() != gobreaker.StateOpen {
		t.Fatalf("expected Open, got %s", cb.State())
	}

	// Before timeout: calls must be rejected.
	_, err := cb.Execute(func() (interface{}, error) { return nil, nil })
	if !errors.Is(err, gobreaker.ErrOpenState) {
		t.Fatalf("expected ErrOpenState before timeout, got: %v", err)
	}

	// Wait for the breaker to become Half-Open.
	time.Sleep(cfg.Timeout + 20*time.Millisecond)

	// The first call after the timeout is the half-open probe — it must be admitted.
	_, probeErr := cb.Execute(func() (interface{}, error) { return nil, nil })
	if probeErr != nil {
		t.Fatalf("probe call should be admitted; got: %v", probeErr)
	}
}

// ---------------------------------------------------------------------------
// Successful probe closes the circuit
// ---------------------------------------------------------------------------

func TestNewBreaker_SuccessfulProbeClosesCircuit(t *testing.T) {
	t.Parallel()

	cfg := resilience.CircuitConfig{
		ConsecutiveFailures: 1,
		Interval:            10 * time.Second,
		Timeout:             50 * time.Millisecond,
	}
	cb := resilience.NewBreaker("close-on-success", cfg, nil)

	// Trip open.
	_ = executeFail(t, cb)

	// Wait for half-open.
	time.Sleep(cfg.Timeout + 20*time.Millisecond)

	// Successful probe.
	executeOK(t, cb)

	// Circuit must be Closed now.
	if cb.State() != gobreaker.StateClosed {
		t.Fatalf("expected Closed after successful probe, got %s", cb.State())
	}

	// Subsequent calls must succeed normally.
	executeOK(t, cb)
}

// ---------------------------------------------------------------------------
// OnStateChange fires on each transition
// ---------------------------------------------------------------------------

func TestNewBreaker_OnStateChangeFires(t *testing.T) {
	t.Parallel()

	type transition struct {
		from gobreaker.State
		to   gobreaker.State
	}

	var mu sync.Mutex
	var recorded []transition

	onStateChange := func(name string, from, to gobreaker.State) {
		mu.Lock()
		recorded = append(recorded, transition{from, to})
		mu.Unlock()
	}

	cfg := resilience.CircuitConfig{
		ConsecutiveFailures: 2,
		Interval:            10 * time.Second,
		Timeout:             50 * time.Millisecond,
	}
	cb := resilience.NewBreaker("state-change-test", cfg, onStateChange)

	// Two failures → Closed → Open.
	_ = executeFail(t, cb)
	_ = executeFail(t, cb)

	// Wait for Half-Open.
	time.Sleep(cfg.Timeout + 20*time.Millisecond)

	// Successful probe → Half-Open → Closed.
	executeOK(t, cb)

	mu.Lock()
	defer mu.Unlock()

	// Expect at least: Closed→Open, then Open→HalfOpen (implicit on first
	// Execute after timeout), then HalfOpen→Closed.
	if len(recorded) < 2 {
		t.Fatalf("expected at least 2 state changes, got %d: %v", len(recorded), recorded)
	}

	// First transition must be Closed → Open.
	if recorded[0].from != gobreaker.StateClosed || recorded[0].to != gobreaker.StateOpen {
		t.Errorf("first transition: want Closed→Open, got %s→%s", recorded[0].from, recorded[0].to)
	}

	// Last transition must end in Closed.
	last := recorded[len(recorded)-1]
	if last.to != gobreaker.StateClosed {
		t.Errorf("last transition: want *→Closed, got %s→%s", last.from, last.to)
	}
}

// ---------------------------------------------------------------------------
// Name is preserved
// ---------------------------------------------------------------------------

func TestNewBreaker_NamePreserved(t *testing.T) {
	t.Parallel()

	name := fmt.Sprintf("my-breaker-%d", time.Now().UnixNano())
	cb := resilience.NewBreaker(name, resilience.DefaultCircuitConfig(), nil)
	if cb.Name() != name {
		t.Errorf("Name: got %q, want %q", cb.Name(), name)
	}
}
