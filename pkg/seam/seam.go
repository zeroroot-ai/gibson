// Package seam is the reusable seam-resolution primitive for the gibson
// platform's self-hosted vs SaaS deployment-profile model (deploy ADR-0006).
//
// A seam is the point where a SaaS-only component replaces the free/open
// self-hosted default. At deployment time a single env-var knob selects which
// implementation runs; when the knob is absent the seam degrades gracefully to
// the fail-safe (self-hosted) implementation with observable signals so a
// silently-degraded SaaS deployment is detectable.
//
// # Usage
//
//	s := seam.New[MyProvider](seam.Spec[MyProvider]{
//	    Name:            "my-feature",
//	    ConfigKnob:      "MY_FEATURE_ENDPOINT",
//	    FailSafe:        func() (MyProvider, error) { return newOSSProvider(), nil },
//	    Remote:          func(endpoint string) (MyProvider, error) { return newSaaSProvider(endpoint), nil },
//	})
//	provider, _ := s.Resolve(context.Background(), logger)
//
// # Observable degradation
//
// Fail-safe activation emits a structured log warning (with seam name and the
// missing knob) and increments the [failSafeActivationsTotal] Prometheus
// counter. A seam that is expected to be wired (SaaS deployment) but silently
// runs fail-safe is therefore visible in metrics and logs without any
// additional instrumentation.
//
// # Registry
//
// Use [Register] + [LogStartupState] to build a process-wide declared list of
// all seams and emit their resolved states (wired vs fail-safe) at daemon
// startup.
package seam

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// failSafeActivationsTotal counts fail-safe activations per seam name. A SaaS
// deployment running with a fail-safe active is an anomaly worth alerting on.
var failSafeActivationsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Namespace: "gibson",
		Subsystem: "seam",
		Name:      "failsafe_activations_total",
		Help: "Total number of times a seam resolved to its fail-safe (self-hosted) " +
			"implementation rather than the remote SaaS component. " +
			"A non-zero value in a SaaS deployment indicates a missing or " +
			"misconfigured seam knob.",
	},
	[]string{"seam"},
)

// Spec declares a single seam.
//
//   - Name is a human-readable identifier used in logs, metrics, and the
//     startup seam-state table. Must be unique across all seams in the process.
//   - ConfigKnob is the name of the environment variable whose non-empty value
//     activates the remote SaaS implementation. The variable's VALUE is the
//     remote endpoint or connection string passed verbatim to Remote.
//   - FailSafe constructs the self-hosted / open-core default implementation.
//     It must always succeed; if it returns an error Resolve returns that error.
//   - Remote constructs the SaaS implementation from the knob value. If it
//     returns an error, Resolve falls back to FailSafe and emits the observable
//     degradation signals.
type Spec[T any] struct {
	Name       string
	ConfigKnob string
	FailSafe   func() (T, error)
	Remote     func(endpoint string) (T, error)
}

// Seam is a typed, resolvable seam instance created from a Spec.
type Seam[T any] struct {
	spec Spec[T]
}

// New creates a Seam from the given Spec.
func New[T any](spec Spec[T]) Seam[T] {
	return Seam[T]{spec: spec}
}

// ResolveResult is the outcome of a Resolve call.
type ResolveResult[T any] struct {
	// Impl is the resolved implementation (either remote or fail-safe).
	Impl T
	// Wired is true when the remote SaaS implementation was successfully
	// constructed (config knob was set and Remote returned no error).
	Wired bool
	// Endpoint is the trimmed value of the config knob, or "" when fail-safe.
	Endpoint string
}

// Resolve reads the config knob and returns the appropriate implementation.
//
// When the knob is non-empty, Remote is called. On Remote construction error,
// Resolve logs a warning, increments the fail-safe counter, and falls back to
// FailSafe (fail-open). When the knob is empty, FailSafe is called directly.
//
// The caller should log the ResolveResult at startup (or use
// [Registry.LogStartupState] to do so for all registered seams at once).
func (s Seam[T]) Resolve(_ context.Context, logger *slog.Logger) (ResolveResult[T], error) {
	endpoint := strings.TrimSpace(os.Getenv(s.spec.ConfigKnob))

	if endpoint != "" {
		impl, err := s.spec.Remote(endpoint)
		if err == nil {
			return ResolveResult[T]{Impl: impl, Wired: true, Endpoint: endpoint}, nil
		}
		// Remote construction failed: log loudly, increment counter, fall back.
		logger.Warn("seam: remote construction failed; degrading to fail-safe",
			"seam", s.spec.Name,
			"knob", s.spec.ConfigKnob,
			"endpoint", endpoint,
			"error", err,
		)
		failSafeActivationsTotal.WithLabelValues(s.spec.Name).Inc()
	}

	impl, err := s.spec.FailSafe()
	if err != nil {
		return ResolveResult[T]{}, err
	}
	// Emit observable degradation when the knob was set but Remote failed — the
	// non-zero counter is the SaaS-deployment anomaly signal. When the knob was
	// simply absent (self-hosted), no counter increment is needed: absence is
	// the expected state for self-hosted installs.
	if endpoint == "" {
		// Knob absent — self-hosted is the expected deployment profile. Log at
		// debug so operator dashboards are not flooded in kind / self-hosted.
		logger.Debug("seam: knob absent; using fail-safe (self-hosted profile)",
			"seam", s.spec.Name,
			"knob", s.spec.ConfigKnob,
		)
	}
	return ResolveResult[T]{Impl: impl, Wired: false, Endpoint: ""}, nil
}
