// Package health — probe.go
//
// SandboxProbe is the periodic 30-second Setec reachability probe
// (Task 43, setec-sandbox-prod-default R5.3). It:
//
//   - Dials the Setec frontend on a 30-second ticker.
//   - Updates the `gibson_sandbox_health{status}` gauge on each tick.
//   - Updates the daemon readiness gate (false when the sandbox is unhealthy
//     in saas mode; true in dev/selfhost mode regardless of health).
//   - Feeds RecordSuccess / RecordFailure into the CircuitBreaker so the
//     dispatch gate can deny SANDBOXED calls when Setec is degraded (Task 45).
//
// Anti-flap rule: the gauge and readiness gate flip only after
// `FlipThreshold` consecutive results in the same direction (default: 2).
// A single failed tick does not trip the gate; a single successful tick
// does not re-open it.
//
// Spec: setec-sandbox-prod-default R5.3.
package health

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	defaultProbeInterval  = 30 * time.Second
	defaultFlipThreshold  = 2
)

// ProbeConfig configures SandboxProbe.
type ProbeConfig struct {
	// Pinger is the Setec reachability probe. Required.
	Pinger Pinger

	// Breaker is the circuit breaker to update on each probe result.
	// When nil, circuit-breaker state is not updated.
	Breaker *CircuitBreaker

	// ReadinessGate, when non-nil, is called with the current healthy state
	// on each relevant state change. The daemon wires the health-state
	// manager's sandbox gate here.
	ReadinessGate func(sandboxReady bool)

	// SaaSMode controls readiness gating (same semantics as StartupCheckConfig).
	SaaSMode bool

	// ProbeInterval is the ticker period. Defaults to 30s when zero.
	ProbeInterval time.Duration

	// FlipThreshold is the number of consecutive results needed before flipping
	// the health state. Defaults to 2 when zero. Setting it to 1 disables
	// anti-flap behaviour (not recommended in production).
	FlipThreshold int

	// Logger is the structured logger. Defaults to slog.Default() when nil.
	Logger *slog.Logger
}

// SandboxProbe runs the periodic health probe loop.
//
// Call Run in a goroutine; cancel the context to stop.
type SandboxProbe struct {
	cfg            ProbeConfig
	mu             sync.RWMutex
	healthy        bool
	consecutiveUp  int
	consecutiveDown int
	logger         *slog.Logger
}

// NewSandboxProbe constructs a SandboxProbe.
func NewSandboxProbe(cfg ProbeConfig) *SandboxProbe {
	if cfg.ProbeInterval <= 0 {
		cfg.ProbeInterval = defaultProbeInterval
	}
	if cfg.FlipThreshold <= 0 {
		cfg.FlipThreshold = defaultFlipThreshold
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	initHealthMetrics()
	return &SandboxProbe{
		cfg:     cfg,
		healthy: true, // optimistic initial state; startup check sets the real value
		logger:  logger,
	}
}

// IsHealthy returns the current sandbox health state as seen by the probe.
// Used by Task 45 to populate Input.SandboxHealthy before the gate call.
func (p *SandboxProbe) IsHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.healthy
}

// Run starts the periodic probe loop. It blocks until ctx is cancelled.
func (p *SandboxProbe) Run(ctx context.Context) {
	ticker := time.NewTicker(p.cfg.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probe(ctx)
		}
	}
}

// probe performs a single health check and updates internal state.
func (p *SandboxProbe) probe(ctx context.Context) {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := p.cfg.Pinger.Ping(probeCtx)
	if err == nil {
		p.recordProbeResult(true)
	} else {
		p.logger.Warn("sandbox health probe: Setec unreachable",
			slog.String("error", err.Error()))
		p.recordProbeResult(false)
	}
}

// recordProbeResult updates consecutive counters, flips state on threshold,
// and updates the gauge + readiness gate.
func (p *SandboxProbe) recordProbeResult(up bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if up {
		p.consecutiveUp++
		p.consecutiveDown = 0

		// Feed the circuit breaker.
		if p.cfg.Breaker != nil {
			p.cfg.Breaker.RecordSuccess()
		}

		// Flip healthy if we've hit the threshold and weren't already healthy.
		if !p.healthy && p.consecutiveUp >= p.cfg.FlipThreshold {
			p.healthy = true
			p.logger.Info("sandbox health: Setec frontend reachable; marking sandbox healthy")
			SetSandboxHealthStatus("up")
			if p.cfg.ReadinessGate != nil {
				p.cfg.ReadinessGate(true)
			}
		}
	} else {
		p.consecutiveDown++
		p.consecutiveUp = 0

		// Feed the circuit breaker.
		if p.cfg.Breaker != nil {
			p.cfg.Breaker.RecordFailure()
		}

		// Flip unhealthy if we've hit the threshold and were healthy.
		if p.healthy && p.consecutiveDown >= p.cfg.FlipThreshold {
			p.healthy = false
			p.logger.Warn("sandbox health: Setec frontend unreachable after consecutive failures; marking sandbox unhealthy",
				slog.Int("consecutive_failures", p.consecutiveDown))
			SetSandboxHealthStatus("down")
			// Readiness gate: only flip false in saas mode.
			if p.cfg.ReadinessGate != nil && p.cfg.SaaSMode {
				p.cfg.ReadinessGate(false)
			}
		}
	}
}

// SetDegraded is called by the spot-eviction handler (Phase 11 / Task 48)
// to flip the gauge to "degraded" without affecting the ready/not-ready
// readiness gate. This lets alerts distinguish a spot eviction event from
// a hard Setec outage.
func (p *SandboxProbe) SetDegraded() {
	p.mu.Lock()
	defer p.mu.Unlock()
	SetSandboxHealthStatus("degraded")
	p.logger.Warn("sandbox health: status set to degraded (spot eviction or operator override)")
}
