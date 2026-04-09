package harness

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/types"
)

// ComplianceHealthCheck adapts a ComplianceMiddleware into an
// observability.HealthChecker — reports unhealthy when the signal fail
// buffer reaches 90% capacity, per audit-compliance-emitter Requirement
// 11.3. Consumed by /readyz, NOT /healthz (the emitter being stuck is a
// readiness concern, not a liveness one).
//
// Implements the HealthChecker interface declared in
// core/gibson/internal/observability/health.go — returned via the
// anonymous interface shape to avoid importing observability here
// (observability would create an import cycle).
type ComplianceHealthCheck struct {
	middleware *ComplianceMiddleware
}

// NewComplianceHealthCheck constructs a health check adapter for the given
// middleware. The middleware must be non-nil.
func NewComplianceHealthCheck(m *ComplianceMiddleware) *ComplianceHealthCheck {
	return &ComplianceHealthCheck{middleware: m}
}

// Health returns the current health status.
//
// Thresholds (Requirement 11.3):
//   - buffer ≥ 90% of capacity → unhealthy
//   - buffer ≥ 70% of capacity → degraded
//   - otherwise              → healthy
func (c *ComplianceHealthCheck) Health(ctx context.Context) types.HealthStatus {
	if c.middleware == nil {
		return types.Unhealthy("compliance middleware is not configured")
	}
	depth := c.middleware.BufferLen()
	cap := c.middleware.BufferCap()
	if cap == 0 {
		return types.Healthy("compliance emitter buffer capacity is zero (unbounded)")
	}

	ratio := float64(depth) / float64(cap)

	switch {
	case ratio >= 0.9:
		return types.Unhealthy(fmt.Sprintf(
			"compliance signal buffer at %.0f%% capacity (%d / %d) — persistence backend likely failing",
			ratio*100, depth, cap,
		))
	case ratio >= 0.7:
		return types.Degraded(fmt.Sprintf(
			"compliance signal buffer at %.0f%% capacity (%d / %d)",
			ratio*100, depth, cap,
		))
	default:
		return types.Healthy(fmt.Sprintf(
			"compliance signal buffer at %.0f%% capacity (%d / %d)",
			ratio*100, depth, cap,
		))
	}
}
