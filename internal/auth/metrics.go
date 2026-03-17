package auth

import (
	"context"
	"log/slog"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metric name constants for authentication observability.
const (
	// MetricAuthAttempts counts authentication attempts by issuer and result.
	// Labels: issuer (oidc issuer URL, "kubernetes", "local"), result (success, failure, error)
	MetricAuthAttempts = "gibson.auth.attempts"

	// MetricAuthLatency measures authentication latency by issuer.
	// Labels: issuer (oidc issuer URL, "kubernetes", "local")
	MetricAuthLatency = "gibson.auth.latency"

	// MetricJWKSCacheHits counts JWKS cache hits and misses.
	// Labels: issuer (oidc issuer URL), hit (true, false)
	MetricJWKSCacheHits = "gibson.auth.jwks_cache"

	// MetricAuthPermissionDenied counts permission denied events.
	// Labels: action, resource
	MetricAuthPermissionDenied = "gibson.auth.permission_denied"
)

// authMetrics holds the initialized metric instruments.
type authMetrics struct {
	attempts         metric.Int64Counter
	latency          metric.Float64Histogram
	jwksCacheHits    metric.Int64Counter
	permissionDenied metric.Int64Counter
}

var (
	metricsInstance *authMetrics
	metricsOnce     sync.Once
)

// initMetrics initializes authentication metrics instruments.
//
// Uses sync.Once to ensure metrics are registered exactly once.
// Safe to call multiple times - subsequent calls are no-ops.
func initMetrics() *authMetrics {
	metricsOnce.Do(func() {
		meter := otel.Meter("gibson.auth")

		// Authentication attempts counter
		attempts, err := meter.Int64Counter(
			MetricAuthAttempts,
			metric.WithDescription("Total authentication attempts by issuer and result"),
			metric.WithUnit("{attempts}"),
		)
		if err != nil {
			slog.Error("failed to create auth attempts metric", "error", err)
		}

		// Authentication latency histogram
		latency, err := meter.Float64Histogram(
			MetricAuthLatency,
			metric.WithDescription("Authentication latency by issuer"),
			metric.WithUnit("ms"),
		)
		if err != nil {
			slog.Error("failed to create auth latency metric", "error", err)
		}

		// JWKS cache hits counter
		jwksCacheHits, err := meter.Int64Counter(
			MetricJWKSCacheHits,
			metric.WithDescription("JWKS cache hits and misses by issuer"),
			metric.WithUnit("{hits}"),
		)
		if err != nil {
			slog.Error("failed to create jwks cache metric", "error", err)
		}

		// Permission denied counter
		permissionDenied, err := meter.Int64Counter(
			MetricAuthPermissionDenied,
			metric.WithDescription("Permission denied events by action and resource"),
			metric.WithUnit("{denials}"),
		)
		if err != nil {
			slog.Error("failed to create permission denied metric", "error", err)
		}

		metricsInstance = &authMetrics{
			attempts:         attempts,
			latency:          latency,
			jwksCacheHits:    jwksCacheHits,
			permissionDenied: permissionDenied,
		}
	})

	return metricsInstance
}

// recordAuthAttempt records an authentication attempt.
//
// Parameters:
//   - ctx: Context for recording (can be background)
//   - issuer: Issuer name (OIDC URL, "kubernetes", "local", "composite")
//   - result: Result of attempt ("success", "failure", "error")
func recordAuthAttempt(ctx context.Context, issuer, result string) {
	m := initMetrics()
	if m.attempts == nil {
		return
	}

	m.attempts.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("issuer", issuer),
			attribute.String("result", result),
		),
	)
}

// recordAuthLatency records authentication latency in milliseconds.
//
// Parameters:
//   - ctx: Context for recording (can be background)
//   - issuer: Issuer name (OIDC URL, "kubernetes", "local", "composite")
//   - latencyMs: Latency in milliseconds
func recordAuthLatency(ctx context.Context, issuer string, latencyMs float64) {
	m := initMetrics()
	if m.latency == nil {
		return
	}

	m.latency.Record(ctx, latencyMs,
		metric.WithAttributes(
			attribute.String("issuer", issuer),
		),
	)
}

// recordJWKSCacheHit records a JWKS cache hit or miss.
//
// Parameters:
//   - ctx: Context for recording (can be background)
//   - issuer: OIDC issuer URL
//   - hit: true for cache hit, false for cache miss
func recordJWKSCacheHit(ctx context.Context, issuer string, hit bool) {
	m := initMetrics()
	if m.jwksCacheHits == nil {
		return
	}

	m.jwksCacheHits.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("issuer", issuer),
			attribute.Bool("hit", hit),
		),
	)
}

// recordPermissionDenied records a permission denied event.
//
// Parameters:
//   - ctx: Context for recording (can be background)
//   - action: The action that was denied
//   - resource: The resource type that was protected
func recordPermissionDenied(ctx context.Context, action, resource string) {
	m := initMetrics()
	if m.permissionDenied == nil {
		return
	}

	m.permissionDenied.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String("action", action),
			attribute.String("resource", resource),
		),
	)
}
