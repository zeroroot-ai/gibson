// span_enrich_metric.go — Prometheus counter for unknown-user spans.
//
// Split into its own file so the metric definition sits alongside the rest
// of the observability metrics without cluttering span_enrich.go's core
// helper. Registration is lazy via sync.Once so importing this file into
// tests doesn't spam the default registry.

package observability

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/otel/trace"
)

var (
	unknownUserOnce    sync.Once
	unknownUserCounter *prometheus.CounterVec
)

// initUnknownUserCounter lazily registers gibson_span_unknown_user_total.
// Labelled by `path` — the span name — so operators can grep for the RPC
// path that's shedding identity on the way through. Label cardinality is
// bounded because span names are a fixed vocabulary from this package.
func initUnknownUserCounter() {
	unknownUserOnce.Do(func() {
		unknownUserCounter = promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gibson_span_unknown_user_total",
				Help: "Count of spans where user identity was unresolvable from context. Incremented by observability.EnrichSpan's fallback branch.",
			},
			[]string{"path"},
		)
	})
}

// recordUnknownUserSpan increments the unknown-user counter with the span's
// name as the `path` label. Lazily initializes the counter on first call.
func recordUnknownUserSpan(_ context.Context, span trace.Span) {
	initUnknownUserCounter()
	path := "unknown"
	if span != nil {
		if sc, ok := span.(interface{ Name() string }); ok {
			if n := sc.Name(); n != "" {
				path = n
			}
		}
	}
	unknownUserCounter.WithLabelValues(path).Inc()
}
