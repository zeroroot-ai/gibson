package harness

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// newTestRegistry returns a fresh Prometheus registry for a single test,
// isolating test metrics from the global default registry and from each
// other. Used across compliance_* tests.
func newTestRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()
	return prometheus.NewRegistry()
}

// counterValue reads the current value of a Prometheus counter via the DTO
// interface. Fails the test on error.
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := c.Write(m); err != nil {
		t.Fatalf("counter.Write: %v", err)
	}
	if m.Counter == nil {
		return 0
	}
	return m.Counter.GetValue()
}

// gaugeValue reads the current value of a Prometheus gauge.
func gaugeValue(t *testing.T, g prometheus.Gauge) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := g.Write(m); err != nil {
		t.Fatalf("gauge.Write: %v", err)
	}
	if m.Gauge == nil {
		return 0
	}
	return m.Gauge.GetValue()
}
