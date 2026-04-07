package observability

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestRecordAuthzDecision_Allow verifies the counter is incremented with
// the correct labels on an allow decision.
func TestRecordAuthzDecision_Allow(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	recorder, err := NewOTelMetricsRecorder(mp)
	if err != nil {
		t.Fatalf("NewOTelMetricsRecorder: %v", err)
	}

	ctx := context.Background()
	recorder.RecordAuthzDecision(ctx, "allow", "/gibson.daemon.admin.v1.DaemonAdminService/ProvisionTenant", "tenants:provision")

	rm := &metricdata.ResourceMetrics{}
	if err := reader.Collect(ctx, rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "gibson.authz.decisions.total" {
				continue
			}
			found = true
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("expected Sum[int64], got %T", m.Data)
			}
			if len(sum.DataPoints) != 1 {
				t.Fatalf("expected 1 data point, got %d", len(sum.DataPoints))
			}
			dp := sum.DataPoints[0]
			if dp.Value != 1 {
				t.Errorf("counter value = %d, want 1", dp.Value)
			}

			labels := map[string]string{}
			for _, kv := range dp.Attributes.ToSlice() {
				labels[string(kv.Key)] = kv.Value.AsString()
			}
			if labels["decision"] != "allow" {
				t.Errorf("decision label = %q, want allow", labels["decision"])
			}
			if labels["method"] != "/gibson.daemon.admin.v1.DaemonAdminService/ProvisionTenant" {
				t.Errorf("method label wrong: %q", labels["method"])
			}
			if labels["permission"] != "tenants:provision" {
				t.Errorf("permission label = %q, want tenants:provision", labels["permission"])
			}
		}
	}
	if !found {
		t.Fatal("gibson.authz.decisions.total counter not found in collected metrics")
	}
}

// TestRecordAuthzDecision_Deny verifies denies are counted separately.
func TestRecordAuthzDecision_Deny(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	recorder, err := NewOTelMetricsRecorder(mp)
	if err != nil {
		t.Fatalf("NewOTelMetricsRecorder: %v", err)
	}

	ctx := context.Background()
	recorder.RecordAuthzDecision(ctx, "deny", "/gibson.test.v1/M", "tenants:list-all")
	recorder.RecordAuthzDecision(ctx, "deny", "/gibson.test.v1/M", "tenants:list-all")

	rm := &metricdata.ResourceMetrics{}
	if err := reader.Collect(ctx, rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "gibson.authz.decisions.total" {
				continue
			}
			sum := m.Data.(metricdata.Sum[int64])
			for _, dp := range sum.DataPoints {
				labels := map[string]string{}
				for _, kv := range dp.Attributes.ToSlice() {
					labels[string(kv.Key)] = kv.Value.AsString()
				}
				if labels["decision"] == "deny" && dp.Value != 2 {
					t.Errorf("deny counter value = %d, want 2", dp.Value)
				}
			}
		}
	}
}

// TestRecordAuthzDecision_EmptyPermissionOmitted verifies the permission
// label is omitted when empty (e.g., for GetAuthSchema with no required
// permissions) rather than emitted as "permission=" which would be noisy
// in Grafana.
func TestRecordAuthzDecision_EmptyPermissionOmitted(t *testing.T) {
	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	recorder, err := NewOTelMetricsRecorder(mp)
	if err != nil {
		t.Fatalf("NewOTelMetricsRecorder: %v", err)
	}

	ctx := context.Background()
	recorder.RecordAuthzDecision(ctx, "allow", "/gibson.daemon.admin.v1.DaemonAdminService/GetAuthSchema", "")

	rm := &metricdata.ResourceMetrics{}
	if err := reader.Collect(ctx, rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name != "gibson.authz.decisions.total" {
				continue
			}
			sum := m.Data.(metricdata.Sum[int64])
			for _, dp := range sum.DataPoints {
				for _, kv := range dp.Attributes.ToSlice() {
					if string(kv.Key) == "permission" {
						t.Errorf("permission label should be omitted when empty, got %q", kv.Value.AsString())
					}
				}
			}
		}
	}
}
