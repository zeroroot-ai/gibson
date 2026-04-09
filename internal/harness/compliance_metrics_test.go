package harness

import (
	"testing"
)

func TestComplianceMetrics_RegisterWithCustomRegistry(t *testing.T) {
	m := NewComplianceMetrics()
	reg := newTestRegistry(t)
	if err := m.Register(reg); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
}

func TestComplianceMetrics_RecordEmitted(t *testing.T) {
	m := NewComplianceMetrics()
	m.RecordEmitted(ActionToolCall, EffectExecute, true)
	m.RecordEmitted(ActionToolCall, EffectExecute, false)

	got := counterValue(t, m.SignalsEmitted.WithLabelValues(ActionToolCall, EffectExecute, "true"))
	if got != 1 {
		t.Errorf("success counter = %v; want 1", got)
	}
	got = counterValue(t, m.SignalsEmitted.WithLabelValues(ActionToolCall, EffectExecute, "false"))
	if got != 1 {
		t.Errorf("failure counter = %v; want 1", got)
	}
}

func TestComplianceMetrics_RecordPersistFailure(t *testing.T) {
	m := NewComplianceMetrics()
	m.RecordPersistFailure("neo4j_unavailable")
	m.RecordPersistFailure("neo4j_unavailable")
	m.RecordPersistFailure("panic")

	got := counterValue(t, m.PersistFailures.WithLabelValues("neo4j_unavailable"))
	if got != 2 {
		t.Errorf("neo4j_unavailable = %v; want 2", got)
	}
	got = counterValue(t, m.PersistFailures.WithLabelValues("panic"))
	if got != 1 {
		t.Errorf("panic = %v; want 1", got)
	}
}

func TestComplianceMetrics_BufferedAndDropped(t *testing.T) {
	m := NewComplianceMetrics()
	m.SetBuffered(42)
	if got := gaugeValue(t, m.SignalsBuffered); got != 42 {
		t.Errorf("buffered = %v; want 42", got)
	}

	m.SignalsDropped.Inc()
	m.SignalsDropped.Inc()
	if got := counterValue(t, m.SignalsDropped); got != 2 {
		t.Errorf("dropped = %v; want 2", got)
	}
}

func TestComplianceMetrics_SubstrateEmissions(t *testing.T) {
	m := NewComplianceMetrics()
	m.RecordSubstrateEmission("audit_logger")
	m.RecordSubstrateEmission("audit_logger")
	m.RecordSubstrateEmission("auth_audit")

	if got := counterValue(t, m.SubstrateEmissions.WithLabelValues("audit_logger")); got != 2 {
		t.Errorf("audit_logger = %v; want 2", got)
	}
	if got := counterValue(t, m.SubstrateEmissions.WithLabelValues("auth_audit")); got != 1 {
		t.Errorf("auth_audit = %v; want 1", got)
	}
}

func TestComplianceMetrics_ReservedKeyViolations(t *testing.T) {
	m := NewComplianceMetrics()
	m.RecordReservedKeyViolation("env", "mission_yaml")
	if got := counterValue(t, m.ReservedKeyViolations.WithLabelValues("env", "mission_yaml")); got != 1 {
		t.Errorf("env violation = %v; want 1", got)
	}
}

func TestComplianceMetrics_DisabledGauge(t *testing.T) {
	m := NewComplianceMetrics()
	m.SetDisabled(true)
	if got := gaugeValue(t, m.EmitterDisabled); got != 1 {
		t.Errorf("disabled = %v; want 1", got)
	}
	m.SetDisabled(false)
	if got := gaugeValue(t, m.EmitterDisabled); got != 0 {
		t.Errorf("disabled = %v; want 0", got)
	}
}
