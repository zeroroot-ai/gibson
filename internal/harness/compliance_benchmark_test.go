package harness

import (
	"context"
	"testing"
)

// BenchmarkComplianceMiddleware_BeginCompleteEmit measures the overhead of
// the full beginSignal/completeSignal/emit path on a fast sink. This is
// the synthetic version of Requirement 10.6's ≤5% p99 overhead check;
// the real comparison (baseline harness vs wrapped harness) requires an
// inner harness and is left to the integration tests.
//
// Run with:
//
//	go test -bench=BenchmarkComplianceMiddleware -benchmem ./internal/harness/
func BenchmarkComplianceMiddleware_BeginCompleteEmit(b *testing.B) {
	sink := &fakeSink{}
	m, err := NewComplianceMiddleware(ComplianceMiddlewareConfig{
		Inner: &noopInnerHarness{},
		Sink:  sink,
	})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
		m.completeSignal(ctx, sip, nil)
		m.emit(ctx, sip)
	}
}

// BenchmarkComplianceMiddleware_DisabledFastPath measures the overhead of
// a disabled middleware — which should be close to zero, since the emit
// path short-circuits.
func BenchmarkComplianceMiddleware_DisabledFastPath(b *testing.B) {
	sink := &fakeSink{}
	m, err := NewComplianceMiddleware(ComplianceMiddlewareConfig{
		Inner: &noopInnerHarness{},
		Sink:  sink,
	})
	if err != nil {
		b.Fatal(err)
	}
	m.SetDisabled(true)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sip := m.beginSignal(ctx, MethodComplete, LLMTarget{Slot: "primary"})
		m.completeSignal(ctx, sip, nil)
		m.emit(ctx, sip)
	}
}
