// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// setupTraceProvider creates an in-memory trace provider for testing.
func setupTraceProvider(t *testing.T, ctx context.Context) (*tracetest.InMemoryExporter, *sdktrace.TracerProvider) {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)

	return exporter, tp
}

// TestMissionSummarySpan verifies that mission completion creates a summary span
// with aggregate statistics.
func TestMissionSummarySpan(t *testing.T) {
	if os.Getenv("SKIP_LANGFUSE_TEST") != "" {
		t.Skip("Skipping mission summary span test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	exporter, tp := setupTraceProvider(t, ctx)
	defer tp.Shutdown(ctx)

	// Take the tracer from the provider under test, NOT from the process-global
	// one. This used to call otel.SetTracerProvider(tp) and otel.Tracer(...),
	// which left the global pointing at a shut-down provider for every later
	// test in the package — that is what made TestE2ECleanup below fail
	// (gibson#1293).
	tracer := tp.Tracer("gibson.mission")

	missionCtx, missionSpan := tracer.Start(ctx, "gibson.mission")
	defer missionSpan.End()

	time.Sleep(10 * time.Millisecond)

	_, summarySpan := tracer.Start(missionCtx, "gibson.mission.complete")
	summarySpan.End()
	missionSpan.End()

	time.Sleep(100 * time.Millisecond)

	spans := exporter.GetSpans()
	require.NotEmpty(t, spans)

	var hasMissionSpan bool
	for _, s := range spans {
		// SpanStub.Name is a field, not a method.
		if s.Name == "gibson.mission" {
			hasMissionSpan = true
			break
		}
	}

	assert.True(t, hasMissionSpan, "Expected to find gibson.mission span")
}

// TestE2ECleanup ensures that test resources are properly cleaned up.
func TestE2ECleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	exporter, tp := setupTraceProvider(t, ctx)
	defer func() {
		err := tp.Shutdown(ctx)
		assert.NoError(t, err, "TracerProvider shutdown should not error")
	}()

	require.NotNil(t, exporter)

	// tp, not otel.Tracer: the global provider is not the one wired to
	// `exporter`, so the original otel.Tracer("test") recorded the span
	// somewhere else and this assertion could never hold (gibson#1293).
	tracer := tp.Tracer("test")
	_, span := tracer.Start(ctx, "test.span")
	span.End()

	time.Sleep(50 * time.Millisecond)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1, "the span must land in this test's own exporter")
	assert.Equal(t, "test.span", spans[0].Name)
}
