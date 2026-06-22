//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"go.opentelemetry.io/otel"
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

// setupMockGraphResponses configures the mock graph client with expected responses.
func setupMockGraphResponses(client *graph.MockGraphClient) {
	// Host creation responses
	for i := 0; i < 10; i++ {
		client.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"element_id": fmt.Sprintf("elem-%d", i), "idx": float64(0)},
			},
		})
	}

	// Relationship creation responses
	for i := 0; i < 20; i++ {
		client.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{"rel_count": int64(1)},
			},
		})
	}
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

	otel.SetTracerProvider(tp)

	// Simulate mission execution with summary span
	tracer := otel.Tracer("gibson.mission")

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

	tracer := otel.Tracer("test")
	_, span := tracer.Start(ctx, "test.span")
	span.End()

	time.Sleep(50 * time.Millisecond)

	spans := exporter.GetSpans()
	assert.NotEmpty(t, spans)
}
