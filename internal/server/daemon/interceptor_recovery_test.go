package daemon

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockServerStream implements grpc.ServerStream for testing.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}

func TestUnaryPanicRecovery(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	interceptor := unaryPanicRecovery(logger, nil)

	handler := func(ctx context.Context, req any) (any, error) {
		panic("test panic value")
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/gibson.daemon.v1.DaemonService/StartMission"}
	resp, err := interceptor(context.Background(), nil, info, handler)

	assert.Nil(t, resp)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "internal server error", st.Message())

	// Panic value must not leak in the gRPC error
	assert.NotContains(t, st.Message(), "test panic value")

	// Log must contain panic details
	logOutput := buf.String()
	assert.Contains(t, logOutput, "test panic value")
	assert.Contains(t, logOutput, "grpc_method")
	assert.Contains(t, logOutput, "stack_trace")
}

func TestStreamPanicRecovery(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	interceptor := streamPanicRecovery(logger, nil)

	handler := func(srv any, ss grpc.ServerStream) error {
		panic(errors.New("stream panic error"))
	}

	info := &grpc.StreamServerInfo{FullMethod: "/gibson.daemon.v1.DaemonService/StreamMissionEvents"}
	err := interceptor(nil, &mockServerStream{}, info, handler)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
	assert.Equal(t, "internal server error", st.Message())

	// Log must contain the error-typed panic value
	assert.Contains(t, buf.String(), "stream panic error")
}

func TestPanicRecoveryCounter(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	meter := mp.Meter("test")

	unary, _, err := panicRecoveryInterceptors(slog.Default(), meter)
	require.NoError(t, err)

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Method"}
	_, _ = unary(context.Background(), nil, info, func(ctx context.Context, req any) (any, error) {
		panic("counter test")
	})

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "gibson.grpc.panics_recovered_total" {
				found = true
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok)
				require.Len(t, sum.DataPoints, 1)
				assert.Equal(t, int64(1), sum.DataPoints[0].Value)
			}
		}
	}
	assert.True(t, found, "counter metric not found")
}

func TestNoPanicPassthrough(t *testing.T) {
	interceptor := unaryPanicRecovery(slog.Default(), nil)

	handler := func(ctx context.Context, req any) (any, error) {
		return "success", nil
	}

	info := &grpc.UnaryServerInfo{FullMethod: "/test/Normal"}
	resp, err := interceptor(context.Background(), "request", info, handler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
}
