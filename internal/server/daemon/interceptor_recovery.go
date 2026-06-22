package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// panicRecoveryInterceptors creates unary and stream gRPC interceptors that
// recover from panics in RPC handlers. These must be registered as the
// outermost interceptors in the chain so they catch panics from all inner
// interceptors (auth, tracing, etc.).
//
// On recovery:
//   - Logs the panic value and full stack trace at slog.Error level
//   - Increments the gibson.grpc.panics_recovered_total counter
//   - Returns codes.Internal with generic "internal server error" message
func panicRecoveryInterceptors(
	logger *slog.Logger,
	meter metric.Meter,
) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor, error) {
	var panicsTotal metric.Int64Counter
	if meter != nil {
		var err error
		panicsTotal, err = meter.Int64Counter(
			"gibson.grpc.panics_recovered_total",
			metric.WithDescription("Total number of panics recovered in gRPC handlers"),
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create panics_recovered_total counter: %w", err)
		}
	}

	unary := unaryPanicRecovery(logger, panicsTotal)
	stream := streamPanicRecovery(logger, panicsTotal)
	return unary, stream, nil
}

// unaryPanicRecovery returns a unary server interceptor that recovers panics.
func unaryPanicRecovery(logger *slog.Logger, counter metric.Int64Counter) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = handlePanic(ctx, logger, counter, r, info.FullMethod, "unary")
			}
		}()
		return handler(ctx, req)
	}
}

// streamPanicRecovery returns a stream server interceptor that recovers panics.
func streamPanicRecovery(logger *slog.Logger, counter metric.Int64Counter) grpc.StreamServerInterceptor {
	return func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = handlePanic(ss.Context(), logger, counter, r, info.FullMethod, "stream")
			}
		}()
		return handler(srv, ss)
	}
}

// handlePanic logs the panic, increments the counter, and returns a gRPC error.
func handlePanic(
	ctx context.Context,
	logger *slog.Logger,
	counter metric.Int64Counter,
	panicValue any,
	method string,
	rpcType string,
) error {
	stack := debug.Stack()

	var panicStr string
	if err, ok := panicValue.(error); ok {
		panicStr = err.Error()
	} else {
		panicStr = fmt.Sprintf("%+v", panicValue)
	}

	logger.Error("gRPC handler panicked",
		"panic_value", panicStr,
		"stack_trace", string(stack),
		"grpc_method", method,
		"grpc_type", rpcType,
	)

	if counter != nil {
		counter.Add(ctx, 1,
			metric.WithAttributes(
				attribute.String("grpc_method", method),
				attribute.String("grpc_type", rpcType),
			),
		)
	}

	return status.Error(codes.Internal, "internal server error")
}
