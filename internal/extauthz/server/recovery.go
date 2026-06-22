// Package server: panic-recovery interceptor for the raw gRPC server.
//
// ext-authz hosts a raw envoy.service.auth.v3.Authorization gRPC server
// (not ConnectRPC); platform-clients/transport.NewServer ships a
// ConnectRPC-shaped recovery interceptor and is therefore not a drop-in
// replacement here. This file is the gRPC-shaped counterpart, kept
// behaviour-equivalent: catches every panic in the handler chain,
// converts to codes.Internal with a generic message (never leaks the
// panic value across the trust boundary), and logs the full stack trace
// to the supplied logger.
//
// Without this interceptor a single panic in the Check handler would
// crash the goroutine, which gRPC handles by tearing down the connection
// — but downstream Envoy was observing this as "ext_authz upstream
// reset" and serving 5xx for every concurrent request scheduled on the
// same connection. Audit finding ext-authz#53.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UnaryPanicRecovery returns a grpc.UnaryServerInterceptor that recovers
// from panics in unary handlers and downstream interceptors. It MUST be
// installed as the outermost interceptor (first in chain) so panics
// raised by inner interceptors are also caught.
//
// On recover:
//   - status.Code is codes.Internal.
//   - The message is a fixed generic string; the panic value never crosses
//     the wire.
//   - The full stack trace and the panic value are logged at ERROR.
func UnaryPanicRecovery(logger *slog.Logger) grpc.UnaryServerInterceptor {
	if logger == nil {
		logger = slog.Default()
	}
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp interface{}, err error) {
		defer func() {
			if r := recover(); r != nil {
				stack := debug.Stack()
				var panicStr string
				if e, ok := r.(error); ok {
					panicStr = e.Error()
				} else {
					panicStr = fmt.Sprintf("%+v", r)
				}
				method := ""
				if info != nil {
					method = info.FullMethod
				}
				logger.ErrorContext(ctx, "grpc handler panicked",
					slog.String("panic_value", panicStr),
					slog.String("stack_trace", string(stack)),
					slog.String("method", method),
				)
				err = status.Error(codes.Internal, "internal server error")
			}
		}()
		return handler(ctx, req)
	}
}
