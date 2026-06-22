// Package transport provides ConnectRPC server and client builders with a
// full interceptor chain pre-wired: panic recovery, OTel tracing, correlation
// ID propagation, identity validation hook, SPIFFE TLS credentials (server),
// and retry+backoff (client).
//
// It is NOT customer-facing; do not import it from any package under
// opensource/.
package transport

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"

	"connectrpc.com/connect"
)

// panicRecoveryInterceptor returns a connect.Interceptor that recovers from
// panics in RPC handlers, converts them to connect.CodeInternal, and logs the
// full stack trace via the supplied logger.
//
// Position in chain: always the outermost interceptor so that panics raised
// by inner interceptors (OTel, auth hooks, etc.) are also caught.
func panicRecoveryInterceptor(logger *slog.Logger) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (_ connect.AnyResponse, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = handlePanic(ctx, logger, r, req.Spec().Procedure)
				}
			}()
			return next(ctx, req)
		}
	})
}

// handlePanic logs the panic value and stack trace, then returns a
// connect.CodeInternal error. The caller's returned error variable is set via
// a named return so the deferred recover can assign to it directly.
func handlePanic(
	ctx context.Context,
	logger *slog.Logger,
	panicValue any,
	procedure string,
) error {
	stack := debug.Stack()

	var panicStr string
	if err, ok := panicValue.(error); ok {
		panicStr = err.Error()
	} else {
		panicStr = fmt.Sprintf("%+v", panicValue)
	}

	logger.ErrorContext(ctx, "connect handler panicked",
		slog.String("panic_value", panicStr),
		slog.String("stack_trace", string(stack)),
		slog.String("procedure", procedure),
	)

	return connect.NewError(connect.CodeInternal, fmt.Errorf("internal server error"))
}
