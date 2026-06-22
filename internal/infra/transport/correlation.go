package transport

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"log/slog"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
)

// CorrelationIDHeader is the HTTP header / ConnectRPC metadata key used to
// propagate a per-request correlation ID. Matches the dashboard's
// x-correlation-id header so the same ID can be grepped across both sides of
// the wire.
const CorrelationIDHeader = "x-correlation-id"

// correlationContextKey is unexported so it cannot be accidentally constructed
// by another package. Use CorrelationIDFromContext / contextWithCorrelationID.
type correlationContextKey struct{}

// CorrelationIDFromContext returns the correlation ID stored in ctx, or the
// empty string when none has been set.
func CorrelationIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(correlationContextKey{}).(string); ok {
		return v
	}
	return ""
}

// contextWithCorrelationID returns ctx with the supplied correlation ID
// attached.
func contextWithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationContextKey{}, id)
}

// crockfordEnc is Crockford base32: no O/0, I/1, L/1 confusion; 26 chars for
// 128-bit UUID. Matches the format used by the gibson daemon.
var crockfordEnc = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").
	WithPadding(base32.NoPadding)

// generateCorrelationID returns a fresh `req-<base32 of uuid7>` ID with
// monotonic time-ordering (UUID v7) so log grep returns events
// chronologically without timestamp parsing.
func generateCorrelationID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// Extremely unlikely (underlying rand.Reader failure). Fall back to v4
		// so callers still get a unique non-empty ID; format is identical.
		id = uuid.New()
	}
	raw, _ := hex.DecodeString(strings.ReplaceAll(id.String(), "-", ""))
	return "req-" + crockfordEnc.EncodeToString(raw)
}

// correlationServerInterceptor returns a connect.Interceptor that:
//  1. reads x-correlation-id from the incoming request header,
//  2. mints a fresh `req-<base32 of uuid7>` ID when absent,
//  3. attaches the ID to the handler context via CorrelationIDFromContext,
//  4. echoes the ID back in the response header so callers can match request
//     and response log lines.
//
// Position in chain: after panic recovery, before auth / identity interceptors.
func correlationServerInterceptor(logger *slog.Logger) connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			id := req.Header().Get(CorrelationIDHeader)
			if id == "" {
				id = generateCorrelationID()
			}
			ctx = contextWithCorrelationID(ctx, id)

			logger.DebugContext(ctx, "correlation_id assigned",
				slog.String("procedure", req.Spec().Procedure),
				slog.String("correlation_id", id),
			)

			resp, err := next(ctx, req)
			if err != nil {
				return nil, err
			}
			resp.Header().Set(CorrelationIDHeader, id)
			return resp, nil
		}
	})
}

// correlationClientInterceptor returns a connect.Interceptor that propagates
// an existing correlation ID from the context into outgoing request headers.
// If no correlation ID is present in the context a fresh one is generated so
// every outbound call is always traceable.
func correlationClientInterceptor() connect.Interceptor {
	return connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
			id := CorrelationIDFromContext(ctx)
			if id == "" {
				id = generateCorrelationID()
				ctx = contextWithCorrelationID(ctx, id)
			}
			req.Header().Set(CorrelationIDHeader, id)
			return next(ctx, req)
		}
	})
}
