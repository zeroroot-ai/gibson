package daemon

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"log/slog"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// CorrelationIDMetadataKey is the gRPC metadata key (lower-case per
// the gRPC convention) used to propagate a per-request correlation ID
// between the dashboard, ext-authz, the daemon, and any downstream
// service. Matches the dashboard's `x-correlation-id` header so the
// same ID can be grepped across both sides of the wire.
const CorrelationIDMetadataKey = "x-correlation-id"

// correlationContextKey is unexported so it cannot be accidentally
// constructed by another package. Use FromContext / ContextWith to
// read / write the per-RPC correlation ID.
type correlationContextKey struct{}

// FromContext returns the correlation ID stored in ctx, or the empty
// string when none is set.
func CorrelationIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(correlationContextKey{}).(string); ok {
		return v
	}
	return ""
}

// ContextWith returns ctx with the supplied correlation ID attached.
// Internal-use; the interceptor below is the only call site.
func contextWithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationContextKey{}, id)
}

// generateCorrelationID returns a fresh `req-<base32 of uuid7>` ID
// matching the dashboard's format. UUIDv7 gives the ID monotonic
// time-ordering so a grep over logs returns events chronologically
// without needing to parse the timestamps.
//
// We use Crockford base32 alphabet to keep IDs unambiguous (no
// `O`/`0`, `I`/`1`, `L`/`1`) and 26 chars (130 bits) wide.
var crockfordEnc = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").
	WithPadding(base32.NoPadding)

func generateCorrelationID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// Extremely unlikely (the underlying rand.Reader would have
		// to fail). Fall back to v4 so callers still get a unique
		// non-empty ID; the format is the same.
		id = uuid.New()
	}
	raw, _ := hex.DecodeString(strings.ReplaceAll(id.String(), "-", ""))
	return "req-" + crockfordEnc.EncodeToString(raw)
}

// correlationIDInterceptors returns unary + stream gRPC server
// interceptors that:
//
//  1. read the `x-correlation-id` metadata key from the incoming
//     request (forwarding the dashboard's ID when present),
//  2. mint a fresh `req-<base32 of uuid7>` ID when the metadata key
//     is absent, so the daemon's structured log line carries a
//     correlation ID for every RPC,
//  3. attach the ID to the handler's `context.Context` via
//     `CorrelationIDFromContext`, so business-logic code can include
//     it in its own structured-log entries,
//  4. echo the ID back to the caller as a response header so the
//     dashboard's `x-correlation-id` response header always matches
//     the daemon log line for the same request.
//
// Position in chain: AFTER panic recovery + error scrub (so panics
// caught upstream still get logged with an ID), BEFORE the auth /
// identity interceptors (so audit + authz failures share the same
// ID as the request that triggered them).
func correlationIDInterceptors(
	logger *slog.Logger,
) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	unary := func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (resp any, err error) {
		id := readOrGenerate(ctx)
		ctx = contextWithCorrelationID(ctx, id)
		// Echo back so the dashboard can match its response header
		// against the daemon's per-RPC log line. We use SetHeader
		// rather than SetTrailer so the dashboard can read the ID
		// even on streaming responses.
		_ = grpc.SetHeader(ctx, metadata.Pairs(CorrelationIDMetadataKey, id))
		logger.Debug("correlation_id assigned",
			slog.String("grpc_method", info.FullMethod),
			slog.String("correlation_id", id),
		)
		return handler(ctx, req)
	}
	stream := func(
		srv any,
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()
		id := readOrGenerate(ctx)
		_ = ss.SetHeader(metadata.Pairs(CorrelationIDMetadataKey, id))
		logger.Debug("correlation_id assigned",
			slog.String("grpc_method", info.FullMethod),
			slog.String("correlation_id", id),
		)
		return handler(srv, &correlationServerStream{
			ServerStream: ss,
			ctx:          contextWithCorrelationID(ctx, id),
		})
	}
	return unary, stream
}

// correlationServerStream wraps a grpc.ServerStream so the handler
// sees a context carrying the correlation ID.
type correlationServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *correlationServerStream) Context() context.Context { return s.ctx }

// readOrGenerate inspects the incoming gRPC metadata for a
// caller-supplied correlation ID; on miss it mints a fresh one.
func readOrGenerate(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return generateCorrelationID()
	}
	if v := md.Get(CorrelationIDMetadataKey); len(v) > 0 && v[0] != "" {
		return v[0]
	}
	return generateCorrelationID()
}
