package identity

import (
	"context"
	"log/slog"
	"net/http"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// verify converts incoming gRPC metadata to http.Header, calls IdentityFromHeaders,
// and on failure emits a security warning and returns codes.Internal.
func verify(secret []byte, ctx context.Context, method string) (Identity, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	h := make(http.Header, len(md))
	for k, vs := range md {
		if len(vs) > 0 {
			h.Set(k, vs[0])
		}
	}
	id, err := IdentityFromHeaders(secret, h)
	if err != nil {
		addr := ""
		if p, ok := peer.FromContext(ctx); ok {
			addr = p.Addr.String()
		}
		slog.Default().Warn("identity: HMAC failure — possible gateway bypass", "method", method, "remote", addr)
		return Identity{}, status.Errorf(codes.Internal, "identity verification failed")
	}
	return id, nil
}

// UnaryInterceptor verifies Envoy-signed identity headers and injects Identity
// into context. HMAC failure returns codes.Internal (gateway bypass attempt).
func UnaryInterceptor(secret []byte) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		id, err := verify(secret, ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return h(WithIdentity(ctx, id), req)
	}
}

// StreamInterceptor is the streaming-RPC equivalent of UnaryInterceptor.
func StreamInterceptor(secret []byte) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		id, err := verify(secret, ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return h(srv, &wrappedStream{ss, WithIdentity(ss.Context(), id)})
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }
