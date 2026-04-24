package identity

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"

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
	if identityTraceEnabled {
		// DEBUG: dump every incoming gRPC metadata key sorted, plus what we got for
		// each x-gibson-identity-* header. This proves whether ext-authz's signed
		// headers are actually arriving at the daemon over the Envoy → daemon hop.
		// Gated behind GIBSON_IDENTITY_TRACE=1 — the e2e test and `make signup-trace`
		// set this env var on the daemon pod.  The daemon_log_tailer.go helper scrapes
		// these lines to assert B16 (headers NOT stripped by Envoy).
		keys := make([]string, 0, len(md))
		for k := range md {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Printf("[identity-debug] method=%s metadata_keys=[%s]\n", method, strings.Join(keys, ","))
		for _, hk := range []string{hSubject, hIssuer, hCredentialType, hTenant, hIssuedAt, hSignature} {
			val := h.Get(hk)
			// Redact the signature value — presence only.
			if hk == hSignature && val != "" {
				val = "[present, redacted]"
			}
			fmt.Printf("[identity-debug]   %s=%q\n", hk, val)
		}
	}
	id, err := IdentityFromHeaders(secret, h)
	if err != nil {
		fmt.Printf("[identity-debug] IdentityFromHeaders err: %v\n", err)
		addr := ""
		if p, ok := peer.FromContext(ctx); ok {
			addr = p.Addr.String()
		}
		slog.Default().Warn("identity: HMAC failure — possible gateway bypass", "method", method, "remote", addr)
		return Identity{}, status.Errorf(codes.Internal, "identity verification failed")
	}
	return id, nil
}

// enrichCtx stores the verified identity plus the derived ActingUser and
// Tenant context keys so every downstream handler (and every span that
// EnrichSpan touches) has an explicit user_id and tenant_id without
// needing to re-read the Identity struct. Identity.Subject is the end-user
// ID for zitadel/apikey issuers and the workload subject for spire; either
// way it's the correct attribution target.
func enrichCtx(ctx context.Context, id Identity) context.Context {
	ctx = WithIdentity(ctx, id)
	if id.Subject != "" {
		ctx = ContextWithActingUser(ctx, id.Subject)
	}
	if id.Tenant != "" {
		ctx = ContextWithTenant(ctx, id.Tenant)
	}
	return ctx
}

// UnaryInterceptor verifies Envoy-signed identity headers and injects Identity
// into context. HMAC failure returns codes.Internal (gateway bypass attempt).
func UnaryInterceptor(secret []byte) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
		id, err := verify(secret, ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return h(enrichCtx(ctx, id), req)
	}
}

// StreamInterceptor is the streaming-RPC equivalent of UnaryInterceptor.
func StreamInterceptor(secret []byte) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
		id, err := verify(secret, ss.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return h(srv, &wrappedStream{ss, enrichCtx(ss.Context(), id)})
	}
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }
