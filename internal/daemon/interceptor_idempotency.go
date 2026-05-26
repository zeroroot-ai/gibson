package daemon

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/idempotency"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

// idempotencyFieldName is the canonical proto field name carried on
// every Create/Run/Update/Start/Build request message under the
// platform-sdk proto-hygiene convention (CONVENTIONS.md, added in
// platform-sdk#2; PRD zeroroot-ai/.github#101). The interceptor uses
// protoreflect to discover the field on each request — no SDK pin
// and no method-name allowlist required.
const idempotencyFieldName = "idempotency_key"

// idempotencyUnaryInterceptor returns a UnaryServerInterceptor that
// deduplicates mutating RPCs by inspecting the request for a non-empty
// `idempotency_key` field. On cache hit it returns the previously
// recorded response (or terminal error) without invoking the handler.
// On cache miss it executes the handler, caches the outcome, and
// returns it.
//
// v1 detection strategy (documented choice): protoreflect lookup of a
// string field named `idempotency_key`. If the field is absent, the
// interceptor passes through unchanged. If present but empty, the
// caller has opted out of dedup and we pass through. Neither a
// proto-side annotation (`gibson.idempotency.required = true`) nor a
// method-name allowlist (`^Create|^Run|...`) is used. The proto
// convention is the single source of truth — as proto-hygiene rolls
// the field out to messages, dedup activates per-message without a
// daemon change. This trades the declarative clarity of an
// annotation for a one-package implementation; if we later need
// finer control (e.g. "this Create RPC must NOT be deduplicated")
// we'll add an annotation and gate on it.
//
// Streaming RPCs are NOT covered: the convention only applies to
// unary mutating calls, and re-emitting a multi-frame stream from
// cache is a separate design problem we have not yet needed to
// solve.
//
// Position in the daemon chain: AFTER identity (so we know the
// caller's tenant; the cache key is `(tenant, method, key)`),
// BEFORE protovalidate runtime (validation is cheap; re-validating
// on a cache hit is fine and keeps the cache write at the same
// point as the handler return).
func idempotencyUnaryInterceptor(store idempotency.Store, defaultTTL time.Duration, logger *slog.Logger) grpc.UnaryServerInterceptor {
	if store == nil {
		panic("daemon: idempotencyUnaryInterceptor: store must not be nil")
	}
	if defaultTTL <= 0 {
		defaultTTL = idempotency.DefaultTTL
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		key := extractIdempotencyKey(req)
		if key == "" {
			// No field on this message or caller opted out — pass through.
			return handler(ctx, req)
		}

		tenant := auth.TenantStringFromContext(ctx)
		if tenant == "" {
			// Without a tenant we cannot scope the cache key safely.
			// Falling back to "" would risk cross-tenant cache hits
			// in pathological self-mode or unauthenticated paths
			// that somehow reach this interceptor with a
			// idempotency_key. Pass through and log so the issue is
			// visible.
			logger.WarnContext(ctx, "idempotency: no tenant on identity; bypassing dedup",
				slog.String("grpc_method", info.FullMethod),
			)
			return handler(ctx, req)
		}
		method := info.FullMethod

		// Phase 1: probe the cache.
		cached, found, err := store.Get(ctx, tenant, method, key)
		if err != nil {
			// Backend transient error — degrade open. The handler
			// still runs; we just don't dedup this call. Logged at
			// WARN so operators see the cache outage but the user
			// flow continues.
			logger.WarnContext(ctx, "idempotency: store.Get failed; degrading to non-deduplicated execution",
				slog.String("grpc_method", info.FullMethod),
				slog.String("error", err.Error()),
			)
			return handler(ctx, req)
		}
		if found && cached != nil {
			return replayCached(cached)
		}

		// Phase 2: plant the in-flight sentinel. If another caller
		// won the race, re-Get and replay their outcome.
		planted, perr := store.MarkPending(ctx, tenant, method, key, idempotency.DefaultPendingTTL)
		if perr != nil {
			logger.WarnContext(ctx, "idempotency: store.MarkPending failed; degrading to non-deduplicated execution",
				slog.String("grpc_method", info.FullMethod),
				slog.String("error", perr.Error()),
			)
			return handler(ctx, req)
		}
		if !planted {
			// Someone else got there first — re-Get to fetch their
			// outcome. If still pending after the wait window the
			// store returns (nil, false), and we fall through to a
			// best-effort re-execution.
			cached2, found2, gerr := store.Get(ctx, tenant, method, key)
			if gerr == nil && found2 && cached2 != nil {
				return replayCached(cached2)
			}
		}

		// Phase 3: execute the handler and cache the outcome.
		resp, herr := handler(ctx, req)
		toCache := buildCachedFromOutcome(resp, herr)
		if toCache != nil {
			if serr := store.Set(ctx, tenant, method, key, toCache, defaultTTL); serr != nil {
				logger.WarnContext(ctx, "idempotency: store.Set failed; outcome not cached",
					slog.String("grpc_method", info.FullMethod),
					slog.String("error", serr.Error()),
				)
			}
		}
		return resp, herr
	}
}

// extractIdempotencyKey returns the value of a top-level string field
// named idempotency_key on req when req is a proto message. Returns
// "" when the field is absent, has the wrong type, or req is not a
// proto.Message. Reflection is used so the interceptor stays valid as
// proto-hygiene adds the field to additional messages.
func extractIdempotencyKey(req any) string {
	if req == nil {
		return ""
	}
	msg, ok := req.(proto.Message)
	if !ok {
		return ""
	}
	r := msg.ProtoReflect()
	if r == nil {
		return ""
	}
	field := r.Descriptor().Fields().ByName(idempotencyFieldName)
	if field == nil {
		return ""
	}
	if field.Kind() != protoreflect.StringKind {
		return ""
	}
	if field.Cardinality() == protoreflect.Repeated {
		return ""
	}
	return r.Get(field).String()
}

// buildCachedFromOutcome converts a (response, handler-error) tuple
// into the on-cache form. Returns nil when the outcome MUST NOT be
// cached: transient gRPC errors (Unavailable, DeadlineExceeded,
// ResourceExhausted, Aborted, Canceled) should let the caller retry
// with a fresh execution.
func buildCachedFromOutcome(resp any, herr error) *idempotency.CachedResponse {
	if herr != nil {
		st, ok := grpcstatus.FromError(herr)
		if !ok {
			// Non-gRPC error — treat as terminal (Internal). Even if
			// re-execution could change the answer, caching prevents
			// retry-loop storms for callers using idempotency_key as
			// a safe-retry token.
			return &idempotency.CachedResponse{
				TerminalError: &idempotency.TerminalError{
					Code:    int32(grpccodes.Internal),
					Message: herr.Error(),
				},
			}
		}
		if isTransientCode(st.Code()) {
			return nil
		}
		return &idempotency.CachedResponse{
			TerminalError: &idempotency.TerminalError{
				Code:    int32(st.Code()),
				Message: st.Message(),
			},
		}
	}
	if resp == nil {
		// Successful handler with no response body is unusual but
		// legal (e.g. Empty return type). Cache an empty Any so a
		// duplicate sees the same nil response.
		return &idempotency.CachedResponse{Response: &anypb.Any{}}
	}
	msg, ok := resp.(proto.Message)
	if !ok {
		// Non-proto response cannot be cached; pass through silently.
		// Today every daemon handler returns proto, so this branch
		// is defensive only.
		return nil
	}
	any, err := anypb.New(msg)
	if err != nil {
		return nil
	}
	return &idempotency.CachedResponse{Response: any}
}

// isTransientCode returns true when the gRPC code indicates a
// retryable failure that MUST NOT be cached.
func isTransientCode(c grpccodes.Code) bool {
	switch c {
	case grpccodes.Unavailable,
		grpccodes.DeadlineExceeded,
		grpccodes.ResourceExhausted,
		grpccodes.Aborted,
		grpccodes.Canceled:
		return true
	}
	return false
}

// replayCached converts a cached entry back into a (response, error)
// tuple matching the original handler outcome.
func replayCached(c *idempotency.CachedResponse) (any, error) {
	if c == nil {
		return nil, errors.New("idempotency: replayCached called with nil entry")
	}
	if c.TerminalError != nil {
		return nil, grpcstatus.Error(grpccodes.Code(c.TerminalError.Code), c.TerminalError.Message)
	}
	if c.Response == nil {
		return nil, errors.New("idempotency: cached entry has neither response nor terminal error")
	}
	msg, err := c.Response.UnmarshalNew()
	if err != nil {
		// Cache is corrupt or the response type is no longer
		// registered in this binary. Returning an error is safer
		// than synthesising a fake response.
		return nil, grpcstatus.Errorf(grpccodes.Internal,
			"idempotency: failed to unmarshal cached response: %v", err)
	}
	return msg, nil
}
