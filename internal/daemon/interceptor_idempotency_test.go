package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/idempotency"
	"github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// requestWithIdemKey is a tiny proto-compatible test fixture: it
// reflects field name `idempotency_key` so the interceptor's
// protoreflect extraction sees it. We reuse wrapperspb.StringValue
// as a stand-in for proto.Message — the interceptor's extractor
// will look for a field named `idempotency_key`, find none on this
// type, and return "". To test the cache-hit path we use a
// dynamic message constructed via protodesc.
//
// Simpler approach: build a custom proto message via a fake
// MessageDescriptor on the fly. But that's a lot of boilerplate.
// Instead, we use the daemon's existing proto types that DO carry
// idempotency_key once the proto-hygiene rollout reaches them, and
// fall back to a runtime-built dynamic message here. To avoid the
// dependency-cycle of pulling in a daemon proto, we use the public
// `google.protobuf.StringValue` for "no idempotency_key" tests and
// a wrapper struct for "yes idempotency_key" tests via reflection.
//
// For a clean unit test we build a small dynamic descriptor below.

// dynamicReqWithIdemKey returns a proto.Message whose descriptor
// declares a single `string idempotency_key = 1` field set to v.
//
// We avoid the heavyweight protodesc path by reusing the standard
// wrapperspb.StringValue: its sole field is named `value`, NOT
// `idempotency_key`, so it provides a useful negative case. For the
// positive case we use a separately-defined fixture below.

// reqNoKey is the proto.Message used to test "no idempotency_key"
// pass-through. It's just wrapperspb.StringValue with no rename.
func reqNoKey() proto.Message { return wrapperspb.String("hello") }

// IdempotentRequest is a hand-rolled proto.Message with an
// `idempotency_key` field. We implement the protoreflect.Message
// interface minimally — enough that the interceptor's reflection
// path can locate and read the field. Test-only.
//
// Implementation note: we use the `dynamicpb` package via a
// descriptor we build from a FileDescriptorProto. This keeps the
// fixture in pure Go (no proto codegen) while still producing a
// genuine proto.Message that ProtoReflect / descriptor lookup
// works against.

// (See helpers_idemkey_test.go for the dynamic-message fixture.)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func newTestStoreT(t *testing.T) (*idempotency.RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return idempotency.NewRedisStore(c, logger), mr
}

// ctxWithTenant returns a ctx carrying an Identity such that
// auth.TenantStringFromContext(ctx) returns "tenant-a".
func ctxWithTenant(t *testing.T) context.Context {
	t.Helper()
	id := auth.Identity{
		Subject:        "user-1",
		Issuer:         auth.IssuerOIDC,
		CredentialType: auth.CredentialOIDCUser,
		Tenant:         mustTenant("tenant-a"),
	}
	return auth.WithIdentity(context.Background(), id)
}

// mustTenant returns a valid auth.TenantID; tests panic on bad input
// (only constants in tests, so panic is acceptable).
func mustTenant(s string) auth.TenantID {
	t, err := auth.NewTenantID(s)
	if err != nil {
		panic("mustTenant: " + err.Error())
	}
	return t
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// info builds a minimal *grpc.UnaryServerInfo for the test harness.
func info(method string) *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: method}
}

func TestIdempotency_NoFieldOnRequest_PassesThrough(t *testing.T) {
	store, _ := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, time.Hour, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		calls.Add(1)
		return wrapperspb.String("ok"), nil
	}

	ctx := ctxWithTenant(t)
	// wrapperspb.StringValue has no idempotency_key field; pass through.
	resp, err := intr(ctx, reqNoKey(), info("/svc/M"), handler)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, int32(1), calls.Load())

	// Second call also passes through (no dedup).
	_, _ = intr(ctx, reqNoKey(), info("/svc/M"), handler)
	assert.Equal(t, int32(2), calls.Load())
}

func TestIdempotency_EmptyKey_PassesThrough(t *testing.T) {
	store, _ := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, time.Hour, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		calls.Add(1)
		return wrapperspb.String("ok"), nil
	}

	ctx := ctxWithTenant(t)
	req := newIdemRequest("", "payload-A") // empty idempotency_key

	_, err := intr(ctx, req, info("/svc/M"), handler)
	require.NoError(t, err)
	_, err = intr(ctx, req, info("/svc/M"), handler)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load(), "empty key opts out of dedup")
}

func TestIdempotency_CacheMissThenHit(t *testing.T) {
	store, _ := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, time.Hour, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		calls.Add(1)
		return wrapperspb.String("once"), nil
	}
	ctx := ctxWithTenant(t)
	req := newIdemRequest("key-1", "payload")

	// First call: miss → execute → cache.
	resp1, err := intr(ctx, req, info("/svc/M"), handler)
	require.NoError(t, err)
	require.NotNil(t, resp1)
	assert.Equal(t, int32(1), calls.Load())

	// Second call: hit → handler NOT executed → cached response returned.
	resp2, err := intr(ctx, req, info("/svc/M"), handler)
	require.NoError(t, err)
	require.NotNil(t, resp2)
	assert.Equal(t, int32(1), calls.Load(), "handler must NOT execute on cache hit")

	got, ok := resp2.(*wrapperspb.StringValue)
	require.True(t, ok, "cached response unmarshalled to %T", resp2)
	assert.Equal(t, "once", got.Value)
}

func TestIdempotency_TerminalErrorIsCached(t *testing.T) {
	store, _ := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, time.Hour, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		calls.Add(1)
		return nil, grpcstatus.Error(grpccodes.PermissionDenied, "no can do")
	}
	ctx := ctxWithTenant(t)
	req := newIdemRequest("key-2", "payload")

	_, err := intr(ctx, req, info("/svc/M"), handler)
	require.Error(t, err)
	st1, _ := grpcstatus.FromError(err)
	assert.Equal(t, grpccodes.PermissionDenied, st1.Code())
	assert.Equal(t, int32(1), calls.Load())

	// Second call: same terminal error, handler NOT executed.
	_, err = intr(ctx, req, info("/svc/M"), handler)
	require.Error(t, err)
	st2, _ := grpcstatus.FromError(err)
	assert.Equal(t, grpccodes.PermissionDenied, st2.Code())
	assert.Equal(t, "no can do", st2.Message())
	assert.Equal(t, int32(1), calls.Load(), "handler must NOT execute on cached terminal error")
}

func TestIdempotency_TransientErrorIsNotCached(t *testing.T) {
	store, _ := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, time.Hour, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		calls.Add(1)
		// First call returns Unavailable, second returns success.
		if calls.Load() == 1 {
			return nil, grpcstatus.Error(grpccodes.Unavailable, "backend down")
		}
		return wrapperspb.String("recovered"), nil
	}
	ctx := ctxWithTenant(t)
	req := newIdemRequest("key-3", "payload")

	_, err := intr(ctx, req, info("/svc/M"), handler)
	require.Error(t, err)

	resp, err := intr(ctx, req, info("/svc/M"), handler)
	require.NoError(t, err, "transient error should not have been cached")
	got, ok := resp.(*wrapperspb.StringValue)
	require.True(t, ok)
	assert.Equal(t, "recovered", got.Value)
	assert.Equal(t, int32(2), calls.Load())
}

func TestIdempotency_TTLExpiryReExecutes(t *testing.T) {
	store, mr := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, 10*time.Second, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		n := calls.Add(1)
		return wrapperspb.String("call-" + map[int32]string{1: "1", 2: "2"}[n]), nil
	}
	ctx := ctxWithTenant(t)
	req := newIdemRequest("key-4", "payload")

	_, err := intr(ctx, req, info("/svc/M"), handler)
	require.NoError(t, err)
	assert.Equal(t, int32(1), calls.Load())

	// Within TTL: cached.
	_, _ = intr(ctx, req, info("/svc/M"), handler)
	assert.Equal(t, int32(1), calls.Load())

	// Past TTL: re-executes.
	mr.FastForward(11 * time.Second)
	resp, err := intr(ctx, req, info("/svc/M"), handler)
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load())
	got, ok := resp.(*wrapperspb.StringValue)
	require.True(t, ok)
	assert.Equal(t, "call-2", got.Value)
}

func TestIdempotency_ConcurrentSameKey_OneExecution(t *testing.T) {
	store, _ := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, time.Hour, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		calls.Add(1)
		// Simulate work so the in-flight sentinel is observable by
		// concurrent callers.
		time.Sleep(30 * time.Millisecond)
		return wrapperspb.String("one-shot"), nil
	}
	ctx := ctxWithTenant(t)
	req := newIdemRequest("key-5", "payload")

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines)
	values := make([]string, goroutines)
	for i := 0; i < goroutines; i++ {
		idx := i
		go func() {
			defer wg.Done()
			resp, err := intr(ctx, req, info("/svc/M"), handler)
			require.NoError(t, err)
			require.NotNil(t, resp)
			values[idx] = resp.(*wrapperspb.StringValue).Value
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), calls.Load(), "concurrent same-key must produce exactly one execution")
	for _, v := range values {
		assert.Equal(t, "one-shot", v, "every caller must observe the same cached response")
	}
}

func TestIdempotency_DifferentTenants_DoNotCollide(t *testing.T) {
	store, _ := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, time.Hour, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		calls.Add(1)
		// Echo the tenant back via the response so we can verify
		// the per-tenant cache discrimination.
		return wrapperspb.String(auth.TenantStringFromContext(ctx)), nil
	}

	ctxA := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u", Issuer: auth.IssuerOIDC, CredentialType: auth.CredentialOIDCUser,
		Tenant: mustTenant("tenant-a"),
	})
	ctxB := auth.WithIdentity(context.Background(), auth.Identity{
		Subject: "u", Issuer: auth.IssuerOIDC, CredentialType: auth.CredentialOIDCUser,
		Tenant: mustTenant("tenant-b"),
	})
	req := newIdemRequest("shared-key", "x")

	rA, _ := intr(ctxA, req, info("/svc/M"), handler)
	rB, _ := intr(ctxB, req, info("/svc/M"), handler)

	assert.Equal(t, "tenant-a", rA.(*wrapperspb.StringValue).Value)
	assert.Equal(t, "tenant-b", rB.(*wrapperspb.StringValue).Value)
	assert.Equal(t, int32(2), calls.Load(), "distinct tenants must NOT share a cache entry")
}

func TestIdempotency_NoTenant_PassesThrough(t *testing.T) {
	store, _ := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, time.Hour, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		calls.Add(1)
		return wrapperspb.String("ok"), nil
	}
	// No identity in context -> no tenant -> bypass dedup.
	ctx := context.Background()
	req := newIdemRequest("k", "x")

	_, _ = intr(ctx, req, info("/svc/M"), handler)
	_, _ = intr(ctx, req, info("/svc/M"), handler)
	assert.Equal(t, int32(2), calls.Load())
}

func TestIdempotency_NonGrpcErrorIsCachedAsInternal(t *testing.T) {
	store, _ := newTestStoreT(t)
	intr := idempotencyUnaryInterceptor(store, time.Hour, newTestLogger())

	var calls atomic.Int32
	handler := func(ctx context.Context, req any) (any, error) {
		calls.Add(1)
		return nil, errors.New("plain-error")
	}
	ctx := ctxWithTenant(t)
	req := newIdemRequest("key-non-grpc", "x")

	_, err := intr(ctx, req, info("/svc/M"), handler)
	require.Error(t, err)

	_, err2 := intr(ctx, req, info("/svc/M"), handler)
	require.Error(t, err2)
	st, _ := grpcstatus.FromError(err2)
	assert.Equal(t, grpccodes.Internal, st.Code())
	assert.Equal(t, int32(1), calls.Load(), "non-grpc error must be cached too")
}

// ---------------------------------------------------------------------------
// Direct extractor coverage — proves protoreflect path works for both
// "has field" and "missing field" cases without depending on the
// surrounding interceptor logic.
// ---------------------------------------------------------------------------

func TestExtractIdempotencyKey(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		assert.Equal(t, "", extractIdempotencyKey(nil))
	})
	t.Run("non-proto request", func(t *testing.T) {
		assert.Equal(t, "", extractIdempotencyKey(struct{ X string }{X: "y"}))
	})
	t.Run("proto without idempotency_key", func(t *testing.T) {
		assert.Equal(t, "", extractIdempotencyKey(wrapperspb.String("nope")))
	})
	t.Run("proto with idempotency_key", func(t *testing.T) {
		req := newIdemRequest("the-key", "payload")
		assert.Equal(t, "the-key", extractIdempotencyKey(req))
	})
	t.Run("proto with empty idempotency_key", func(t *testing.T) {
		req := newIdemRequest("", "payload")
		assert.Equal(t, "", extractIdempotencyKey(req))
	})
}

// TestExtractIdempotencyKey_WrongFieldKind verifies the extractor
// rejects a same-named field of the wrong kind (proto3-level
// safeguard against pathological message shapes).
func TestExtractIdempotencyKey_WrongFieldKind(t *testing.T) {
	// Manually build a request whose `idempotency_key` field is
	// declared as int32 via the dynamicpb path. The extractor must
	// return "" — only string-kind, singular fields are accepted.
	req := newWrongKindRequest()
	assert.Equal(t, "", extractIdempotencyKey(req))
}

// Compile-time guard: extractIdempotencyKey returns a string. If the
// signature changes the surrounding test rebinds will not compile,
// which is the cheapest possible regression signal.
var _ = func() string { return extractIdempotencyKey(nil) }

// Compile-time guard: protoreflect import is referenced (a stray
// unused-import would block the build).
var _ protoreflect.Message
