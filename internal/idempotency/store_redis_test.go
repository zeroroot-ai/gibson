package idempotency

import (
	"context"
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
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// newTestRedis constructs an in-process miniredis-backed *redis.Client
// for use in tests. The mock is cleaned up automatically when t ends.
func newTestRedis(t *testing.T) (*goredis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	c := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

func newTestStore(t *testing.T) (*RedisStore, *miniredis.Miniredis) {
	t.Helper()
	c, mr := newTestRedis(t)
	s := NewRedisStore(c, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	// Speed up polling for tests that exercise the pending wait loop.
	s.pollInterval = 10 * time.Millisecond
	return s, mr
}

func anyOfString(t *testing.T, v string) *anypb.Any {
	t.Helper()
	any, err := anypb.New(wrapperspb.String(v))
	require.NoError(t, err)
	return any
}

func TestRedisStore_GetReturnsMissOnEmptyKey(t *testing.T) {
	s, _ := newTestStore(t)
	cached, found, err := s.Get(context.Background(), "t1", "/svc/M", "k1")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Nil(t, cached)
}

func TestRedisStore_SetThenGetRoundTripsResponse(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	resp := anyOfString(t, "hello")
	err := s.Set(ctx, "t1", "/svc/M", "k1", &CachedResponse{Response: resp}, time.Hour)
	require.NoError(t, err)

	got, found, err := s.Get(ctx, "t1", "/svc/M", "k1")
	require.NoError(t, err)
	require.True(t, found)
	require.NotNil(t, got.Response)
	assert.Nil(t, got.TerminalError)

	out := &wrapperspb.StringValue{}
	require.NoError(t, got.Response.UnmarshalTo(out))
	assert.Equal(t, "hello", out.Value)
}

func TestRedisStore_SetThenGetRoundTripsTerminalError(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	err := s.Set(ctx, "t1", "/svc/M", "k1", &CachedResponse{
		TerminalError: &TerminalError{Code: 7, Message: "permission denied"},
	}, time.Hour)
	require.NoError(t, err)

	got, found, err := s.Get(ctx, "t1", "/svc/M", "k1")
	require.NoError(t, err)
	require.True(t, found)
	require.Nil(t, got.Response)
	require.NotNil(t, got.TerminalError)
	assert.Equal(t, int32(7), got.TerminalError.Code)
	assert.Equal(t, "permission denied", got.TerminalError.Message)
}

func TestRedisStore_TTLExpiryEvictsEntry(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	resp := anyOfString(t, "value")
	require.NoError(t, s.Set(ctx, "t1", "/svc/M", "k1", &CachedResponse{Response: resp}, 30*time.Second))

	// Confirm presence.
	_, found, err := s.Get(ctx, "t1", "/svc/M", "k1")
	require.NoError(t, err)
	require.True(t, found)

	// Fast-forward the miniredis clock past the TTL.
	mr.FastForward(31 * time.Second)

	_, found, err = s.Get(ctx, "t1", "/svc/M", "k1")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestRedisStore_MarkPendingOnce(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	planted, err := s.MarkPending(ctx, "t1", "/svc/M", "k1", 5*time.Second)
	require.NoError(t, err)
	assert.True(t, planted)

	// Second caller observes the sentinel and does not plant.
	planted, err = s.MarkPending(ctx, "t1", "/svc/M", "k1", 5*time.Second)
	require.NoError(t, err)
	assert.False(t, planted)
}

func TestRedisStore_GetReturnsCachedOnceSentinelOverwritten(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	planted, err := s.MarkPending(ctx, "t1", "/svc/M", "k1", 5*time.Second)
	require.NoError(t, err)
	require.True(t, planted)

	// Background: another goroutine overwrites the sentinel with a
	// real cached response after a brief delay.
	resp := anyOfString(t, "final-result")
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = s.Set(ctx, "t1", "/svc/M", "k1", &CachedResponse{Response: resp}, time.Hour)
	}()

	// Concurrent Get sees the pending sentinel, polls, then finds
	// the real response within MaxWaitForPending.
	got, found, err := s.Get(ctx, "t1", "/svc/M", "k1")
	require.NoError(t, err)
	require.True(t, found)
	require.NotNil(t, got.Response)

	out := &wrapperspb.StringValue{}
	require.NoError(t, got.Response.UnmarshalTo(out))
	assert.Equal(t, "final-result", out.Value)
}

func TestRedisStore_GetGivesUpAfterMaxWaitForPending(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	planted, err := s.MarkPending(ctx, "t1", "/svc/M", "k1", 60*time.Second)
	require.NoError(t, err)
	require.True(t, planted)

	// Shrink the wait window so the test does not block for 5s.
	s.pollInterval = 10 * time.Millisecond

	// The Get below would wait MaxWaitForPending (5s) before giving
	// up. We confirm correctness by giving it a context with a
	// shorter deadline AND verifying the response is "miss". When
	// the context expires Get returns ctx.Err(); when MaxWait
	// elapses first it returns (nil, false, nil). Either is
	// acceptable behaviour for "gave up" — what we test is "did
	// not block forever".
	ctxShort, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	got, found, err := s.Get(ctxShort, "t1", "/svc/M", "k1")
	if err != nil {
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	}
	assert.False(t, found)
	assert.Nil(t, got)
}

// TestRedisStore_ConcurrentSetGet exercises the case where many
// goroutines race on the same key. Exactly one MarkPending should
// return true; the others should observe the sentinel. Once the
// "winner" calls Set, all readers should see the same cached value.
func TestRedisStore_ConcurrentSetGet(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	const goroutines = 16
	var planted atomic.Int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ok, err := s.MarkPending(ctx, "t1", "/svc/M", "k1", 30*time.Second)
			require.NoError(t, err)
			if ok {
				planted.Add(1)
				// Simulate handler work, then publish the result.
				time.Sleep(20 * time.Millisecond)
				require.NoError(t, s.Set(ctx, "t1", "/svc/M", "k1",
					&CachedResponse{Response: anyOfString(t, "winner")}, time.Hour))
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), planted.Load(), "exactly one goroutine should win MarkPending")

	got, found, err := s.Get(ctx, "t1", "/svc/M", "k1")
	require.NoError(t, err)
	require.True(t, found)
	out := &wrapperspb.StringValue{}
	require.NoError(t, got.Response.UnmarshalTo(out))
	assert.Equal(t, "winner", out.Value)
}

func TestRedisStore_DistinctTenantsDoNotCollide(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "tA", "/svc/M", "k1",
		&CachedResponse{Response: anyOfString(t, "A")}, time.Hour))
	require.NoError(t, s.Set(ctx, "tB", "/svc/M", "k1",
		&CachedResponse{Response: anyOfString(t, "B")}, time.Hour))

	a, _, err := s.Get(ctx, "tA", "/svc/M", "k1")
	require.NoError(t, err)
	outA := &wrapperspb.StringValue{}
	require.NoError(t, a.Response.UnmarshalTo(outA))
	assert.Equal(t, "A", outA.Value)

	b, _, err := s.Get(ctx, "tB", "/svc/M", "k1")
	require.NoError(t, err)
	outB := &wrapperspb.StringValue{}
	require.NoError(t, b.Response.UnmarshalTo(outB))
	assert.Equal(t, "B", outB.Value)
}

// TestCodec_EncodeDecodeRoundTrip ensures both response and terminal
// error envelopes survive a wire encode/decode round-trip.
func TestCodec_EncodeDecodeRoundTrip(t *testing.T) {
	// Response variant.
	respIn := &CachedResponse{Response: anyOfString(t, "round-trip")}
	raw, err := encodeEntry(respIn)
	require.NoError(t, err)
	respOut, err := decodeEntry(raw)
	require.NoError(t, err)
	require.NotNil(t, respOut.Response)
	out := &wrapperspb.StringValue{}
	require.NoError(t, respOut.Response.UnmarshalTo(out))
	assert.Equal(t, "round-trip", out.Value)

	// Terminal-error variant.
	errIn := &CachedResponse{TerminalError: &TerminalError{Code: 3, Message: "bad request"}}
	raw, err = encodeEntry(errIn)
	require.NoError(t, err)
	errOut, err := decodeEntry(raw)
	require.NoError(t, err)
	require.NotNil(t, errOut.TerminalError)
	assert.Equal(t, int32(3), errOut.TerminalError.Code)
	assert.Equal(t, "bad request", errOut.TerminalError.Message)
}

// TestCodec_TypedResponseSurvivesRoundTrip checks a non-trivial proto
// payload (Timestamp) survives the Any → JSON → Any path.
func TestCodec_TypedResponseSurvivesRoundTrip(t *testing.T) {
	ts := timestamppb.New(time.Unix(1700000000, 12345))
	any, err := anypb.New(ts)
	require.NoError(t, err)

	raw, err := encodeEntry(&CachedResponse{Response: any})
	require.NoError(t, err)
	dec, err := decodeEntry(raw)
	require.NoError(t, err)

	out := &timestamppb.Timestamp{}
	require.NoError(t, dec.Response.UnmarshalTo(out))
	assert.Equal(t, ts.Seconds, out.Seconds)
	assert.Equal(t, ts.Nanos, out.Nanos)
}

func TestCodec_RejectsBadEnvelope(t *testing.T) {
	_, err := decodeEntry([]byte(`{"kind":"unknown"}`))
	assert.Error(t, err)

	_, err = decodeEntry([]byte("not-json"))
	assert.Error(t, err)
}

func TestRedisStore_SetWithZeroTTLUsesDefault(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "t1", "/svc/M", "k1",
		&CachedResponse{Response: anyOfString(t, "x")}, 0))

	// Default TTL is 24h; just verify entry exists and has a TTL.
	rk := redisKey("t1", "/svc/M", "k1")
	ttl := mr.TTL(rk)
	assert.True(t, ttl > 23*time.Hour, "expected ~24h default TTL, got %s", ttl)
}
