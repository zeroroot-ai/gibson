package idempotency

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// memRedis is an in-memory redisBackend for unit tests. It supports TTL
// by recording the absolute expiry time and evicting on Get. The mu lock
// is exported to allow tests to manipulate internal state (e.g. backdate
// expiry to simulate TTL expiry without real sleeps).
type memRedis struct {
	mu      sync.Mutex
	entries map[string]memEntry
}

type memEntry struct {
	value     []byte
	expiresAt time.Time // zero means no TTL
}

func newMemRedis() *memRedis {
	return &memRedis{entries: make(map[string]memEntry)}
}

func (m *memRedis) GetBytes(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return nil, nil
	}
	if !e.expiresAt.IsZero() && time.Now().After(e.expiresAt) {
		delete(m.entries, key)
		return nil, nil
	}
	cp := make([]byte, len(e.value))
	copy(cp, e.value)
	return cp, nil
}

func (m *memRedis) SetNX(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, exists := m.entries[key]; exists {
		if e.expiresAt.IsZero() || time.Now().Before(e.expiresAt) {
			return false, nil
		}
	}
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	m.entries[key] = memEntry{value: cp, expiresAt: exp}
	return true, nil
}

func (m *memRedis) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	cp := make([]byte, len(value))
	copy(cp, value)
	m.entries[key] = memEntry{value: cp, expiresAt: exp}
	return nil
}

// backdateExpiry moves the expiry of key into the past, simulating TTL expiry
// without real sleeps.
func (m *memRedis) backdateExpiry(key string, ago time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.entries[key]; ok {
		e.expiresAt = time.Now().Add(-ago)
		m.entries[key] = e
	}
}

// ttlOf returns the remaining TTL for key.
func (m *memRedis) ttlOf(key string) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok || e.expiresAt.IsZero() {
		return 0
	}
	return time.Until(e.expiresAt)
}

func newTestStore(t *testing.T) (*RedisStore, *memRedis) {
	t.Helper()
	backend := newMemRedis()
	s := NewRedisStore(backend, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	s.pollInterval = 10 * time.Millisecond
	return s, backend
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
	s, backend := newTestStore(t)
	ctx := context.Background()

	resp := anyOfString(t, "value")
	require.NoError(t, s.Set(ctx, "t1", "/svc/M", "k1", &CachedResponse{Response: resp}, 30*time.Second))

	_, found, err := s.Get(ctx, "t1", "/svc/M", "k1")
	require.NoError(t, err)
	require.True(t, found)

	// Simulate TTL expiry by backdating the stored entry's expiry time.
	backend.backdateExpiry(redisKey("t1", "/svc/M", "k1"), 1*time.Second)

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

	resp := anyOfString(t, "final-result")
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = s.Set(ctx, "t1", "/svc/M", "k1", &CachedResponse{Response: resp}, time.Hour)
	}()

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

	s.pollInterval = 10 * time.Millisecond

	ctxShort, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()

	got, found, err := s.Get(ctxShort, "t1", "/svc/M", "k1")
	if err != nil {
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	}
	assert.False(t, found)
	assert.Nil(t, got)
}

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

func TestCodec_EncodeDecodeRoundTrip(t *testing.T) {
	respIn := &CachedResponse{Response: anyOfString(t, "round-trip")}
	raw, err := encodeEntry(respIn)
	require.NoError(t, err)
	respOut, err := decodeEntry(raw)
	require.NoError(t, err)
	require.NotNil(t, respOut.Response)
	out := &wrapperspb.StringValue{}
	require.NoError(t, respOut.Response.UnmarshalTo(out))
	assert.Equal(t, "round-trip", out.Value)

	errIn := &CachedResponse{TerminalError: &TerminalError{Code: 3, Message: "bad request"}}
	raw, err = encodeEntry(errIn)
	require.NoError(t, err)
	errOut, err := decodeEntry(raw)
	require.NoError(t, err)
	require.NotNil(t, errOut.TerminalError)
	assert.Equal(t, int32(3), errOut.TerminalError.Code)
	assert.Equal(t, "bad request", errOut.TerminalError.Message)
}

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
	s, backend := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.Set(ctx, "t1", "/svc/M", "k1",
		&CachedResponse{Response: anyOfString(t, "x")}, 0))

	rk := redisKey("t1", "/svc/M", "k1")
	ttl := backend.ttlOf(rk)
	assert.True(t, ttl > 23*time.Hour, "expected ~24h default TTL, got %s", ttl)
}
