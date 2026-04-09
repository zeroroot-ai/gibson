package resolver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prometheusInstantResponse builds a Prometheus instant-query HTTP response
// body for a single vector result with the given value.
func prometheusInstantResponse(value string) string {
	return `{
  "status": "success",
  "data": {
    "resultType": "vector",
    "result": [
      {
        "metric": {"component_id": "test"},
        "value": [1700000000, "` + value + `"]
      }
    ]
  }
}`
}

func TestHTTPPrometheusQuerier_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v1/query", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(prometheusInstantResponse("42.5")))
	}))
	defer srv.Close()

	q := NewHTTPPrometheusQuerier(srv.URL, nil)
	val, err := q.QueryInstant(context.Background(), `gibson_component_queue_depth{component_id="abc"}`)
	require.NoError(t, err)
	assert.InDelta(t, 42.5, val, 0.001)
}

func TestHTTPPrometheusQuerier_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	q := NewHTTPPrometheusQuerier(srv.URL, nil)
	_, err := q.QueryInstant(context.Background(), "somequery")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}

func TestHTTPPrometheusQuerier_EmptyResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()

	q := NewHTTPPrometheusQuerier(srv.URL, nil)
	_, err := q.QueryInstant(context.Background(), "somequery")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no results")
}

// mockPrometheusQuerier counts calls and returns a fixed value.
type mockPrometheusQuerier struct {
	calls int
	value float64
	err   error
}

func (m *mockPrometheusQuerier) QueryInstant(_ context.Context, _ string) (float64, error) {
	m.calls++
	return m.value, m.err
}

func TestCachedPrometheusQuerier_CacheMissCallsInner(t *testing.T) {
	inner := &mockPrometheusQuerier{value: 15.0}
	cached := NewCachedPrometheusQuerier(inner, nil)

	val, err := cached.QueryInstant(context.Background(), "test_query")
	require.NoError(t, err)
	assert.InDelta(t, 15.0, val, 0.001)
	assert.Equal(t, 1, inner.calls)
}

func TestCachedPrometheusQuerier_CacheHitAvoidsDuplicateCall(t *testing.T) {
	inner := &mockPrometheusQuerier{value: 15.0}
	cached := NewCachedPrometheusQuerier(inner, nil)

	// First call primes the cache.
	_, err := cached.QueryInstant(context.Background(), "test_query")
	require.NoError(t, err)
	assert.Equal(t, 1, inner.calls)

	// Second call: should hit cache.
	val, err := cached.QueryInstant(context.Background(), "test_query")
	require.NoError(t, err)
	assert.InDelta(t, 15.0, val, 0.001)
	assert.Equal(t, 1, inner.calls) // still 1
}

func TestCachedPrometheusQuerier_CacheMissAfterTTL(t *testing.T) {
	inner := &mockPrometheusQuerier{value: 15.0}
	cached := NewCachedPrometheusQuerier(inner, nil)
	// Force a very short TTL for the test.
	cached.ttl = 10 * time.Millisecond

	_, err := cached.QueryInstant(context.Background(), "test_query")
	require.NoError(t, err)
	assert.Equal(t, 1, inner.calls)

	// Wait for TTL to expire.
	time.Sleep(20 * time.Millisecond)

	_, err = cached.QueryInstant(context.Background(), "test_query")
	require.NoError(t, err)
	assert.Equal(t, 2, inner.calls)
}
