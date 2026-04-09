package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// PrometheusQuerier abstracts the Prometheus instant-query API.
// Implementations are expected to be safe for concurrent use.
type PrometheusQuerier interface {
	// QueryInstant issues a PromQL instant query and returns the first result
	// as a float64. Returns (0, err) when the query fails or returns no data.
	QueryInstant(ctx context.Context, query string) (float64, error)
}

// prometheusResponse mirrors the Prometheus HTTP API JSON response for
// instant-vector queries (resultType: "vector").
type prometheusResponse struct {
	Status string `json:"status"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Value  [2]any            `json:"value"` // [unix_timestamp, value_string]
		} `json:"result"`
	} `json:"data"`
}

// HTTPPrometheusQuerier queries the Prometheus HTTP API.
type HTTPPrometheusQuerier struct {
	baseURL string
	client  *http.Client
	logger  *slog.Logger
}

// NewHTTPPrometheusQuerier creates an HTTPPrometheusQuerier targeting the
// given Prometheus base URL (e.g. "http://prometheus:9090").
func NewHTTPPrometheusQuerier(baseURL string, logger *slog.Logger) *HTTPPrometheusQuerier {
	if logger == nil {
		logger = slog.Default()
	}
	return &HTTPPrometheusQuerier{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 10 * time.Second},
		logger:  logger,
	}
}

// QueryInstant issues GET {baseURL}/api/v1/query?query=<q> and parses the
// Prometheus instant-vector JSON response.
func (h *HTTPPrometheusQuerier) QueryInstant(ctx context.Context, query string) (float64, error) {
	endpoint := fmt.Sprintf("%s/api/v1/query?query=%s", h.baseURL, url.QueryEscape(query))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("prometheus build request: %w", err)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("prometheus HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("prometheus returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("prometheus read body: %w", err)
	}

	var pr prometheusResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		return 0, fmt.Errorf("prometheus parse response: %w", err)
	}

	if pr.Status != "success" {
		return 0, fmt.Errorf("prometheus query failed with status %q", pr.Status)
	}

	if len(pr.Data.Result) == 0 {
		return 0, fmt.Errorf("prometheus query returned no results")
	}

	// value[1] is the string-encoded float64 metric value.
	rawVal, ok := pr.Data.Result[0].Value[1].(string)
	if !ok {
		return 0, fmt.Errorf("prometheus value[1] is not a string")
	}

	val, err := strconv.ParseFloat(rawVal, 64)
	if err != nil {
		return 0, fmt.Errorf("prometheus parse float value %q: %w", rawVal, err)
	}

	return val, nil
}

// promCacheEntry is one record in the in-process query cache.
type promCacheEntry struct {
	score     float64
	expiresAt time.Time
}

// CachedPrometheusQuerier wraps a PrometheusQuerier with a 30-second in-process
// cache keyed on the query string. Expired entries are evicted lazily on read.
// All methods are safe for concurrent use.
type CachedPrometheusQuerier struct {
	inner  PrometheusQuerier
	cache  sync.Map
	ttl    time.Duration
	logger *slog.Logger
}

// NewCachedPrometheusQuerier wraps inner with a 30-second TTL cache.
func NewCachedPrometheusQuerier(inner PrometheusQuerier, logger *slog.Logger) *CachedPrometheusQuerier {
	if logger == nil {
		logger = slog.Default()
	}
	return &CachedPrometheusQuerier{
		inner:  inner,
		ttl:    30 * time.Second,
		logger: logger,
	}
}

// QueryInstant returns a cached value when available and unexpired.
// On cache miss it calls the inner querier, caches the result, and returns it.
func (c *CachedPrometheusQuerier) QueryInstant(ctx context.Context, query string) (float64, error) {
	if v, ok := c.cache.Load(query); ok {
		entry := v.(promCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.score, nil
		}
		// Expired: evict.
		c.cache.Delete(query)
	}

	score, err := c.inner.QueryInstant(ctx, query)
	if err != nil {
		return 0, err
	}

	c.cache.Store(query, promCacheEntry{
		score:     score,
		expiresAt: time.Now().Add(c.ttl),
	})

	return score, nil
}
