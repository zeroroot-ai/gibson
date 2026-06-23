// Package lokilogs queries Grafana Loki's LogQL HTTP API for tenant-scoped
// mission and daemon log lines, backing the daemon's gibson.daemon.logs.v1
// LogsService (E9, gibson#811).
//
// # Tenant isolation
//
// The caller passes a TenantID that the daemon has ALREADY derived from the
// authenticated identity (auth.TenantFromContext). This package folds that
// tenant into both the LogQL `tenant_id` label selector AND the multi-tenant
// `X-Scope-OrgID` Loki org header. Callers never accept a client-supplied
// tenant — that is the isolation fix this whole service exists for. (The Loki
// deployment is a single org named "gibson"; per-tenant separation is enforced
// by the `tenant_id` stream label, exactly as the audit Loki client does.)
//
// # Availability contract
//
// Loki is optional infrastructure. If the endpoint is unreachable or returns a
// non-200 status, query methods return ErrLokiUnavailable (a typed sentinel) so
// the handler can surface a clean Unavailable to the dashboard instead of a
// 500.
package lokilogs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ErrLokiUnavailable is returned when Loki is unreachable or returns an
// unexpected status. The handler maps it to codes.Unavailable.
var ErrLokiUnavailable = errors.New("lokilogs: Loki unavailable")

// lokiOrgID is the single multi-tenant Loki org Gibson logs ship to. Per-tenant
// isolation is enforced by the tenant_id stream label, not by the org header —
// matching internal/platform/audit/loki_client.go.
const lokiOrgID = "gibson"

// Entry is a single log line returned from Loki.
type Entry struct {
	// UnixNanos is the entry's emit time as Unix nanoseconds.
	UnixNanos int64
	// Line is the raw log line.
	Line string
	// Labels are the Loki stream labels for this entry.
	Labels map[string]string
}

// MissionQuery describes a single-mission log query. TenantID is daemon-derived.
type MissionQuery struct {
	TenantID  string
	MissionID string
	Start     time.Time // zero -> default window
	End       time.Time // zero -> now
	Limit     int       // <=0 -> default
}

// DaemonQuery describes a daemon-log query. TenantID is daemon-derived.
type DaemonQuery struct {
	TenantID  string
	Level     string // "" -> no level filter; e.g. "ERROR", "WARN", "INFO", "DEBUG"
	MissionID string // "" -> no mission filter
	Start     time.Time
	End       time.Time
	Limit     int
}

// Querier is the narrow interface the LogsService handler depends on. A real
// Loki HTTP client satisfies it; tests provide a fake. This is the same
// dependency-inversion shape the daemon uses for audit.LokiQuerier, keeping the
// handler unit-testable without standing up Loki.
type Querier interface {
	QueryMissionLogs(ctx context.Context, q MissionQuery) ([]Entry, error)
	QueryDaemonLogs(ctx context.Context, q DaemonQuery) ([]Entry, error)
}

// Client implements Querier against a real Loki HTTP endpoint.
type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// Config configures a Client.
type Config struct {
	// BaseURL is the Loki base URL, e.g. "http://gibson-loki:3100".
	BaseURL string
	// Timeout is the HTTP request timeout. Defaults to 30s.
	Timeout time.Duration
}

// NewClient constructs a Client. Returns an error if BaseURL is empty.
func NewClient(cfg Config, logger *slog.Logger) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("lokilogs: BaseURL is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		baseURL:    strings.TrimRight(cfg.BaseURL, "/"),
		httpClient: &http.Client{Timeout: timeout},
		logger:     logger.With("component", "observability.lokilogs"),
	}, nil
}

const (
	defaultLimit  = 200
	maxLimit      = 1000
	defaultWindow = time.Hour
)

// QueryMissionLogs returns the tenant's log lines for one mission. The tenant_id
// label is set from q.TenantID (daemon-derived), and the mission id is matched
// as a line substring — mirroring the dashboard's loki-client.ts queryMissionLogs.
func (c *Client) QueryMissionLogs(ctx context.Context, q MissionQuery) ([]Entry, error) {
	logql := fmt.Sprintf(`{namespace="gibson", tenant_id=%q} |~ %q`, q.TenantID, q.MissionID)
	return c.query(ctx, logql, q.TenantID, q.Start, q.End, q.Limit)
}

// QueryDaemonLogs returns the tenant's daemon log lines, optionally filtered by
// level and/or mission id — mirroring the dashboard's loki-client.ts
// queryDaemonLogs.
func (c *Client) QueryDaemonLogs(ctx context.Context, q DaemonQuery) ([]Entry, error) {
	var sb strings.Builder
	fmt.Fprintf(&sb, `{namespace="gibson", pod=~"gibson-0.*", tenant_id=%q}`, q.TenantID)
	if q.Level != "" {
		lvl := strings.ToUpper(q.Level)
		// Match the structured ("level":"ERROR") and logfmt (level=ERROR) shapes.
		// Built by concatenation rather than a single format string so the
		// JSON-quoted alternative ("level":"X") is not mistaken for a %q target.
		levelRe := `level.*` + lvl + `|level=` + lvl + `|"level":"` + lvl + `"`
		fmt.Fprintf(&sb, ` |~ %q`, levelRe)
	}
	if q.MissionID != "" {
		fmt.Fprintf(&sb, ` |~ %q`, q.MissionID)
	}
	return c.query(ctx, sb.String(), q.TenantID, q.Start, q.End, q.Limit)
}

// query runs a LogQL query_range request. orgID is always the single "gibson"
// org; tenant isolation lives in the tenant_id label baked into logql.
func (c *Client) query(ctx context.Context, logql, tenantID string, start, end time.Time, limit int) ([]Entry, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	endTime := end
	if endTime.IsZero() {
		endTime = time.Now().UTC()
	}
	startTime := start
	if startTime.IsZero() {
		startTime = endTime.Add(-defaultWindow)
	}

	params := url.Values{}
	params.Set("query", logql)
	params.Set("start", strconv.FormatInt(startTime.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(endTime.UnixNano(), 10))
	params.Set("limit", strconv.Itoa(limit))
	params.Set("direction", "backward")

	reqURL := fmt.Sprintf("%s/loki/api/v1/query_range?%s", c.baseURL, params.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrLokiUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")
	// Daemon-owned tenant scoping: the org header is the fixed "gibson" org.
	req.Header.Set("X-Scope-OrgID", lokiOrgID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.WarnContext(ctx, "loki log query failed",
			slog.String("error", err.Error()), slog.String("tenant_id", tenantID))
		return nil, fmt.Errorf("%w: HTTP request failed: %w", ErrLokiUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		c.logger.WarnContext(ctx, "loki returned non-200",
			slog.Int("status", resp.StatusCode), slog.String("body", string(body)))
		return nil, fmt.Errorf("%w: status %d", ErrLokiUnavailable, resp.StatusCode)
	}

	var lr queryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, fmt.Errorf("%w: decode response: %w", ErrLokiUnavailable, err)
	}
	if lr.Status != "success" {
		return nil, fmt.Errorf("%w: Loki status=%q error=%q", ErrLokiUnavailable, lr.Status, lr.Error)
	}

	entries := make([]Entry, 0, limit)
	for _, stream := range lr.Data.Result {
		for _, v := range stream.Values {
			ns, perr := strconv.ParseInt(v[0], 10, 64)
			if perr != nil {
				continue
			}
			entries = append(entries, Entry{UnixNanos: ns, Line: v[1], Labels: stream.Stream})
		}
	}
	// Newest first (direction=backward).
	sort.SliceStable(entries, func(i, j int) bool { return entries[i].UnixNanos > entries[j].UnixNanos })
	return entries, nil
}

// queryRangeResponse is the Loki query_range JSON envelope.
type queryRangeResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Stream map[string]string `json:"stream"`
			Values [][2]string       `json:"values"` // [nanosTimestamp, logLine]
		} `json:"result"`
	} `json:"data"`
}
