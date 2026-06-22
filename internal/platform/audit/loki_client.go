// Package audit — loki_client.go
//
// LokiClient queries Grafana Loki's LogQL HTTP API for Gibson audit events.
// The daemon's structured log lines include event_type, tenant_id, actor_id,
// actor_email, and other fields that the query method can filter on server-side.
//
// # Availability contract
//
// Loki is optional infrastructure.  If the Loki endpoint is unreachable or
// returns an unexpected status, QueryAuditEvents returns ErrLokiUnavailable
// (a typed sentinel) so callers can fall back to the Redis audit stream
// without treating the error as fatal.
//
// # Pagination
//
// Loki does not support opaque cursors.  Pagination is implemented using the
// end-time of the last received entry as the new end boundary (direction=backward,
// so "older" means smaller timestamps).  The cursor value stored in
// ListAuditEventsResponse.next_cursor is the nanosecond timestamp string of the
// oldest event on the current page.
//
// # Log line format
//
// The daemon emits audit log entries as structured slog JSON lines.  Key fields:
//
//	{"level":"INFO","msg":"component grant added","event_type":"component_grant_added",
//	 "tenant_id":"acme","actor_id":"uuid","actor_email":"user@acme.com",...}
//
// LogQL pipelines extract these fields via json label extraction.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrLokiUnavailable is returned when the Loki endpoint is unreachable or
// returns an unexpected status code.  Callers should fall back to the
// Redis audit stream when they receive this error.
var ErrLokiUnavailable = errors.New("audit: Loki unavailable")

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

// LokiQuerier is the narrow interface used by the daemon's ListAuditEvents handler.
// Implementations may query real Loki or fall back to another source.
type LokiQuerier interface {
	// QueryAuditEvents returns audit events matching the filter.
	// Returns ErrLokiUnavailable when Loki cannot be reached.
	QueryAuditEvents(ctx context.Context, filter AuditFilter) ([]AuditEntry, string, error)
}

// ---------------------------------------------------------------------------
// Filter type
// ---------------------------------------------------------------------------

// AuditFilter describes the query parameters for an audit event search.
type AuditFilter struct {
	TenantID    string
	EventTypes  []string
	ActorUserID string
	TargetMatch string
	FromTime    time.Time
	ToTime      time.Time
	Limit       int
	Cursor      string // nanosecond timestamp string, used as ToTime for next page
}

// ---------------------------------------------------------------------------
// LokiClient
// ---------------------------------------------------------------------------

// LokiClient implements LokiQuerier against a real Loki HTTP endpoint.
type LokiClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// LokiClientConfig holds the configuration for a LokiClient.
type LokiClientConfig struct {
	// BaseURL is the base URL of the Loki instance, e.g. "http://gibson-loki:3100".
	BaseURL string

	// Timeout is the HTTP request timeout.  Defaults to 15 seconds.
	Timeout time.Duration
}

// NewLokiClient constructs a LokiClient from config.
// Returns an error if BaseURL is empty.
func NewLokiClient(cfg LokiClientConfig, logger *slog.Logger) (*LokiClient, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("loki_client: BaseURL is required")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &LokiClient{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger.With("component", "audit.loki_client"),
	}, nil
}

// QueryAuditEvents queries Loki's query_range endpoint using a LogQL pipeline
// that filters by tenant_id and optional event_type, actor, and target fields.
//
// Returns ErrLokiUnavailable when Loki is unreachable or returns a non-200
// status.  Pagination uses the Cursor field (nanosecond timestamp of the last
// seen event) as the new end time for the next request.
func (c *LokiClient) QueryAuditEvents(ctx context.Context, filter AuditFilter) ([]AuditEntry, string, error) {
	query := c.buildQuery(filter)
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	// Determine time bounds.
	endTime := time.Now().UTC()
	if !filter.ToTime.IsZero() {
		endTime = filter.ToTime
	}
	// If a cursor was provided, use it as the end time for the next page.
	if filter.Cursor != "" {
		if ns, err := strconv.ParseInt(filter.Cursor, 10, 64); err == nil {
			// Subtract 1 ns so we don't re-fetch the boundary entry.
			endTime = time.Unix(0, ns-1).UTC()
		}
	}

	startTime := endTime.Add(-24 * time.Hour) // default: last 24 hours
	if !filter.FromTime.IsZero() {
		startTime = filter.FromTime
	}

	params := url.Values{}
	params.Set("query", query)
	params.Set("start", strconv.FormatInt(startTime.UnixNano(), 10))
	params.Set("end", strconv.FormatInt(endTime.UnixNano(), 10))
	params.Set("limit", strconv.Itoa(limit))
	params.Set("direction", "backward")

	reqURL := fmt.Sprintf("%s/loki/api/v1/query_range?%s", c.baseURL, params.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("%w: build request: %v", ErrLokiUnavailable, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Scope-OrgID", "gibson") // Loki multi-tenant org

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.WarnContext(ctx, "loki query failed",
			slog.String("error", err.Error()),
			slog.String("tenant_id", filter.TenantID),
		)
		return nil, "", fmt.Errorf("%w: HTTP request failed: %v", ErrLokiUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		c.logger.WarnContext(ctx, "loki returned non-200",
			slog.Int("status", resp.StatusCode),
			slog.String("body", string(body)),
		)
		return nil, "", fmt.Errorf("%w: status %d", ErrLokiUnavailable, resp.StatusCode)
	}

	var lokiResp lokiQueryRangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&lokiResp); err != nil {
		return nil, "", fmt.Errorf("%w: decode response: %v", ErrLokiUnavailable, err)
	}
	if lokiResp.Status != "success" {
		return nil, "", fmt.Errorf("%w: Loki status=%q error=%q", ErrLokiUnavailable, lokiResp.Status, lokiResp.Error)
	}

	entries, oldestNs := c.parseEntries(ctx, lokiResp, filter)

	// Build next cursor: the nanosecond timestamp of the oldest event on this page.
	nextCursor := ""
	if len(entries) == limit && oldestNs > 0 {
		nextCursor = strconv.FormatInt(oldestNs, 10)
	}

	return entries, nextCursor, nil
}

// ---------------------------------------------------------------------------
// LogQL query builder
// ---------------------------------------------------------------------------

// buildQuery constructs a LogQL pipeline for audit events.
//
// Base selector: {namespace="gibson", app="gibson"}
// Then a JSON label extraction to pull structured fields, followed by
// label filters for tenant_id, event_type, actor_id, etc.
func (c *LokiClient) buildQuery(filter AuditFilter) string {
	var sb strings.Builder

	// Selector — match the Gibson daemon log stream.
	sb.WriteString(`{namespace="gibson", app="gibson"}`)

	// JSON extraction — parse the structured log line.
	sb.WriteString(` | json`)

	// Label filters.
	if filter.TenantID != "" {
		fmt.Fprintf(&sb, ` | tenant_id="%s"`, filter.TenantID)
	}

	if len(filter.EventTypes) > 0 {
		if len(filter.EventTypes) == 1 {
			fmt.Fprintf(&sb, ` | event_type="%s"`, filter.EventTypes[0])
		} else {
			// OR join: event_type=~"type1|type2"
			joined := strings.Join(filter.EventTypes, "|")
			fmt.Fprintf(&sb, ` | event_type=~"%s"`, joined)
		}
	} else {
		// Restrict to audit events only (must have event_type field).
		sb.WriteString(` | event_type != ""`)
	}

	if filter.ActorUserID != "" {
		fmt.Fprintf(&sb, ` | actor_id="%s"`, filter.ActorUserID)
	}

	if filter.TargetMatch != "" {
		// Treat target_match as a substring search across the raw log line.
		fmt.Fprintf(&sb, ` |~ "%s"`, strings.ReplaceAll(filter.TargetMatch, `"`, `\"`))
	}

	return sb.String()
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

// lokiQueryRangeResponse is the Loki query_range JSON response envelope.
type lokiQueryRangeResponse struct {
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

// lokiLogLine is the structured format of a Gibson audit log line.
type lokiLogLine struct {
	Level      string            `json:"level"`
	Msg        string            `json:"msg"`
	EventType  string            `json:"event_type"`
	TenantID   string            `json:"tenant_id"`
	ActorID    string            `json:"actor_id"`
	ActorEmail string            `json:"actor_email"`
	ResourceID string            `json:"resource_id"`
	Resource   string            `json:"resource"`
	Action     string            `json:"action"`
	TraceID    string            `json:"trace_id"`
	Extra      map[string]string `json:"-"` // captured via custom unmarshal
}

// parseEntries converts a Loki query response to AuditEntries.
// Returns the oldest nanosecond timestamp seen (for cursor construction).
func (c *LokiClient) parseEntries(ctx context.Context, resp lokiQueryRangeResponse, filter AuditFilter) ([]AuditEntry, int64) {
	var entries []AuditEntry
	var oldestNs int64 = -1

	for _, stream := range resp.Data.Result {
		for _, val := range stream.Values {
			nsStr := val[0]
			line := val[1]

			ns, err := strconv.ParseInt(nsStr, 10, 64)
			if err != nil {
				continue
			}
			if oldestNs < 0 || ns < oldestNs {
				oldestNs = ns
			}

			ts := time.Unix(0, ns).UTC()

			// Parse the JSON log line.
			var ll lokiLogLine
			if jsonErr := json.Unmarshal([]byte(line), &ll); jsonErr != nil {
				// If the line isn't JSON, emit a minimal entry.
				entries = append(entries, AuditEntry{
					Timestamp:  ts,
					TenantID:   filter.TenantID,
					Action:     "unknown",
					Resource:   "log",
					ResourceID: "",
					Details:    map[string]any{"raw": line},
					Result:     resultSuccess,
				})
				continue
			}

			// Build the details map from all extra fields we don't have dedicated columns for.
			details := map[string]any{}
			if ll.Resource != "" {
				details["resource"] = ll.Resource
			}
			if ll.ResourceID != "" {
				details["resource_id"] = ll.ResourceID
			}
			if ll.Action != "" {
				details["action"] = ll.Action
			}

			// Map stream labels as additional details.
			for k, v := range stream.Stream {
				if k != "namespace" && k != "app" {
					details[k] = v
				}
			}

			entry := AuditEntry{
				ID:         ll.TraceID, // use trace_id as the entry ID
				Timestamp:  ts,
				TenantID:   ll.TenantID,
				ActorID:    ll.ActorID,
				ActorEmail: ll.ActorEmail,
				Action:     ll.EventType,
				Resource:   ll.Resource,
				ResourceID: ll.ResourceID,
				Details:    details,
				Result:     resultSuccess,
			}
			if entry.TenantID == "" {
				entry.TenantID = filter.TenantID
			}
			entries = append(entries, entry)
		}
	}

	// Return oldest timestamp so caller can build the next cursor.
	if oldestNs < 0 {
		return entries, 0
	}
	return entries, oldestNs
}
