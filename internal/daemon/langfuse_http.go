// Package daemon — langfuse_http.go
//
// langfuseHTTPClient is a minimal server-side Langfuse REST API client used by
// tracesServer. It is constructed per-request with tenant-specific credentials
// resolved from the credential broker; the dashboard never sees the host/keys.
//
// Only the endpoints needed by TracesService are implemented:
//   - GET /api/public/traces?... (paginated list)
//   - GET /api/public/traces/:id
//   - GET /api/public/observations/:id
//   - POST /api/public/scores
//
// All I/O uses encoding/json + net/http from the standard library with no
// third-party HTTP-client dep. Connections reuse the package-level httpClient
// (keep-alive enabled, 10-second timeout) so per-request overhead is minimised.
package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// langfuseHTTPTimeout is the per-request timeout for Langfuse REST calls.
const langfuseHTTPTimeout = 10 * time.Second

// langfuseClient wraps tenant-scoped Langfuse credentials and exposes the
// subset of the Langfuse v3 public API that TracesService needs.
type langfuseClient struct {
	baseURL    string
	authHeader string
	// httpClient is the HTTP client to use for requests. When nil, defaults to
	// a shared package-level client with keep-alive and a 10-second timeout.
	// Tests may set this to an *httptest.Server client for isolation.
	httpClient *http.Client
}

// langfuseSharedClient is a shared keep-alive HTTP client used when
// langfuseClient.httpClient is nil. Not mutated after init.
var langfuseSharedClient = &http.Client{Timeout: langfuseHTTPTimeout}

// newLangfuseClient constructs a langfuseClient from the given credentials.
// Returns an error when any required field is blank.
func newLangfuseClient(host, publicKey, secretKey string) (*langfuseClient, error) {
	if host == "" {
		return nil, fmt.Errorf("langfuse client: host is required")
	}
	if publicKey == "" {
		return nil, fmt.Errorf("langfuse client: public_key is required")
	}
	if secretKey == "" {
		return nil, fmt.Errorf("langfuse client: secret_key is required")
	}
	creds := base64.StdEncoding.EncodeToString([]byte(publicKey + ":" + secretKey))
	return &langfuseClient{
		baseURL:    strings.TrimRight(host, "/"),
		authHeader: "Basic " + creds,
	}, nil
}

// newLangfuseClientWithHTTP constructs a langfuseClient with a custom HTTP
// client. Used in tests to inject an *httptest.Server client.
func newLangfuseClientWithHTTP(host, publicKey, secretKey string, hc *http.Client) (*langfuseClient, error) {
	c, err := newLangfuseClient(host, publicKey, secretKey)
	if err != nil {
		return nil, err
	}
	c.httpClient = hc
	return c, nil
}

// client returns the HTTP client to use for requests.
func (c *langfuseClient) client() *http.Client {
	if c.httpClient != nil {
		return c.httpClient
	}
	return langfuseSharedClient
}

// ---------------------------------------------------------------------------
// Wire types — mirrors the Langfuse v3 /api/public REST response shapes.
// ---------------------------------------------------------------------------

// langfuseTrace is the JSON shape returned by GET /api/public/traces/:id and
// the items inside GET /api/public/traces.
type langfuseTrace struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Timestamp        string         `json:"timestamp"`
	Metadata         map[string]any `json:"metadata"`
	Tags             []string       `json:"tags"`
	UserID           string         `json:"userId"`
	SessionID        string         `json:"sessionId"`
	TotalTokens      int64          `json:"totalTokens"`
	PromptTokens     int64          `json:"promptTokens"`
	CompletionTokens int64          `json:"completionTokens"`
	Latency          float64        `json:"latency"`
	Observations     []string       `json:"observations"`
}

// langfuseObservation is the JSON shape returned by GET /api/public/observations/:id.
type langfuseObservation struct {
	ID                  string         `json:"id"`
	TraceID             string         `json:"traceId"`
	Type                string         `json:"type"`
	Name                string         `json:"name"`
	StartTime           string         `json:"startTime"`
	EndTime             string         `json:"endTime"`
	ParentObservationID string         `json:"parentObservationId"`
	Model               string         `json:"model"`
	Input               any            `json:"input"`
	Output              any            `json:"output"`
	Metadata            map[string]any `json:"metadata"`
	PromptTokens        int64          `json:"promptTokens"`
	CompletionTokens    int64          `json:"completionTokens"`
	TotalTokens         int64          `json:"totalTokens"`
	Level               string         `json:"level"`
	StatusMessage       string         `json:"statusMessage"`
}

// langfuseTracePage is the envelope returned by GET /api/public/traces.
type langfuseTracePage struct {
	Data []langfuseTrace `json:"data"`
	Meta struct {
		Page       int32 `json:"page"`
		Limit      int32 `json:"limit"`
		TotalItems int64 `json:"totalItems"`
		TotalPages int32 `json:"totalPages"`
	} `json:"meta"`
}

// langfuseError captures the error body Langfuse returns on 4xx/5xx.
type langfuseErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// ---------------------------------------------------------------------------
// API methods
// ---------------------------------------------------------------------------

// listTraces calls GET /api/public/traces with the given parameters and returns
// the page envelope. opts fields use their zero value to omit the parameter.
func (c *langfuseClient) listTraces(ctx context.Context, opts langfuseListTracesOpts) (*langfuseTracePage, error) {
	params := url.Values{}
	params.Set("orderBy", "timestamp.DESC")
	if opts.Page > 0 {
		params.Set("page", fmt.Sprintf("%d", opts.Page))
	}
	if opts.Limit > 0 {
		params.Set("limit", fmt.Sprintf("%d", opts.Limit))
	}
	if opts.FromTimestamp != "" {
		params.Set("fromTimestamp", opts.FromTimestamp)
	}
	if opts.ToTimestamp != "" {
		params.Set("toTimestamp", opts.ToTimestamp)
	}
	if opts.Name != "" {
		params.Set("name", opts.Name)
	}
	if opts.UserID != "" {
		params.Set("userId", opts.UserID)
	}
	for _, tag := range opts.Tags {
		if tag != "" {
			params.Add("tags", tag)
		}
	}

	var page langfuseTracePage
	if err := c.get(ctx, "/api/public/traces?"+params.Encode(), &page); err != nil {
		return nil, err
	}
	return &page, nil
}

// langfuseListTracesOpts carries optional filter parameters for listTraces.
type langfuseListTracesOpts struct {
	Page          int32
	Limit         int32
	FromTimestamp string
	ToTimestamp   string
	Name          string
	UserID        string
	Tags          []string
}

// getTrace calls GET /api/public/traces/:traceId.
func (c *langfuseClient) getTrace(ctx context.Context, traceID string) (*langfuseTrace, error) {
	var trace langfuseTrace
	if err := c.get(ctx, "/api/public/traces/"+url.PathEscape(traceID), &trace); err != nil {
		return nil, err
	}
	return &trace, nil
}

// getObservation calls GET /api/public/observations/:observationId.
func (c *langfuseClient) getObservation(ctx context.Context, observationID string) (*langfuseObservation, error) {
	var obs langfuseObservation
	if err := c.get(ctx, "/api/public/observations/"+url.PathEscape(observationID), &obs); err != nil {
		return nil, err
	}
	return &obs, nil
}

// langfuseCreateScoreRequest is the POST /api/public/scores body.
type langfuseCreateScoreRequest struct {
	TraceID string  `json:"traceId"`
	Name    string  `json:"name"`
	Value   float64 `json:"value"`
	Comment string  `json:"comment,omitempty"`
}

// createScore calls POST /api/public/scores.
func (c *langfuseClient) createScore(ctx context.Context, req langfuseCreateScoreRequest) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("langfuse createScore: marshal failed: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/public/scores", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("langfuse createScore: build request failed: %w", err)
	}
	httpReq.Header.Set("Authorization", c.authHeader)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client().Do(httpReq)
	if err != nil {
		return fmt.Errorf("langfuse createScore: HTTP error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return langfuseAuthError{}
	}
	if resp.StatusCode == http.StatusNotFound {
		return langfuseNotFoundError{resource: "trace " + req.TraceID}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return langfuseAPIError{status: resp.StatusCode}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// get performs a GET request against the Langfuse API and JSON-decodes the
// response into dst. Returns typed errors for 401/404/5xx.
func (c *langfuseClient) get(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("langfuse GET %s: build request failed: %w", path, err)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("langfuse GET %s: HTTP error: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return langfuseAuthError{}
	}
	if resp.StatusCode == http.StatusNotFound {
		return langfuseNotFoundError{resource: path}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return langfuseAPIError{status: resp.StatusCode, body: string(body)}
	}

	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		return fmt.Errorf("langfuse GET %s: decode failed: %w", path, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

// langfuseAuthError signals a 401 Unauthorized from Langfuse.
type langfuseAuthError struct{}

func (langfuseAuthError) Error() string { return "langfuse: invalid credentials (401)" }

// langfuseNotFoundError signals a 404 Not Found from Langfuse.
type langfuseNotFoundError struct{ resource string }

func (e langfuseNotFoundError) Error() string {
	return fmt.Sprintf("langfuse: not found: %s", e.resource)
}

// langfuseAPIError signals a non-2xx non-401 non-404 response from Langfuse.
type langfuseAPIError struct {
	status int
	body   string
}

func (e langfuseAPIError) Error() string {
	return fmt.Sprintf("langfuse: API error %d: %s", e.status, e.body)
}
