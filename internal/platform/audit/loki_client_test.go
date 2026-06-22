package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestLokiClient(t *testing.T, server *httptest.Server) *LokiClient {
	t.Helper()
	c, err := NewLokiClient(LokiClientConfig{
		BaseURL: server.URL,
		Timeout: 5 * time.Second,
	}, slog.Default())
	require.NoError(t, err)
	return c
}

func lokiSuccessResponse(streams []lokiStream) lokiQueryRangeResponse {
	resp := lokiQueryRangeResponse{}
	resp.Status = "success"
	resp.Data.ResultType = "streams"
	resp.Data.Result = make([]struct {
		Stream map[string]string `json:"stream"`
		Values [][2]string       `json:"values"`
	}, len(streams))
	for i, s := range streams {
		resp.Data.Result[i].Stream = s.labels
		resp.Data.Result[i].Values = s.values
	}
	return resp
}

type lokiStream struct {
	labels map[string]string
	values [][2]string
}

func makeLogLine(eventType, tenantID, actorID, actorEmail string) string {
	m := map[string]string{
		"level":       "INFO",
		"msg":         eventType,
		"event_type":  eventType,
		"tenant_id":   tenantID,
		"actor_id":    actorID,
		"actor_email": actorEmail,
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// nanoTimestamp returns a nanosecond string for the given time.
func nanoTimestamp(t time.Time) string {
	return fmt.Sprintf("%d", t.UnixNano())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewLokiClient_RequiresBaseURL(t *testing.T) {
	_, err := NewLokiClient(LokiClientConfig{BaseURL: ""}, slog.Default())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "BaseURL")
}

func TestNewLokiClient_DefaultTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := NewLokiClient(LokiClientConfig{BaseURL: srv.URL}, slog.Default())
	require.NoError(t, err)
	assert.Equal(t, 15*time.Second, c.httpClient.Timeout)
}

func TestQueryAuditEvents_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	line1 := makeLogLine("component_grant_added", "acme", "user-1", "alice@acme.com")
	line2 := makeLogLine("team_created", "acme", "user-1", "alice@acme.com")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/loki/api/v1/query_range", r.URL.Path)
		assert.Equal(t, "gibson", r.Header.Get("X-Scope-OrgID"))
		assert.Contains(t, r.URL.Query().Get("query"), `tenant_id="acme"`)
		assert.Equal(t, "backward", r.URL.Query().Get("direction"))

		resp := lokiSuccessResponse([]lokiStream{
			{
				labels: map[string]string{"namespace": "gibson", "app": "gibson"},
				values: [][2]string{
					{nanoTimestamp(now), line1},
					{nanoTimestamp(now.Add(-time.Second)), line2},
				},
			},
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestLokiClient(t, srv)
	events, cursor, err := c.QueryAuditEvents(context.Background(), AuditFilter{
		TenantID: "acme",
		Limit:    10,
	})

	require.NoError(t, err)
	assert.Len(t, events, 2)
	assert.Equal(t, "component_grant_added", events[0].Action)
	assert.Equal(t, "team_created", events[1].Action)
	assert.Equal(t, "acme", events[0].TenantID)
	assert.Equal(t, "alice@acme.com", events[0].ActorEmail)
	// Cursor is empty because we only got 2 events and limit was 10.
	assert.Equal(t, "", cursor)
}

func TestQueryAuditEvents_PaginationCursor(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	line := makeLogLine("component_grant_added", "acme", "user-1", "alice@acme.com")

	// Build exactly `limit` events to trigger cursor generation.
	limit := 3
	var pairs [][2]string
	for i := 0; i < limit; i++ {
		pairs = append(pairs, [2]string{nanoTimestamp(now.Add(time.Duration(-i) * time.Second)), line})
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := lokiSuccessResponse([]lokiStream{
			{
				labels: map[string]string{"namespace": "gibson"},
				values: pairs,
			},
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestLokiClient(t, srv)
	events, cursor, err := c.QueryAuditEvents(context.Background(), AuditFilter{
		TenantID: "acme",
		Limit:    limit,
	})

	require.NoError(t, err)
	assert.Len(t, events, limit)
	// Cursor should be the oldest nanosecond timestamp.
	assert.NotEmpty(t, cursor)
}

func TestQueryAuditEvents_EventTypeFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		assert.Contains(t, query, `event_type="component_grant_added"`)

		resp := lokiSuccessResponse(nil)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestLokiClient(t, srv)
	_, _, err := c.QueryAuditEvents(context.Background(), AuditFilter{
		TenantID:   "acme",
		EventTypes: []string{"component_grant_added"},
	})
	require.NoError(t, err)
}

func TestQueryAuditEvents_MultipleEventTypes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("query")
		assert.Contains(t, query, `event_type=~"component_grant_added|team_created"`)

		resp := lokiSuccessResponse(nil)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestLokiClient(t, srv)
	_, _, err := c.QueryAuditEvents(context.Background(), AuditFilter{
		TenantID:   "acme",
		EventTypes: []string{"component_grant_added", "team_created"},
	})
	require.NoError(t, err)
}

func TestQueryAuditEvents_LokiUnreachable(t *testing.T) {
	// Point at a port that has nothing listening.
	c, err := NewLokiClient(LokiClientConfig{
		BaseURL: "http://127.0.0.1:19999",
		Timeout: 500 * time.Millisecond,
	}, slog.Default())
	require.NoError(t, err)

	_, _, err = c.QueryAuditEvents(context.Background(), AuditFilter{TenantID: "acme"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrLokiUnavailable)
}

func TestQueryAuditEvents_LokiNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("service unavailable"))
	}))
	defer srv.Close()

	c := newTestLokiClient(t, srv)
	_, _, err := c.QueryAuditEvents(context.Background(), AuditFilter{TenantID: "acme"})
	assert.ErrorIs(t, err, ErrLokiUnavailable)
}

func TestQueryAuditEvents_LokiErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"error":  "bad query",
		})
	}))
	defer srv.Close()

	c := newTestLokiClient(t, srv)
	_, _, err := c.QueryAuditEvents(context.Background(), AuditFilter{TenantID: "acme"})
	assert.ErrorIs(t, err, ErrLokiUnavailable)
}

func TestQueryAuditEvents_ContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never respond — simulate timeout.
		<-r.Context().Done()
	}))
	defer srv.Close()

	c := newTestLokiClient(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, err := c.QueryAuditEvents(ctx, AuditFilter{TenantID: "acme"})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrLokiUnavailable)
}

func TestBuildQuery_NoFilters(t *testing.T) {
	c, _ := NewLokiClient(LokiClientConfig{BaseURL: "http://localhost:3100"}, slog.Default())
	q := c.buildQuery(AuditFilter{TenantID: "acme"})
	assert.Contains(t, q, `{namespace="gibson", app="gibson"}`)
	assert.Contains(t, q, `| json`)
	assert.Contains(t, q, `tenant_id="acme"`)
	assert.Contains(t, q, `event_type != ""`)
}

func TestBuildQuery_ActorFilter(t *testing.T) {
	c, _ := NewLokiClient(LokiClientConfig{BaseURL: "http://localhost:3100"}, slog.Default())
	q := c.buildQuery(AuditFilter{TenantID: "acme", ActorUserID: "user-123"})
	assert.Contains(t, q, `actor_id="user-123"`)
}

func TestBuildQuery_TargetMatch(t *testing.T) {
	c, _ := NewLokiClient(LokiClientConfig{BaseURL: "http://localhost:3100"}, slog.Default())
	q := c.buildQuery(AuditFilter{TenantID: "acme", TargetMatch: "tool:nmap"})
	assert.Contains(t, q, `|~ "tool:nmap"`)
}

func TestQueryAuditEvents_NonJSONLine(t *testing.T) {
	now := time.Now().UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := lokiSuccessResponse([]lokiStream{
			{
				labels: map[string]string{"namespace": "gibson"},
				values: [][2]string{
					{nanoTimestamp(now), "not valid json at all"},
				},
			},
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	c := newTestLokiClient(t, srv)
	events, _, err := c.QueryAuditEvents(context.Background(), AuditFilter{TenantID: "acme"})
	require.NoError(t, err)
	// Should still return an event (degraded).
	assert.Len(t, events, 1)
	assert.Contains(t, events[0].Details, "raw")
	rawVal, ok := events[0].Details["raw"].(string)
	assert.True(t, ok)
	assert.Contains(t, rawVal, "not valid json")
}
