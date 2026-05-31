// Package daemon — traces_service_test.go
//
// Tests for tracesServer, covering:
//   - Construction validation (nil credentialGetter panics).
//   - Missing tenant → PermissionDenied.
//   - Nil credential handler → Unavailable.
//   - Missing required request fields → InvalidArgument.
//   - Cross-tenant isolation (credential name distinctness).
//   - mapLangfuseError coverage.
//   - parseTimestamp edge cases.
//   - traceToProto / observationToProto field mapping.
//   - langfuseClient HTTP round-trips against a fake httptest server.
//   - AuthzRegistry: all four RPCs appear with the member relation.
package daemon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/authz/registry"
	daemonapi "github.com/zeroroot-ai/gibson/internal/daemon/api"
	tracespb "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/traces/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// keep time import used in parseTimestamp tests.
var _ = time.RFC3339

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// tenantCtxTraces returns a context carrying the given tenant string.
func tenantCtxTraces(tenantID string) context.Context {
	return auth.ContextWithTenantString(context.Background(), tenantID)
}

// tracesServerWithHandler creates a tracesServer whose credentialGetter returns
// the given handler (may be nil to simulate not-yet-initialised broker stack).
func tracesServerWithHandler(h *daemonapi.CredentialHandler) *tracesServer {
	return NewTracesServer(func() *daemonapi.CredentialHandler { return h }, nil)
}

// assertCode is a local shorthand matching the style in graph_service_test.go.
func assertCode(t *testing.T, err error, want codes.Code, label string) {
	t.Helper()
	require.Error(t, err, label+": expected an error")
	st, ok := status.FromError(err)
	require.True(t, ok, label+": expected a gRPC status error")
	assert.Equal(t, want, st.Code(), label+": wrong gRPC code")
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

func TestNewTracesServer_NilCredentialGetter_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil credentialGetter, got none")
		}
	}()
	NewTracesServer(nil, nil)
}

func TestNewTracesServer_ValidConfig(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	assert.NotNil(t, srv)
}

// ---------------------------------------------------------------------------
// ListTraces
// ---------------------------------------------------------------------------

func TestListTraces_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.ListTraces(context.Background(), &tracespb.ListTracesRequest{})
	assertCode(t, err, codes.PermissionDenied, "ListTraces no tenant")
}

func TestListTraces_NilCredentialHandler_Unavailable(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.ListTraces(tenantCtxTraces("acme"), &tracespb.ListTracesRequest{})
	assertCode(t, err, codes.Unavailable, "ListTraces nil handler")
}

// ---------------------------------------------------------------------------
// GetTrace
// ---------------------------------------------------------------------------

func TestGetTrace_EmptyTraceID_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.GetTrace(tenantCtxTraces("acme"), &tracespb.GetTraceRequest{TraceId: ""})
	assertCode(t, err, codes.InvalidArgument, "GetTrace empty trace_id")
}

func TestGetTrace_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.GetTrace(context.Background(), &tracespb.GetTraceRequest{TraceId: "t1"})
	assertCode(t, err, codes.PermissionDenied, "GetTrace no tenant")
}

func TestGetTrace_NilCredentialHandler_Unavailable(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.GetTrace(tenantCtxTraces("acme"), &tracespb.GetTraceRequest{TraceId: "t1"})
	assertCode(t, err, codes.Unavailable, "GetTrace nil handler")
}

// ---------------------------------------------------------------------------
// GetObservation
// ---------------------------------------------------------------------------

func TestGetObservation_EmptyObsID_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.GetObservation(tenantCtxTraces("acme"), &tracespb.GetObservationRequest{ObservationId: ""})
	assertCode(t, err, codes.InvalidArgument, "GetObservation empty observation_id")
}

func TestGetObservation_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.GetObservation(context.Background(), &tracespb.GetObservationRequest{ObservationId: "o1"})
	assertCode(t, err, codes.PermissionDenied, "GetObservation no tenant")
}

func TestGetObservation_NilCredentialHandler_Unavailable(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.GetObservation(tenantCtxTraces("acme"), &tracespb.GetObservationRequest{ObservationId: "o1"})
	assertCode(t, err, codes.Unavailable, "GetObservation nil handler")
}

// ---------------------------------------------------------------------------
// AddTraceScore
// ---------------------------------------------------------------------------

func TestAddTraceScore_EmptyTraceID_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.AddTraceScore(tenantCtxTraces("acme"), &tracespb.AddTraceScoreRequest{
		TraceId: "", Name: "feedback", Value: 1.0,
	})
	assertCode(t, err, codes.InvalidArgument, "AddTraceScore empty trace_id")
}

func TestAddTraceScore_EmptyName_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.AddTraceScore(tenantCtxTraces("acme"), &tracespb.AddTraceScoreRequest{
		TraceId: "t1", Name: "", Value: 1.0,
	})
	assertCode(t, err, codes.InvalidArgument, "AddTraceScore empty name")
}

func TestAddTraceScore_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.AddTraceScore(context.Background(), &tracespb.AddTraceScoreRequest{
		TraceId: "t1", Name: "feedback", Value: 1.0,
	})
	assertCode(t, err, codes.PermissionDenied, "AddTraceScore no tenant")
}

func TestAddTraceScore_NilCredentialHandler_Unavailable(t *testing.T) {
	t.Parallel()
	srv := tracesServerWithHandler(nil)
	_, err := srv.AddTraceScore(tenantCtxTraces("acme"), &tracespb.AddTraceScoreRequest{
		TraceId: "t1", Name: "feedback", Value: 1.0,
	})
	assertCode(t, err, codes.Unavailable, "AddTraceScore nil handler")
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation: credential names are distinct per tenant
// ---------------------------------------------------------------------------

func TestTracesLangfuseCredentialName_Isolation(t *testing.T) {
	t.Parallel()
	nameA := tracesLangfuseCredentialName("tenant-A")
	nameB := tracesLangfuseCredentialName("tenant-B")
	assert.NotEqual(t, nameA, nameB,
		"credential names for different tenants must be distinct")
	assert.Contains(t, nameA, "tenant-A")
	assert.Contains(t, nameB, "tenant-B")
}

// ---------------------------------------------------------------------------
// mapLangfuseError
// ---------------------------------------------------------------------------

func TestMapLangfuseError_AuthError(t *testing.T) {
	t.Parallel()
	err := mapLangfuseError(langfuseAuthError{})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

func TestMapLangfuseError_NotFoundError(t *testing.T) {
	t.Parallel()
	err := mapLangfuseError(langfuseNotFoundError{resource: "/api/public/traces/xyz"})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestMapLangfuseError_APIError(t *testing.T) {
	t.Parallel()
	err := mapLangfuseError(langfuseAPIError{status: 500, body: "internal"})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestMapLangfuseError_Generic(t *testing.T) {
	t.Parallel()
	err := mapLangfuseError(fmt.Errorf("connection refused"))
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestMapLangfuseError_Nil(t *testing.T) {
	t.Parallel()
	assert.Nil(t, mapLangfuseError(nil))
}

// ---------------------------------------------------------------------------
// parseTimestamp
// ---------------------------------------------------------------------------

func TestParseTimestamp_RFC3339Nano(t *testing.T) {
	t.Parallel()
	ts := parseTimestamp("2024-01-15T10:30:00.123456789Z")
	require.NotNil(t, ts)
	assert.Equal(t, 2024, ts.AsTime().Year())
}

func TestParseTimestamp_RFC3339(t *testing.T) {
	t.Parallel()
	ts := parseTimestamp("2024-01-15T10:30:00Z")
	require.NotNil(t, ts)
	assert.Equal(t, 2024, ts.AsTime().Year())
}

func TestParseTimestamp_Empty(t *testing.T) {
	t.Parallel()
	assert.Nil(t, parseTimestamp(""))
}

func TestParseTimestamp_Invalid(t *testing.T) {
	t.Parallel()
	assert.Nil(t, parseTimestamp("not-a-timestamp"))
}

// ---------------------------------------------------------------------------
// traceToProto
// ---------------------------------------------------------------------------

func TestTraceToProto_NilInput(t *testing.T) {
	t.Parallel()
	assert.Nil(t, traceToProto(nil))
}

func TestTraceToProto_Fields(t *testing.T) {
	t.Parallel()
	lf := &langfuseTrace{
		ID: "trace-1", Name: "mission-run",
		Timestamp:   "2024-06-01T12:00:00Z",
		Tags:        []string{"agent:recon", "env:prod"},
		UserID:      "user-42",
		SessionID:   "sess-99",
		TotalTokens: 1000, PromptTokens: 400, CompletionTokens: 600,
		Latency:      1500.5,
		Observations: []string{"obs-1", "obs-2"},
	}
	pb := traceToProto(lf)
	require.NotNil(t, pb)
	assert.Equal(t, "trace-1", pb.Id)
	assert.Equal(t, "mission-run", pb.Name)
	assert.NotNil(t, pb.Timestamp)
	assert.Equal(t, []string{"agent:recon", "env:prod"}, pb.Tags)
	assert.Equal(t, "user-42", pb.UserId)
	assert.Equal(t, "sess-99", pb.SessionId)
	assert.Equal(t, int64(1000), pb.TotalTokens)
	assert.Equal(t, int64(400), pb.PromptTokens)
	assert.Equal(t, int64(600), pb.CompletionTokens)
	assert.InDelta(t, 1500.5, pb.LatencyMs, 0.001)
	assert.Equal(t, []string{"obs-1", "obs-2"}, pb.ObservationIds)
}

// ---------------------------------------------------------------------------
// observationToProto
// ---------------------------------------------------------------------------

func TestObservationToProto_NilInput(t *testing.T) {
	t.Parallel()
	assert.Nil(t, observationToProto(nil))
}

func TestObservationToProto_Fields(t *testing.T) {
	t.Parallel()
	lf := &langfuseObservation{
		ID: "obs-1", TraceID: "trace-1", Type: "GENERATION", Name: "llm-call",
		StartTime: "2024-06-01T12:00:00Z", EndTime: "2024-06-01T12:00:05Z",
		ParentObservationID: "obs-0", Model: "claude-3-5-sonnet",
		Input:        map[string]any{"prompt": "hello"},
		Output:       map[string]any{"completion": "world"},
		Metadata:     map[string]any{"langfuse.user.id": "u1"},
		PromptTokens: 200, CompletionTokens: 100, TotalTokens: 300,
		Level: "DEFAULT",
	}
	pb := observationToProto(lf)
	require.NotNil(t, pb)
	assert.Equal(t, "obs-1", pb.Id)
	assert.Equal(t, "trace-1", pb.TraceId)
	assert.Equal(t, "GENERATION", pb.Type)
	assert.Equal(t, "llm-call", pb.Name)
	assert.NotNil(t, pb.StartTime)
	assert.NotNil(t, pb.EndTime)
	assert.Equal(t, "obs-0", pb.ParentObservationId)
	assert.Equal(t, "claude-3-5-sonnet", pb.Model)
	assert.Contains(t, pb.InputJson, "prompt")
	assert.Contains(t, pb.OutputJson, "completion")
	assert.Contains(t, pb.MetadataJson, "langfuse.user.id")
	assert.Equal(t, int64(200), pb.PromptTokens)
	assert.Equal(t, int64(300), pb.TotalTokens)
	assert.Equal(t, "DEFAULT", pb.Level)
}

func TestObservationToProto_NilIO(t *testing.T) {
	t.Parallel()
	lf := &langfuseObservation{ID: "obs-1", TraceID: "trace-1", Type: "EVENT", Name: "ev", Level: "DEFAULT"}
	pb := observationToProto(lf)
	require.NotNil(t, pb)
	assert.Empty(t, pb.InputJson)
	assert.Empty(t, pb.OutputJson)
	assert.Empty(t, pb.MetadataJson)
}

// ---------------------------------------------------------------------------
// langfuseClient HTTP round-trips (fake httptest server)
// ---------------------------------------------------------------------------

type fakeLangfuseHandler func(w http.ResponseWriter, r *http.Request)

func newFakeLangfuseServer(t *testing.T, handlers map[string]fakeLangfuseHandler) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, h := range handlers {
		path, h := path, h
		mux.HandleFunc(path, h)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	require.NoError(t, json.NewEncoder(w).Encode(v))
}

func base64Creds(pk, sk string) string {
	return base64.StdEncoding.EncodeToString([]byte(pk + ":" + sk))
}

func TestLangfuseClientListTraces_Success(t *testing.T) {
	t.Parallel()
	srv := newFakeLangfuseServer(t, map[string]fakeLangfuseHandler{
		"/api/public/traces": func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "Basic "+base64Creds("pk", "sk"), r.Header.Get("Authorization"))
			page := langfuseTracePage{}
			page.Data = []langfuseTrace{{ID: "t1", Name: "run", Tags: []string{"env:prod"}, UserID: "u1"}}
			page.Meta.Page = 1
			page.Meta.Limit = 25
			page.Meta.TotalItems = 1
			page.Meta.TotalPages = 1
			writeJSON(t, w, page)
		},
	})

	// Override the package-level HTTP client to use the fake server's transport.
	client, err := newLangfuseClientWithHTTP(srv.URL, "pk", "sk", srv.Client())
	require.NoError(t, err)

	result, err := client.listTraces(context.Background(), langfuseListTracesOpts{Page: 1, Limit: 25})
	require.NoError(t, err)
	require.Len(t, result.Data, 1)
	assert.Equal(t, "t1", result.Data[0].ID)
}

func TestLangfuseClientGetTrace_Success(t *testing.T) {
	t.Parallel()
	srv := newFakeLangfuseServer(t, map[string]fakeLangfuseHandler{
		"/api/public/traces/t1": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, langfuseTrace{ID: "t1", Name: "run", Tags: []string{"a"}})
		},
	})
	client, err := newLangfuseClientWithHTTP(srv.URL, "pk", "sk", srv.Client())
	require.NoError(t, err)

	trace, err := client.getTrace(context.Background(), "t1")
	require.NoError(t, err)
	assert.Equal(t, "t1", trace.ID)
}

func TestLangfuseClientGetTrace_NotFound(t *testing.T) {
	t.Parallel()
	srv := newFakeLangfuseServer(t, map[string]fakeLangfuseHandler{
		"/api/public/traces/missing": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(404)
		},
	})
	client, err := newLangfuseClientWithHTTP(srv.URL, "pk", "sk", srv.Client())
	require.NoError(t, err)

	_, err = client.getTrace(context.Background(), "missing")
	require.Error(t, err)
	var notFound langfuseNotFoundError
	require.ErrorAs(t, err, &notFound)
}

func TestLangfuseClientGetObservation_Success(t *testing.T) {
	t.Parallel()
	srv := newFakeLangfuseServer(t, map[string]fakeLangfuseHandler{
		"/api/public/observations/o1": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(t, w, langfuseObservation{ID: "o1", TraceID: "t1", Type: "SPAN", Name: "db-call"})
		},
	})
	client, err := newLangfuseClientWithHTTP(srv.URL, "pk", "sk", srv.Client())
	require.NoError(t, err)

	obs, err := client.getObservation(context.Background(), "o1")
	require.NoError(t, err)
	assert.Equal(t, "o1", obs.ID)
	assert.Equal(t, "SPAN", obs.Type)
}

func TestLangfuseClientCreateScore_Success(t *testing.T) {
	t.Parallel()
	var receivedBody []byte
	srv := newFakeLangfuseServer(t, map[string]fakeLangfuseHandler{
		"/api/public/scores": func(w http.ResponseWriter, r *http.Request) {
			require.Equal(t, "POST", r.Method)
			var err error
			receivedBody, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			w.WriteHeader(200)
		},
	})
	client, err := newLangfuseClientWithHTTP(srv.URL, "pk", "sk", srv.Client())
	require.NoError(t, err)

	err = client.createScore(context.Background(), langfuseCreateScoreRequest{
		TraceID: "t1", Name: "user_feedback", Value: 1.0, Comment: "great",
	})
	require.NoError(t, err)

	var body map[string]any
	require.NoError(t, json.Unmarshal(receivedBody, &body))
	assert.Equal(t, "t1", body["traceId"])
	assert.Equal(t, "user_feedback", body["name"])
	assert.Equal(t, 1.0, body["value"])
	assert.Equal(t, "great", body["comment"])
}

func TestLangfuseClientCreateScore_AuthError(t *testing.T) {
	t.Parallel()
	srv := newFakeLangfuseServer(t, map[string]fakeLangfuseHandler{
		"/api/public/scores": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
		},
	})
	client, err := newLangfuseClientWithHTTP(srv.URL, "pk", "sk", srv.Client())
	require.NoError(t, err)

	err = client.createScore(context.Background(), langfuseCreateScoreRequest{TraceID: "t1", Name: "fb", Value: 1})
	require.Error(t, err)
	var authErr langfuseAuthError
	assert.ErrorAs(t, err, &authErr)
}

func TestNewLangfuseClient_MissingFields(t *testing.T) {
	t.Parallel()
	_, err := newLangfuseClient("", "pk", "sk")
	assert.Error(t, err, "empty host should fail")

	_, err = newLangfuseClient("http://example.com", "", "sk")
	assert.Error(t, err, "empty public key should fail")

	_, err = newLangfuseClient("http://example.com", "pk", "")
	assert.Error(t, err, "empty secret key should fail")
}

// ---------------------------------------------------------------------------
// AuthzRegistry: all four TracesService RPCs must have member relation
// ---------------------------------------------------------------------------

func TestTracesServiceAuthzRegistry(t *testing.T) {
	t.Parallel()

	rpcs := []string{
		"/gibson.traces.v1.TracesService/ListTraces",
		"/gibson.traces.v1.TracesService/GetTrace",
		"/gibson.traces.v1.TracesService/GetObservation",
		"/gibson.traces.v1.TracesService/AddTraceScore",
	}

	for _, method := range rpcs {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			entry, ok := registry.Registry[method]
			require.True(t, ok, "method %s must be in the authz registry", method)
			assert.Equal(t, "member", entry.Relation,
				"TracesService RPCs must require tenant member relation (method=%s)", method)
			assert.Equal(t, "tenant", entry.ObjectType, method)
			assert.Equal(t, "tenant_from_identity", entry.ObjectDeriver, method)
			assert.False(t, entry.Unauthenticated, "TracesService RPCs must not be unauthenticated")
		})
	}
}
