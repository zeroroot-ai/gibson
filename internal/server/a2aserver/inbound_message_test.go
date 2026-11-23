// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/agentcall"
)

func msg(parts ...*a2a.Part) *a2a.Message {
	return &a2a.Message{ID: "m1", Role: a2a.MessageRoleUser, Parts: parts}
}

func TestTargetsOf(t *testing.T) {
	tests := []struct {
		name        string
		msg         *a2a.Message
		want        []string
		wantPresent bool
		wantErr     error
	}{
		{"a nil message", nil, nil, false, nil},
		{"no parts", msg(), nil, false, nil},
		{"a list in a data part from JSON", msg(a2a.NewDataPart(map[string]any{"targets": []any{"t1", "t2"}})),
			[]string{"t1", "t2"}, true, nil},
		{"a list in a data part from Go", msg(a2a.NewDataPart(map[string]any{"targets": []string{"t1"}})),
			[]string{"t1"}, true, nil},
		{"a list and text", msg(a2a.NewTextPart("scan"), a2a.NewDataPart(map[string]any{"targets": []any{"t1"}})),
			[]string{"t1"}, true, nil},
		{"a data part with another key", msg(a2a.NewDataPart(map[string]any{"budget": 5, "scope": "all"})), nil, false, nil},
		{"a data part that is not an object", msg(a2a.NewDataPart([]any{"t1"}), a2a.NewDataPart("t1")), nil, false, nil},
		{"a nil part", msg(nil), nil, false, nil},
		{"two lists", msg(a2a.NewDataPart(map[string]any{"targets": []any{"t1"}}),
			a2a.NewDataPart(map[string]any{"targets": []any{"t2"}})), nil, false, ErrAmbiguousTargets},
		{"an empty list", msg(a2a.NewDataPart(map[string]any{"targets": []any{}})), nil, false, a2a.ErrInvalidParams},
		{"a list that is a string", msg(a2a.NewDataPart(map[string]any{"targets": "t1"})), nil, false, a2a.ErrInvalidParams},
		{"an entry that is a number", msg(a2a.NewDataPart(map[string]any{"targets": []any{1}})), nil, false,
			a2a.ErrInvalidParams},
		{"an empty entry", msg(a2a.NewDataPart(map[string]any{"targets": []any{""}})), nil, false, a2a.ErrInvalidParams},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, present, err := TargetsOf(tt.msg)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantPresent, present)
		})
	}
}

// No text of a message is a target. A target list in the text, in the metadata of
// a part and in a file part changes nothing. Only a data part holds a list.
func TestTargetsOf_NeverReadsATargetFromTextOrMetadata(t *testing.T) {
	textPart := a2a.NewTextPart(`{"targets": ["t-evil"]} scan t-evil and 203.0.113.0/24`)
	metaPart := a2a.NewTextPart("scan")
	metaPart.Metadata = map[string]any{"targets": []any{"t-evil"}}
	filePart := a2a.NewFileURLPart("https://example.com/t-evil", "text/plain")
	rawPart := a2a.NewRawPart([]byte(`{"targets":["t-evil"]}`))

	got, present, err := TargetsOf(msg(textPart, metaPart, filePart, rawPart))

	require.NoError(t, err)
	assert.False(t, present)
	assert.Empty(t, got)
}

// fakeStarts records each inbound call and answers with a fixed Task.
type fakeStarts struct {
	got        []InboundStart
	task       *a2a.Task
	err        error
	asked      []InboundCaller
	askedByID  []a2a.TaskID
	askedAgent []string
	// resultSize, when set, makes Task set the write deadline for a result of this size.
	resultSize int64
}

func (f *fakeStarts) Start(_ context.Context, req InboundStart) (*a2a.Task, error) {
	f.got = append(f.got, req)
	return f.task, f.err
}

func (f *fakeStarts) Task(ctx context.Context, c InboundCaller, agent string, id a2a.TaskID) (*a2a.Task, error) {
	if f.resultSize > 0 {
		ExtendWriteDeadline(ctx, f.resultSize)
	}
	f.asked, f.askedByID, f.askedAgent = append(f.asked, c), append(f.askedByID, id), append(f.askedAgent, agent)
	return f.task, f.err
}

func (f *fakeStarts) Cancel(_ context.Context, c InboundCaller, agent string, id a2a.TaskID) (*a2a.Task, error) {
	f.asked, f.askedByID, f.askedAgent = append(f.asked, c), append(f.askedByID, id), append(f.askedAgent, agent)
	return f.task, f.err
}

func rpcCall(h http.Handler, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// rpcErrorCode returns the JSON-RPC error code of an answer, and 0 when the answer
// has no error.
func rpcErrorCode(t *testing.T, body string) int {
	t.Helper()
	var r struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &r), body)
	if r.Error == nil {
		return 0
	}
	return r.Error.Code
}

// The JSON-RPC error codes that the inbound endpoint answers.
const (
	codeParse            = -32700
	codeInvalidParams    = -32602
	codeInternal         = -32603
	codeServerBusy       = -32000
	codeTaskNotFound     = -32001
	codeNotCancelable    = -32002
	codeUnsupported      = -32004
	codePermissionDenied = -31403
)

const sendBody = `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":` +
	`{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"scan"},{"data":{"targets":["t1"]}}]}}}`

func TestInboundRPC_SendMessageStartsARunForTheAgentInThePath(t *testing.T) {
	starts := &fakeStarts{task: &a2a.Task{ID: "m-1", ContextID: "m-1", Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted}}}
	h := NewInboundHandler(starts, &recordingCards{}, allowGrants)
	// A forged route header and mission header change nothing.
	headers := map[string]string{
		"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9",
		agentcall.HeaderRouteAgent: "other", "x-gibson-mission": "m-evil",
	}

	rec := rpcCall(h, "/a2a/inbound/recon", sendBody, headers)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, starts.got, 1)
	got := starts.got[0]
	assert.Equal(t, "recon", got.Agent)
	assert.Equal(t, InboundCaller{Tenant: "acme", Subject: "agent_principal:9"}, got.Caller)
	ids, present, err := TargetsOf(got.Message)
	require.NoError(t, err)
	assert.True(t, present)
	assert.Equal(t, []string{"t1"}, ids)
	var resp struct {
		Result struct {
			Task struct {
				ID string `json:"id"`
			} `json:"task"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "m-1", resp.Result.Task.ID, rec.Body.String())
}

func TestInboundRPC_Refusals(t *testing.T) {
	trusted := map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"}
	tests := []struct {
		name       string
		path       string
		body       string
		headers    map[string]string
		starts     *fakeStarts
		wantStatus int
		wantCode   int // the JSON-RPC error code, 0 for none
		wantStart  int
	}{
		{"no caller headers", "/a2a/inbound/recon", sendBody, nil, &fakeStarts{}, http.StatusUnauthorized, 0, 0},
		{"a path with an invalid agent", agentcall.InboundPrefix + "Re_con", sendBody, trusted, &fakeStarts{},
			http.StatusNotFound, 0, 0},
		{"a message with no parts", "/a2a/inbound/recon",
			`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"ROLE_USER","parts":[]}}}`,
			trusted, &fakeStarts{}, http.StatusOK, codeInvalidParams, 0},
		{"a body that is not JSON", "/a2a/inbound/recon", `{`, trusted, &fakeStarts{}, http.StatusOK, codeParse, 0},
		{"a start that fails with an internal cause", "/a2a/inbound/recon", sendBody, trusted,
			&fakeStarts{err: errors.New("redis is down")}, http.StatusOK, codeInternal, 1},
		{"a start that policy refuses", "/a2a/inbound/recon", sendBody, trusted,
			&fakeStarts{err: ErrRefused}, http.StatusOK, codePermissionDenied, 1},
		{"a method that is not served", "/a2a/inbound/recon",
			`{"jsonrpc":"2.0","id":1,"method":"ListTasks","params":{}}`, trusted, &fakeStarts{}, http.StatusOK, codeUnsupported, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := rpcCall(NewInboundHandler(tt.starts, &recordingCards{}, allowGrants), tt.path, tt.body, tt.headers)
			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantStatus == http.StatusOK {
				assert.Equal(t, tt.wantCode, rpcErrorCode(t, rec.Body.String()))
			}
			assert.NotContains(t, rec.Body.String(), "redis is down", "an internal cause never reaches the caller")
			assert.Len(t, tt.starts.got, tt.wantStart)
		})
	}
}

func TestInboundRPC_RefusesAContextWithNoCaller(t *testing.T) {
	h := &inboundRPC{runs: &fakeStarts{}}
	_, err := h.SendMessage(context.Background(), &a2a.SendMessageRequest{Message: msg(a2a.NewTextPart("x"))})
	assert.ErrorIs(t, err, a2a.ErrUnauthenticated)
}

const (
	getBody    = `{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"m-1"}}`
	cancelBody = `{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{"id":"m-1"}}`
)

// GetTask and CancelTask act for the caller of the headers. The caller never
// names its own identity in the body.
func TestInboundRPC_GetAndCancelActForTheCallerOfTheHeaders(t *testing.T) {
	trusted := map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"}
	for name, body := range map[string]string{"GetTask": getBody, "CancelTask": cancelBody} {
		t.Run(name, func(t *testing.T) {
			starts := &fakeStarts{task: &a2a.Task{ID: "m-1", ContextID: "m-1",
				Status: a2a.TaskStatus{State: a2a.TaskStateWorking}}}
			rec := rpcCall(NewInboundHandler(starts, &recordingCards{}, allowGrants), "/a2a/inbound/recon", body, trusted)

			require.Equal(t, http.StatusOK, rec.Code)
			assert.Contains(t, rec.Body.String(), "TASK_STATE_WORKING")
			require.Len(t, starts.asked, 1)
			assert.Equal(t, InboundCaller{Tenant: "acme", Subject: "agent_principal:9"}, starts.asked[0])
			assert.Equal(t, a2a.TaskID("m-1"), starts.askedByID[0])
			assert.Equal(t, []string{"recon"}, starts.askedAgent, "the run gets the agent of the path")
		})
	}
}

func TestInboundRPC_GetAndCancelRefusals(t *testing.T) {
	trusted := map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"}
	tests := []struct {
		name string
		body string
		err  error
		want int
	}{
		{"get with no task", `{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}`, nil, codeInvalidParams},
		{"cancel with no task", `{"jsonrpc":"2.0","id":1,"method":"CancelTask","params":{}}`, nil, codeInvalidParams},
		{"get of a task that is not of the caller", getBody, ErrNotFound, codeTaskNotFound},
		{"cancel of a task that is not of the caller", cancelBody, ErrNotFound, codeTaskNotFound},
		{"cancel of a task in a final state", cancelBody, ErrNotCancelable, codeNotCancelable},
		{"get with the permits used", getBody, ErrBusy, codeServerBusy},
		{"cancel that fails inside", cancelBody, errors.New("redis is down"), codeInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			starts := &fakeStarts{err: tt.err}
			rec := rpcCall(NewInboundHandler(starts, &recordingCards{}, allowGrants), "/a2a/inbound/recon", tt.body, trusted)
			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, tt.want, rpcErrorCode(t, rec.Body.String()))
			assert.NotContains(t, rec.Body.String(), "redis is down")
		})
	}
}

func TestInboundRPC_RefusesAGetOrCancelWithNoCaller(t *testing.T) {
	h := &inboundRPC{runs: &fakeStarts{}}
	_, err := h.GetTask(context.Background(), &a2a.GetTaskRequest{ID: "m-1"})
	require.ErrorIs(t, err, a2a.ErrUnauthenticated)
	_, err = h.CancelTask(context.Background(), &a2a.CancelTaskRequest{ID: "m-1"})
	assert.ErrorIs(t, err, a2a.ErrUnauthenticated)
}

// An outside caller can never answer an approval. A message that names a Task is
// the way an A2A client answers a request for input, so the daemon refuses it
// and starts nothing.
func TestInboundRPC_AMessageToATaskIsRefusedAndStartsNothing(t *testing.T) {
	starts := &fakeStarts{}
	body := `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":` +
		`{"messageId":"m","taskId":"m-1","role":"ROLE_USER","parts":[{"text":"yes, approve"}]}}}`
	trusted := map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"}

	rec := rpcCall(NewInboundHandler(starts, &recordingCards{}, allowGrants), "/a2a/inbound/recon", body, trusted)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, codePermissionDenied, rpcErrorCode(t, rec.Body.String()))
	assert.Contains(t, rec.Body.String(), "cannot answer an approval")
	assert.Empty(t, starts.got, "no mission started")
	assert.Empty(t, starts.asked)
}

// A message that is not well formed is an invalid params error. It is never an
// internal error, and an empty list never means all targets.
func TestInboundRPC_AMalformedTargetListIsAnInvalidParamsError(t *testing.T) {
	trusted := map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"}
	for name, parts := range map[string]string{
		"two lists":  `[{"data":{"targets":["a"]}},{"data":{"targets":["b"]}}]`,
		"empty list": `[{"data":{"targets":[]}}]`,
		"a string":   `[{"data":{"targets":"a"}}]`,
	} {
		t.Run(name, func(t *testing.T) {
			starts := &fakeStarts{}
			// The fake start runs TargetsOf as the daemon does.
			body := `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"ROLE_USER","parts":` + parts + `}}}`
			h := NewInboundHandler(startsThatReadTargets{starts}, &recordingCards{}, allowGrants)
			rec := rpcCall(h, "/a2a/inbound/recon", body, trusted)
			assert.Equal(t, codeInvalidParams, rpcErrorCode(t, rec.Body.String()))
		})
	}
}

// startsThatReadTargets reads the target list of the message before it answers.
type startsThatReadTargets struct{ *fakeStarts }

func (s startsThatReadTargets) Start(ctx context.Context, req InboundStart) (*a2a.Task, error) {
	if _, _, err := TargetsOf(req.Message); err != nil {
		return nil, err
	}
	return s.fakeStarts.Start(ctx, req)
}

// A body over the limit is refused, and it starts nothing. Without a limit the
// handler reads a body of any size.
func TestInboundRPC_ABodyOverTheLimitIsRefused(t *testing.T) {
	trusted := map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"}
	starts := &fakeStarts{}
	big := `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"ROLE_USER",` +
		`"parts":[{"text":"` + strings.Repeat("A", MaxInboundRequestBytes) + `"}]}}}`

	rec := rpcCall(NewInboundHandler(starts, &recordingCards{}, allowGrants), "/a2a/inbound/recon", big, trusted)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, codeParse, rpcErrorCode(t, rec.Body.String()), "a body over the limit is a parse error")
	assert.Empty(t, starts.got)

	ok := rpcCall(NewInboundHandler(starts, &recordingCards{}, allowGrants), "/a2a/inbound/recon", sendBody, trusted)
	assert.Contains(t, ok.Body.String(), "result", "a normal message still passes")
}

// fakeGrants answers the question of the live grant.
type fakeGrants struct {
	ok    bool
	err   error
	asked int
}

func (f *fakeGrants) CanOriginate(context.Context, InboundCaller, string) (bool, error) {
	f.asked++
	return f.ok, f.err
}

var allowGrants = &fakeGrants{ok: true}

// The method that runs is the method that checks. A start, a cancel and the Agent
// Card need the live grant. A read needs none, so a caller keeps the read of its own
// missions after an unpublish or a revoke of its grant.
func TestInboundRPC_TheGrantIsCheckedByTheMethodThatRuns(t *testing.T) {
	trusted := map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"}
	task := &a2a.Task{ID: "m-1", ContextID: "m-1", Status: a2a.TaskStatus{State: a2a.TaskStateCompleted}}
	tests := []struct {
		name        string
		body        string
		wantGrant   bool
		wantReaches int
	}{
		{"a start", sendBody, true, 1},
		{"a cancel", cancelBody, true, 1},
		{"a read", getBody, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name+" with no grant", func(t *testing.T) {
			starts := &fakeStarts{task: task}
			grants := &fakeGrants{}
			rec := rpcCall(NewInboundHandler(starts, &recordingCards{}, grants), "/a2a/inbound/recon", tt.body, trusted)
			require.Equal(t, http.StatusOK, rec.Code)
			if tt.wantGrant {
				if tt.name == "a start" {
					assert.Zero(t, rpcErrorCode(t, rec.Body.String()), "a start with no grant is a Task and not an error")
					assert.Contains(t, rec.Body.String(), "TASK_STATE_REJECTED")
					assert.Contains(t, rec.Body.String(), ReasonAgentNotAvailable)
				} else {
					assert.Equal(t, codePermissionDenied, rpcErrorCode(t, rec.Body.String()), "a cancel with no grant")
				}
				assert.Empty(t, starts.got)
				assert.Empty(t, starts.asked, "a refused call reached no run")
				assert.Equal(t, 1, grants.asked)
			} else {
				assert.Contains(t, rec.Body.String(), "TASK_STATE_COMPLETED", "a read needs no grant")
				assert.Equal(t, 0, grants.asked, "a read asks no grant")
			}
		})
	}
	// The grant check fails inside: the call is refused and starts nothing.
	starts := &fakeStarts{task: task}
	rec := rpcCall(NewInboundHandler(starts, &recordingCards{}, &fakeGrants{err: errors.New("fga down")}),
		"/a2a/inbound/recon", sendBody, trusted)
	assert.Equal(t, codeInternal, rpcErrorCode(t, rec.Body.String()))
	assert.NotContains(t, rec.Body.String(), "fga down")
	assert.Empty(t, starts.got)
}

func TestInboundCard_NeedsTheLiveGrant(t *testing.T) {
	cards := &recordingCards{cards: map[string]*a2a.AgentCard{"recon": {Name: "recon"}}}
	hdr := map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"}

	// No grant gives the answer of an agent with no card: 404.
	rec := inboundGet(NewInboundHandler(&fakeStarts{}, cards, &fakeGrants{}), "/a2a/inbound/recon"+agentcall.CardPath, hdr)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Zero(t, cards.asked, "no card is read for a caller with no grant")

	rec = inboundGet(NewInboundHandler(&fakeStarts{}, cards, &fakeGrants{err: errors.New("fga down")}),
		"/a2a/inbound/recon"+agentcall.CardPath, hdr)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.NotContains(t, rec.Body.String(), "fga down")
}

func TestAfterResponse_RunsAfterTheHandlerAndAtOnceWithNoRequest(t *testing.T) {
	ran := false
	AfterResponse(context.Background(), func() { ran = true })
	assert.True(t, ran, "with no request the function runs at once")

	ran = false
	ctx, done := WithResponseHooks(context.Background())
	AfterResponse(ctx, func() { ran = true })
	assert.False(t, ran)
	done()
	assert.True(t, ran)
}

// The busy error maps to a retryable server error of JSON-RPC.
func TestMapError_BusyIsARetryableServerError(t *testing.T) {
	err := MapError(ErrBusy)
	require.ErrorIs(t, err, a2a.ErrServerError)
	assert.Contains(t, err.Error(), "retry later")
}

// The handler wraps only the SendMessage result as {"task": ...}. GetTask and
// CancelTask put the Task directly in "result". The SDK client and the exit test
// decode by this shape.
func TestInboundRPC_ResultShapePerMethod(t *testing.T) {
	task := &a2a.Task{ID: "m-1", ContextID: "m-1", Status: a2a.TaskStatus{State: a2a.TaskStateCompleted}}
	tests := []struct {
		method, body string
		wrapped      bool
	}{
		{"SendMessage", sendBody, true},
		{"GetTask", getBody, false},
		{"CancelTask", cancelBody, false},
	}
	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			rec := rpcCall(NewInboundHandler(&fakeStarts{task: task}, &recordingCards{}, allowGrants), "/a2a/inbound/recon", tt.body, map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"})
			var r struct {
				Result map[string]json.RawMessage `json:"result"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &r), rec.Body.String())
			_, hasTask := r.Result["task"]
			assert.Equal(t, tt.wrapped, hasTask, rec.Body.String())
			_, hasStatus := r.Result["status"]
			assert.Equal(t, !tt.wrapped, hasStatus, rec.Body.String())
		})
	}
}

func TestWriteTimeoutFor(t *testing.T) {
	tests := []struct {
		size int64
		want time.Duration
	}{
		{0, InboundWriteFloor},
		{1, InboundWriteFloor + InboundWritePerMiB},
		{1 << 20, InboundWriteFloor + InboundWritePerMiB},
		{(1 << 20) + 1, InboundWriteFloor + 2*InboundWritePerMiB},
		{50 << 20, InboundWriteFloor + 50*InboundWritePerMiB},
		{10 << 30, InboundWriteMax},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, WriteTimeoutFor(tt.size), "size %d", tt.size)
	}
}

// deadlineRecorder records the write deadlines that a handler sets.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadlines = append(d.deadlines, t)
	return nil
}

// Every inbound response has a write deadline, and a result sets a longer one for
// its size.
func TestInboundMiddleware_SetsTheWriteDeadline(t *testing.T) {
	headers := map[string]string{"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"}
	task := &a2a.Task{ID: "m-1", Status: a2a.TaskStatus{State: a2a.TaskStateCompleted}}
	for name, size := range map[string]int64{"no result": 0, "a result of 20 MiB": 20 << 20} {
		t.Run(name, func(t *testing.T) {
			h := NewInboundHandler(&fakeStarts{task: task, resultSize: size}, &recordingCards{}, allowGrants)
			req := httptest.NewRequest(http.MethodPost, "/a2a/inbound/recon", strings.NewReader(getBody))
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			before := time.Now()
			h.ServeHTTP(rec, req)

			require.NotEmpty(t, rec.deadlines, "the response has a write deadline")
			require.True(t, rec.deadlines[len(rec.deadlines)-1].IsZero(), "the deadline is cleared at the end")
			last := rec.deadlines[len(rec.deadlines)-2]
			assert.WithinDuration(t, before.Add(WriteTimeoutFor(size)), last, 5*time.Second)
		})
	}
}

// orderRecorder records the order of the deadlines and the writes of a response.
type orderRecorder struct {
	*httptest.ResponseRecorder
	events []string
}

func (o *orderRecorder) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		o.events = append(o.events, "deadline:cleared")
	} else {
		o.events = append(o.events, "deadline:set")
	}
	return nil
}

func (o *orderRecorder) Write(b []byte) (int, error) {
	o.events = append(o.events, "write")
	n, err := o.ResponseRecorder.Write(b)
	if err != nil {
		return n, fmt.Errorf("record the write: %w", err)
	}
	return n, nil
}

// On a kept-alive connection the deadline of one request must not stay for the next.
// The deadline is set before the first write, and it is cleared after the last one.
// The refusal of a request with no caller is a write too, so it is bound.
func TestInboundMiddleware_SetsTheDeadlineFirstAndClearsItLast(t *testing.T) {
	task := &a2a.Task{ID: "m-1", Status: a2a.TaskStatus{State: a2a.TaskStateCompleted}}
	for name, headers := range map[string]map[string]string{
		"a refused request":   nil,
		"an answered request": {"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9"},
	} {
		t.Run(name, func(t *testing.T) {
			h := NewInboundHandler(&fakeStarts{task: task, resultSize: 20 << 20}, &recordingCards{}, allowGrants)
			req := httptest.NewRequest(http.MethodPost, "/a2a/inbound/recon", strings.NewReader(getBody))
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			rec := &orderRecorder{ResponseRecorder: httptest.NewRecorder()}

			h.ServeHTTP(rec, req)

			require.GreaterOrEqual(t, len(rec.events), 3, "%v", rec.events)
			assert.Equal(t, "deadline:set", rec.events[0], "the deadline comes before any write")
			assert.Equal(t, "deadline:cleared", rec.events[len(rec.events)-1], "the deadline is cleared at the end")
			firstWrite := slices.Index(rec.events, "write")
			assert.Positive(t, firstWrite)
		})
	}
}

func TestWebhookOf(t *testing.T) {
	hook := map[string]any{"title": "x"}
	obj := a2a.NewDataPart(map[string]any{"webhook": hook})
	tests := []struct {
		name        string
		msg         *a2a.Message
		want        map[string]any
		wantPresent bool
		wantErr     bool
	}{
		{"nil message", nil, nil, false, false},
		{"no data part", &a2a.Message{Parts: []*a2a.Part{a2a.NewTextPart("webhook")}}, nil, false, false},
		{"the webhook", &a2a.Message{Parts: []*a2a.Part{a2a.NewTextPart("note"), obj}}, hook, true, false},
		{"two webhooks", &a2a.Message{Parts: []*a2a.Part{obj, obj}}, nil, false, true},
		{"not an object", &a2a.Message{Parts: []*a2a.Part{a2a.NewDataPart(map[string]any{"webhook": "x"})}}, nil, false, true},
		{"too large", &a2a.Message{Parts: []*a2a.Part{a2a.NewDataPart(map[string]any{
			"webhook": map[string]any{"body": strings.Repeat("a", MaxWebhookBytes)}})}}, nil, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, present, err := WebhookOf(tt.msg)
			if tt.wantErr {
				if !errors.Is(err, a2a.ErrInvalidParams) {
					t.Fatalf("err = %v, want invalid params", err)
				}
				return
			}
			if err != nil || present != tt.wantPresent || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v %v %v", got, present, err)
			}
		})
	}
}

func TestWebhookMessageKey(t *testing.T) {
	tests := []struct {
		name string
		msg  *a2a.Message
		want string
	}{
		{"nil", nil, ""},
		{"plain id", &a2a.Message{ID: "msg-1"}, ""},
		{"webhook id", &a2a.Message{ID: "webhook:okta:e1"}, "webhook:okta:e1"},
		{"metadata", &a2a.Message{ID: "x", Metadata: map[string]any{"webhook_id": "e2", "webhook_source": "okta"}}, "webhook:okta:e2"},
		{"empty metadata id", &a2a.Message{ID: "x", Metadata: map[string]any{"webhook_id": ""}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WebhookMessageKey(tt.msg); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
