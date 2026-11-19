// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

// fakeStarts records each inbound start and answers with a fixed Task.
type fakeStarts struct {
	got  []InboundStart
	task *a2a.Task
	err  error
}

func (f *fakeStarts) Start(_ context.Context, req InboundStart) (*a2a.Task, error) {
	f.got = append(f.got, req)
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

const sendBody = `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":` +
	`{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"scan"},{"data":{"targets":["t1"]}}]}}}`

func TestInboundRPC_SendMessageStartsARunForTheAgentInThePath(t *testing.T) {
	starts := &fakeStarts{task: &a2a.Task{ID: "m-1", ContextID: "m-1", Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted}}}
	h := NewInboundHandler(starts, &recordingCards{})
	// A forged route header and mission header change nothing.
	headers := map[string]string{
		"x-gibson-tenant": "acme", "x-gibson-subject": "agent_principal:9",
		agentcall.HeaderRouteAgent: "other", "x-gibson-mission": "m-evil",
	}

	rec := rpcCall(h, agentcall.InboundPathFor("recon"), sendBody, headers)

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
		wantBody   string
		wantStart  int
	}{
		{"no caller headers", agentcall.InboundPathFor("recon"), sendBody, nil, &fakeStarts{}, http.StatusUnauthorized, "", 0},
		{"a path with an invalid agent", agentcall.InboundPrefix + "Re_con", sendBody, trusted, &fakeStarts{},
			http.StatusNotFound, "", 0},
		{"a message with no parts", agentcall.InboundPathFor("recon"),
			`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m","role":"ROLE_USER","parts":[]}}}`,
			trusted, &fakeStarts{}, http.StatusOK, "error", 0},
		{"a start that fails with an internal cause", agentcall.InboundPathFor("recon"), sendBody, trusted,
			&fakeStarts{err: errors.New("redis is down")}, http.StatusOK, "error", 1},
		{"a start that policy refuses", agentcall.InboundPathFor("recon"), sendBody, trusted,
			&fakeStarts{err: ErrRefused}, http.StatusOK, "error", 1},
		{"a method that is not served", agentcall.InboundPathFor("recon"),
			`{"jsonrpc":"2.0","id":1,"method":"ListTasks","params":{}}`, trusted, &fakeStarts{}, http.StatusOK, "error", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := rpcCall(NewInboundHandler(tt.starts, &recordingCards{}), tt.path, tt.body, tt.headers)
			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Contains(t, rec.Body.String(), tt.wantBody)
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
