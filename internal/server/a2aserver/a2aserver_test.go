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
)

type fakeRuns struct {
	started []StartRequest
	err     error
	seen    Caller
}

func (f *fakeRuns) Start(_ context.Context, req StartRequest) (*a2a.Task, error) {
	f.started = append(f.started, req)
	if f.err != nil {
		return nil, f.err
	}
	return &a2a.Task{ID: "t-1", ContextID: "c-1", Status: a2a.TaskStatus{State: a2a.TaskStateSubmitted}}, nil
}

func (f *fakeRuns) Task(_ context.Context, c Caller, id a2a.TaskID) (*a2a.Task, error) {
	f.seen = c
	if f.err != nil {
		return nil, f.err
	}
	return &a2a.Task{ID: id, ContextID: "c-1", Status: a2a.TaskStatus{State: a2a.TaskStateWorking}}, nil
}

func (f *fakeRuns) Cancel(_ context.Context, c Caller, id a2a.TaskID) (*a2a.Task, error) {
	f.seen = c
	if f.err != nil {
		return nil, f.err
	}
	return &a2a.Task{ID: id, ContextID: "c-1", Status: a2a.TaskStatus{State: a2a.TaskStateCanceled}}, nil
}

type fakeCards struct{ err error }

func (f fakeCards) Card(_ context.Context, _, agent string) (*a2a.AgentCard, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &a2a.AgentCard{Name: agent}, nil
}

func trustedHeaders(r *http.Request) {
	r.Header.Set("x-gibson-tenant", "acme")
	r.Header.Set("x-gibson-subject", "agent:caller")
	r.Header.Set("x-gibson-mission", "m1")
	r.Header.Set("x-gibson-task", "w1")
	r.Header.Set("x-gibson-route-agent", "scout")
}

func rpc(t *testing.T, h http.Handler, method string, params any, mutate func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	trustedHeaders(req)
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sendParams() map[string]any {
	return map[string]any{"message": map[string]any{
		"messageId": "msg-1", "role": "ROLE_USER", "parts": []any{map[string]any{"text": "map the host"}},
	}}
}

func TestSendMessage_StartsWorkForTheCallerMission(t *testing.T) {
	runs := &fakeRuns{}
	rec := rpc(t, NewHandler(runs, fakeCards{}), "SendMessage", sendParams(), func(r *http.Request) {
		r.Header.Set("x-gibson-route-bank", "bank-9")
	})
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if len(runs.started) != 1 {
		t.Fatalf("started = %d", len(runs.started))
	}
	got := runs.started[0]
	if got.Caller != (Caller{Tenant: "acme", Subject: "agent:caller", Mission: "m1", Task: "w1"}) {
		t.Errorf("caller = %+v", got.Caller)
	}
	if got.Route != (Route{Agent: "scout", Bank: "bank-9"}) {
		t.Errorf("route = %+v", got.Route)
	}
	if TextOf(got.Message) != "map the host" {
		t.Errorf("text = %q", TextOf(got.Message))
	}
}

func TestSendMessage_TheBodyCannotChooseTheCaller(t *testing.T) {
	runs := &fakeRuns{}
	params := sendParams()
	params["tenant"] = "evil"
	params["metadata"] = map[string]any{"mission": "m-other", "tenant": "evil"}
	if rec := rpc(t, NewHandler(runs, fakeCards{}), "SendMessage", params, nil); rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
	if c := runs.started[0].Caller; c.Tenant != "acme" || c.Mission != "m1" {
		t.Fatalf("caller = %+v", c)
	}
}

func TestRequests_AreRefusedWithoutTheTrustedHeaders(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"no tenant", "x-gibson-tenant", http.StatusUnauthorized},
		{"no subject", "x-gibson-subject", http.StatusUnauthorized},
		{"no mission", "x-gibson-mission", http.StatusForbidden},
		{"no task", "x-gibson-task", http.StatusForbidden},
		{"no agent", "x-gibson-route-agent", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runs := &fakeRuns{}
			rec := rpc(t, NewHandler(runs, fakeCards{}), "SendMessage", sendParams(), func(r *http.Request) {
				r.Header.Del(tc.header)
			})
			if rec.Code != tc.want {
				t.Fatalf("status %d, want %d", rec.Code, tc.want)
			}
			if len(runs.started) != 0 {
				t.Fatal("a refused request must start no work")
			}
		})
	}
}

func TestGetTaskAndCancelTask_UseTheCallerFromTheHeaders(t *testing.T) {
	runs := &fakeRuns{}
	h := NewHandler(runs, fakeCards{})
	rec := rpc(t, h, "GetTask", map[string]any{"id": "t-1"}, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "TASK_STATE_WORKING") {
		t.Fatalf("GetTask: %d %s", rec.Code, rec.Body)
	}
	if runs.seen.Mission != "m1" || runs.seen.Tenant != "acme" {
		t.Fatalf("caller = %+v", runs.seen)
	}
	rec = rpc(t, h, "CancelTask", map[string]any{"id": "t-1"}, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "TASK_STATE_CANCELED") {
		t.Fatalf("CancelTask: %d %s", rec.Code, rec.Body)
	}
}

func TestErrors_MapToA2AErrorsWithoutLeakingText(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"not found":      {ErrNotFound, "task not found"},
		"not cancelable": {ErrNotCancelable, "cannot be canceled"},
		"refused":        {ErrRefused, "permission denied"},
		"unknown":        {errors.New("pq: secret table name"), "internal error"},
	} {
		t.Run(name, func(t *testing.T) {
			rec := rpc(t, NewHandler(&fakeRuns{err: tc.err}, fakeCards{}), "GetTask", map[string]any{"id": "t"}, nil)
			body := rec.Body.String()
			if !strings.Contains(body, tc.want) {
				t.Fatalf("body %s does not hold %q", body, tc.want)
			}
			if strings.Contains(body, "secret table name") {
				t.Fatalf("the error text leaked: %s", body)
			}
		})
	}
}

func TestSendMessage_RefusesAnEmptyMessage(t *testing.T) {
	runs := &fakeRuns{}
	params := map[string]any{"message": map[string]any{"messageId": "m", "role": "ROLE_USER", "parts": []any{}}}
	rec := rpc(t, NewHandler(runs, fakeCards{}), "SendMessage", params, nil)
	if len(runs.started) != 0 || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("started %d body %s", len(runs.started), rec.Body)
	}
}

func TestUnsupportedMethods(t *testing.T) {
	rec := rpc(t, NewHandler(&fakeRuns{}, fakeCards{}), "ListTasks", map[string]any{}, nil)
	if !strings.Contains(rec.Body.String(), "not supported") {
		t.Fatalf("body %s", rec.Body)
	}
}

func cardRequest(path string, mutate func(*http.Request)) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
	trustedHeaders(req)
	if mutate != nil {
		mutate(req)
	}
	return req
}

func TestCard_ServedForTheRoutedAgent(t *testing.T) {
	h := NewHandler(&fakeRuns{}, fakeCards{})
	rec := httptest.NewRecorder()
	// A card needs no mission.
	h.ServeHTTP(rec, cardRequest("/agents/scout/.well-known/agent-card.json", func(r *http.Request) {
		r.Header.Del("x-gibson-mission")
		r.Header.Del("x-gibson-task")
	}))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"scout"`) {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
}

func TestCard_RefusesAPathThatDisagreesWithTheRoute(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(&fakeRuns{}, fakeCards{}).ServeHTTP(rec, cardRequest("/agents/other/.well-known/agent-card.json", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestCard_RefusesWithoutACaller(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(&fakeRuns{}, fakeCards{}).ServeHTTP(rec, cardRequest("/agents/scout/.well-known/agent-card.json",
		func(r *http.Request) { r.Header.Del("x-gibson-tenant") }))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestCard_NotFoundAndFailure(t *testing.T) {
	rec := httptest.NewRecorder()
	NewHandler(&fakeRuns{}, fakeCards{err: ErrNoCard}).ServeHTTP(rec, cardRequest("/agents/scout/.well-known/agent-card.json", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	NewHandler(&fakeRuns{}, fakeCards{err: errors.New("redis down")}).ServeHTTP(rec, cardRequest("/agents/scout/.well-known/agent-card.json", nil))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "redis") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body)
	}
}
