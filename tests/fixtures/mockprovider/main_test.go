// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func do(t *testing.T, srv *httptest.Server, method, path, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-Api-Key", "k1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read reply of %s: %v", path, err)
	}
	return resp.StatusCode, string(data)
}

func TestProviderAnswersAndRecords(t *testing.T) {
	p := &Provider{}
	srv := httptest.NewServer(p)
	defer srv.Close()

	tests := []struct {
		name, method, path, body string
		want                     []string
	}{
		{"messages", http.MethodPost, "/v1/messages", `{"model":"m1"}`,
			[]string{`"type":"thinking"`, `"type":"tool_use"`, `"model":"m1"`}},
		{"messages stream", http.MethodPost, "/v1/messages", `{"stream":true}`,
			[]string{"event: message_start", "thinking_delta", "input_json_delta", "event: message_stop"}},
		{"responses", http.MethodPost, "/v1/responses", `{"model":"m2"}`,
			[]string{`"type":"reasoning"`, `"type":"function_call"`, `"object":"response"`}},
		{"responses stream", http.MethodPost, "/v1/responses", `{"stream":true}`,
			[]string{"event: response.created", "response.output_text.delta", "event: response.completed"}},
		{"embeddings", http.MethodPost, "/v1/embeddings", `{"input":["a","b"],"dimensions":4}`,
			[]string{`"object":"embedding"`, `"index":1`}},
		{"models", http.MethodGet, "/v1/models", "", []string{Model}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, body := do(t, srv, tt.method, tt.path, tt.body)
			if status != http.StatusOK {
				t.Fatalf("status = %d, want 200. body: %s", status, body)
			}
			for _, want := range tt.want {
				if !strings.Contains(body, want) {
					t.Errorf("reply lacks %q. reply: %s", want, body)
				}
			}
		})
	}

	got := p.Requests()
	if len(got) != len(tests) {
		t.Fatalf("recorded %d requests, want %d", len(got), len(tests))
	}
	if got[0].Header.Get("X-Api-Key") != "k1" || got[0].Body != `{"model":"m1"}` {
		t.Errorf("first record = %+v, want header k1 and the sent body", got[0])
	}
}

func TestRecordedEndpointIsNotRecorded(t *testing.T) {
	p := &Provider{}
	srv := httptest.NewServer(p)
	defer srv.Close()
	do(t, srv, http.MethodGet, "/v1/models", "")
	_, body := do(t, srv, http.MethodGet, "/_recorded", "")
	var recorded []Recorded
	if err := json.Unmarshal([]byte(body), &recorded); err != nil {
		t.Fatalf("parse /_recorded: %v", err)
	}
	if len(recorded) != 1 || recorded[0].Path != "/v1/models" {
		t.Errorf("recorded = %+v, want one /v1/models request", recorded)
	}
}

func TestUnknownPathIs404(t *testing.T) {
	srv := httptest.NewServer(&Provider{})
	defer srv.Close()
	if status, _ := do(t, srv, http.MethodPost, "/v1/nothing", "{}"); status != http.StatusNotFound {
		t.Errorf("status = %d, want 404", status)
	}
}
