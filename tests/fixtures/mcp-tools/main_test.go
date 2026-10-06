// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func call(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handle(rec, httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)))
	return rec
}

// tools/list returns exactly the names that the exit test expects.
func TestToolsList_MatchesTheExpectedNames(t *testing.T) {
	rec := call(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	var resp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	f, err := os.Open("expected-tools.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var want []string
	for sc := bufio.NewScanner(f); sc.Scan(); {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			want = append(want, line)
		}
	}
	if len(resp.Result.Tools) != len(want) {
		t.Fatalf("tools = %+v, want %v", resp.Result.Tools, want)
	}
	for i, tool := range resp.Result.Tools {
		if tool.Name != want[i] {
			t.Errorf("tool %d = %q, want %q", i, tool.Name, want[i])
		}
	}
}

func TestInitializeNotificationAndUnknownMethod(t *testing.T) {
	if rec := call(t, `{"jsonrpc":"2.0","id":1,"method":"initialize"}`); rec.Header().Get("Mcp-Session-Id") == "" || !strings.Contains(rec.Body.String(), "protocolVersion") {
		t.Errorf("initialize = %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); rec.Code != http.StatusAccepted {
		t.Errorf("notification code = %d", rec.Code)
	}
	if rec := call(t, `{"jsonrpc":"2.0","id":3,"method":"nope"}`); !strings.Contains(rec.Body.String(), "-32601") {
		t.Errorf("unknown method = %s", rec.Body)
	}
	if rec := call(t, `{`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad JSON code = %d", rec.Code)
	}
}

func TestPingGetAndPort(t *testing.T) {
	if rec := call(t, `{"jsonrpc":"2.0","id":4,"method":"ping"}`); !strings.Contains(rec.Body.String(), `"result"`) {
		t.Errorf("ping = %s", rec.Body)
	}
	rec := httptest.NewRecorder()
	handle(rec, httptest.NewRequest(http.MethodGet, "/mcp", http.NoBody))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET code = %d", rec.Code)
	}
	if got := newServer(func(string) string { return "" }).Addr; got != ":8080" {
		t.Errorf("default addr = %q", got)
	}
	if got := newServer(func(string) string { return "9090" }).Addr; got != ":9090" {
		t.Errorf("MCP_PORT addr = %q", got)
	}
}
