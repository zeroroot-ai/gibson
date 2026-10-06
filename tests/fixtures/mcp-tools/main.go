// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command mcp-tools is the fixture MCP server of the Hosted connector exit
// test (gibson#811). It speaks the streamable HTTP transport on /mcp, on the
// port in MCP_PORT (8080 by default, the port that the connector operator
// gives ToolHive). It answers
// initialize and tools/list. The tool names are the contract that the test
// checks, in tests/fixtures/mcp-tools/expected-tools.txt.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

// tools is the tool list of the fixture.
var tools = []map[string]any{
	{
		"name":        "echo",
		"description": "Return the text it gets.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}},
	},
	{
		"name":        "add",
		"description": "Return the sum of two numbers.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "number"}, "b": map[string]any{"type": "number"}}},
	},
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
}

// handle answers one JSON-RPC message of the MCP streamable HTTP transport.
func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad JSON-RPC message", http.StatusBadRequest)
		return
	}
	if len(req.ID) == 0 {
		// A notification, for example notifications/initialized.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result any
	switch req.Method {
	case "initialize":
		w.Header().Set("Mcp-Session-Id", "fixture")
		result = map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "gibson-fixture-mcp-tools", "version": "1.0.0"},
		}
	case "tools/list":
		result = map[string]any{"tools": tools}
	case "ping":
		result = map[string]any{}
	default:
		writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID,
			"error": map[string]any{"code": -32601, "message": "method not found"}})
		return
	}
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// newServer returns the fixture server on the port in MCP_PORT, or on 8080.
func newServer(getenv func(string) string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", handle)
	// ToolHive passes the port in MCP_PORT. The connector operator sets it
	// to 8080.
	port := getenv("MCP_PORT")
	if port == "" {
		port = "8080"
	}
	return &http.Server{Addr: ":" + port, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
}

func main() {
	log.Fatal(newServer(os.Getenv).ListenAndServe())
}
