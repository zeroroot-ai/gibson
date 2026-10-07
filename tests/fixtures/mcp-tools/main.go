// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command mcp-tools is the fixture MCP server of the Hosted connector exit
// test (gibson#811). It speaks the streamable HTTP transport on /mcp, on the
// port in MCP_PORT (8080 by default, the port that the connector operator
// gives ToolHive). It answers
// initialize, tools/list and tools/call of probe_egress. The tool names are
// the contract that the test checks, in tests/fixtures/mcp-tools/expected-tools.txt.
//
// probe_egress dials an address from inside the connector pod and says
// whether the connection opened. The exit test uses it to prove that the
// egress of a connector follows its host list (gibson#758).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
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
	{
		"name":        "probe_egress",
		"description": "Open a TCP connection to host:port from the connector pod and say whether it opened.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"address": map[string]any{"type": "string"}}},
	},
}

// probeTimeout bounds one probe. A connection that the network policy drops
// times out instead of being refused, so the bound is the answer.
const probeTimeout = 5 * time.Second

// dialer opens the probe connection. Tests replace it.
var dialer = func(ctx context.Context, address string) error {
	conn, err := (&net.Dialer{Timeout: probeTimeout}).DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("dial %s: %w", address, err)
	}
	return conn.Close()
}

// probeEgress answers a tools/call of probe_egress with "reachable" or
// "unreachable: <reason>".
func probeEgress(ctx context.Context, args map[string]any) map[string]any {
	address, _ := args["address"].(string)
	text := "reachable"
	if address == "" {
		text = "unreachable: no address"
	} else if err := dialer(ctx, address); err != nil {
		text = "unreachable: " + err.Error()
	}
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}}
}

type callParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
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
	case "tools/call":
		var p callParams
		if err := json.Unmarshal(req.Params, &p); err != nil || p.Name != "probe_egress" {
			writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID,
				"error": map[string]any{"code": -32602, "message": "only probe_egress can be called"}})
			return
		}
		result = probeEgress(r.Context(), p.Arguments)
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
