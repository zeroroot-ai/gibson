// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Command mockprovider is a fake model provider. A gateway test points a
// gateway backend at it. It answers four calls:
//
//   - POST /v1/messages answers in the Anthropic Messages format. The reply
//     holds a thinking block, a text block and a tool_use block. A request
//     with "stream": true gets the same reply as server-sent events.
//   - POST /v1/responses answers in the Open Responses format, plain or
//     streamed. The reply holds a reasoning item, a message item and a
//     function_call item.
//   - POST /v1/embeddings answers in the OpenAI Embeddings format.
//   - GET /v1/models answers with one model list.
//
// The provider records each request, with its headers and its body. A test
// reads the record with Provider.Requests, or with GET /_recorded when the
// provider runs as a process. A call to /_recorded is not recorded.
//
// The provider checks no credential. It records the credential headers, so a
// test can assert which key the gateway sent.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// Model is the model name that the model list holds and that a reply echoes
// when the request has no model name.
const Model = "claude-sonnet-5-5"

// Fixed reply content. A test asserts these values in a trace.
const (
	ThinkingText = "I must scan the host first."
	ReplyText    = "I will run a port scan."
	ToolName     = "nmap"
	ToolID       = "toolu_2"
	ToolInput    = `{"target":"10.0.0.5","ports":"1-1024"}`
)

// Recorded is one request that the provider received.
type Recorded struct {
	Method string      `json:"method"`
	Path   string      `json:"path"`
	Header http.Header `json:"header"`
	Body   string      `json:"body"`
}

// Provider is the fake model provider. It is an http.Handler.
type Provider struct {
	mu       sync.Mutex
	recorded []Recorded
}

// Requests returns a copy of each recorded request, oldest first.
func (p *Provider) Requests() []Recorded {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Recorded(nil), p.recorded...)
}

// Reset deletes each recorded request.
func (p *Provider) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.recorded = nil
}

// ServeHTTP implements http.Handler.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/_recorded" {
		writeJSON(w, http.StatusOK, p.Requests())
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.recorded = append(p.recorded, Recorded{
		Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: string(body),
	})
	p.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/models":
		serveModels(w)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/messages":
		serveMessages(w, body)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/responses":
		serveResponses(w, body)
	case r.Method == http.MethodPost && r.URL.Path == "/v1/embeddings":
		serveEmbeddings(w, body)
	default:
		http.NotFound(w, r)
	}
}

// request holds the fields of a call body that the provider reads.
type request struct {
	Model      string          `json:"model"`
	Stream     bool            `json:"stream"`
	Input      json.RawMessage `json:"input"`
	Dimensions int             `json:"dimensions"`
}

func parse(body []byte) request {
	var req request
	// A body that does not parse leaves the zero value. The reply then uses
	// the default model name.
	_ = json.Unmarshal(body, &req)
	if req.Model == "" {
		req.Model = Model
	}
	return req
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "marshal reply: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func serveModels(w http.ResponseWriter) {
	// The reply fits the Anthropic list and the OpenAI list.
	writeJSON(w, http.StatusOK, map[string]any{
		"object":   "list",
		"has_more": false,
		"data": []map[string]any{
			{"id": Model, "type": "model", "object": "model", "display_name": Model},
		},
	})
}

func serveMessages(w http.ResponseWriter, body []byte) {
	req := parse(body)
	if req.Stream {
		serveMessagesStream(w, req.Model)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": "msg_1", "type": "message", "role": "assistant", "model": req.Model,
		"content": []map[string]any{
			{"type": "thinking", "thinking": ThinkingText, "signature": "sig"},
			{"type": "text", "text": ReplyText},
			{"type": "tool_use", "id": ToolID, "name": ToolName, "input": json.RawMessage(ToolInput)},
		},
		"stop_reason": "tool_use",
		"usage":       map[string]any{"input_tokens": 120, "output_tokens": 45},
	})
}

// sseWriter writes server-sent events and flushes after each one.
type sseWriter struct {
	w http.ResponseWriter
}

func newSSE(w http.ResponseWriter) *sseWriter {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	return &sseWriter{w: w}
}

func (s *sseWriter) event(name string, data map[string]any) {
	data["type"] = name
	raw, err := json.Marshal(data)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", name, raw)
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}
}

func serveMessagesStream(w http.ResponseWriter, model string) {
	s := newSSE(w)
	s.event("message_start", map[string]any{"message": map[string]any{
		"id": "msg_1", "type": "message", "role": "assistant", "model": model,
		"content": []any{}, "stop_reason": nil,
		"usage": map[string]any{"input_tokens": 120, "output_tokens": 1},
	}})
	s.event("content_block_start", map[string]any{"index": 0,
		"content_block": map[string]any{"type": "thinking", "thinking": ""}})
	s.event("content_block_delta", map[string]any{"index": 0,
		"delta": map[string]any{"type": "thinking_delta", "thinking": ThinkingText}})
	s.event("content_block_delta", map[string]any{"index": 0,
		"delta": map[string]any{"type": "signature_delta", "signature": "sig"}})
	s.event("content_block_stop", map[string]any{"index": 0})
	s.event("content_block_start", map[string]any{"index": 1,
		"content_block": map[string]any{"type": "text", "text": ""}})
	s.event("content_block_delta", map[string]any{"index": 1,
		"delta": map[string]any{"type": "text_delta", "text": "I will run "}})
	s.event("content_block_delta", map[string]any{"index": 1,
		"delta": map[string]any{"type": "text_delta", "text": "a port scan."}})
	s.event("content_block_stop", map[string]any{"index": 1})
	s.event("content_block_start", map[string]any{"index": 2,
		"content_block": map[string]any{"type": "tool_use", "id": ToolID, "name": ToolName, "input": map[string]any{}}})
	s.event("content_block_delta", map[string]any{"index": 2,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": `{"target":"10.0.0.5",`}})
	s.event("content_block_delta", map[string]any{"index": 2,
		"delta": map[string]any{"type": "input_json_delta", "partial_json": `"ports":"1-1024"}`}})
	s.event("content_block_stop", map[string]any{"index": 2})
	s.event("message_delta", map[string]any{
		"delta": map[string]any{"stop_reason": "tool_use"},
		"usage": map[string]any{"output_tokens": 45},
	})
	s.event("message_stop", map[string]any{})
}

// responseOutput is the output list of an Open Responses reply.
func responseOutput() []map[string]any {
	return []map[string]any{
		{"type": "reasoning", "id": "rs_1", "summary": []map[string]any{
			{"type": "summary_text", "text": ThinkingText},
		}},
		{"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
			"content": []map[string]any{{"type": "output_text", "text": ReplyText, "annotations": []any{}}}},
		{"type": "function_call", "id": "fc_1", "call_id": ToolID, "name": ToolName,
			"arguments": ToolInput, "status": "completed"},
	}
}

func responseObject(model, status string, output []map[string]any) map[string]any {
	return map[string]any{
		"id": "resp_1", "object": "response", "created_at": time.Unix(1700000000, 0).Unix(),
		"status": status, "model": model, "output": output,
		"usage": map[string]any{"input_tokens": 120, "output_tokens": 45, "total_tokens": 165},
	}
}

func serveResponses(w http.ResponseWriter, body []byte) {
	req := parse(body)
	if !req.Stream {
		writeJSON(w, http.StatusOK, responseObject(req.Model, "completed", responseOutput()))
		return
	}
	s := newSSE(w)
	seq := 0
	emit := func(name string, data map[string]any) {
		data["sequence_number"] = seq
		seq++
		s.event(name, data)
	}
	emit("response.created", map[string]any{"response": responseObject(req.Model, "in_progress", []map[string]any{})})
	out := responseOutput()
	for i, item := range out {
		emit("response.output_item.added", map[string]any{"output_index": i, "item": item})
		if item["type"] == "message" {
			emit("response.output_text.delta", map[string]any{
				"output_index": i, "item_id": "msg_1", "content_index": 0, "delta": "I will run ",
			})
			emit("response.output_text.delta", map[string]any{
				"output_index": i, "item_id": "msg_1", "content_index": 0, "delta": "a port scan.",
			})
		}
		emit("response.output_item.done", map[string]any{"output_index": i, "item": item})
	}
	emit("response.completed", map[string]any{"response": responseObject(req.Model, "completed", out)})
}

// defaultDimensions is the vector length when the request names none.
const defaultDimensions = 3

// maxDimensions is the longest vector that the mock builds. A request for a
// longer vector gets an error, so a request cannot set the size of an
// allocation.
const maxDimensions = 8192

func serveEmbeddings(w http.ResponseWriter, body []byte) {
	req := parse(body)
	count := 1
	var list []json.RawMessage
	if err := json.Unmarshal(req.Input, &list); err == nil && len(list) > 0 {
		count = len(list)
	}
	dims := req.Dimensions
	if dims <= 0 {
		dims = defaultDimensions
	}
	if dims > maxDimensions {
		http.Error(w, "dimensions is over the limit of "+strconv.Itoa(maxDimensions), http.StatusBadRequest)
		return
	}
	data := make([]map[string]any, 0, count)
	for i := range count {
		vec := make([]float64, dims)
		for j := range vec {
			vec[j] = float64(j+1) / float64(dims+1)
		}
		data = append(data, map[string]any{"object": "embedding", "index": i, "embedding": vec})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list", "data": data, "model": req.Model,
		"usage": map[string]any{"prompt_tokens": 7, "total_tokens": 7},
	})
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18080", "listen address")
	flag.Parse()
	srv := &http.Server{
		Addr:              *addr,
		Handler:           &Provider{},
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("mock provider listening", "addr", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("mock provider stopped", "error", err)
		os.Exit(1)
	}
}
