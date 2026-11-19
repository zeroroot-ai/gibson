// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package modelclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/server/extauthz/modelcall"
)

type errCloser struct{ err error }

func (c errCloser) Close() error { return c.err }

// frames builds a Stream over the text of an event stream.
func frames(text string) *Stream {
	return &Stream{body: io.NopCloser(strings.NewReader("")), sc: bufio.NewScanner(strings.NewReader(text))}
}

func TestStreamNext_ReadsEventsAndSkipsNonDataLines(t *testing.T) {
	s := frames(": comment\nevent: x\nid: 7\nretry: 5\n\n" +
		"data:{\"type\":\"response.output_text.delta\",\"delta\":\"he\"}\n\n" +
		"data: {\"type\":\"response.created\"}\n\n" +
		"data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"r\",\"status\":\"incomplete\"}}\n\n" +
		"data: [DONE]\n\n" +
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"never\"}\n\n")

	if !s.Next() || s.Event().Type != EventTextDelta || s.Event().Delta != "he" {
		t.Fatalf("first event = %+v", s.Event())
	}
	if !s.Next() || s.Event().Type != "response.created" || s.Event().Delta != "" {
		t.Fatalf("second event = %+v", s.Event())
	}
	if !s.Next() || s.Event().Type != "response.incomplete" || s.Event().Response == nil ||
		s.Event().Response.Status != "incomplete" {
		t.Fatalf("third event = %+v", s.Event())
	}
	if s.Next() {
		t.Fatal("the stream must end at [DONE]")
	}
	if s.Next() {
		t.Fatal("Next after the end must stay false")
	}
	if s.Err() != nil {
		t.Fatalf("a clean end has error %v", s.Err())
	}
}

func TestStreamNext_JoinsDataLinesAndAcceptsAFinalFrameWithoutABlankLine(t *testing.T) {
	s := frames("data: {\"type\":\ndata: \"response.created\"}")

	if !s.Next() || s.Event().Type != "response.created" {
		t.Fatalf("event = %+v, error %v", s.Event(), s.Err())
	}
	if s.Next() {
		t.Fatal("no event is left")
	}
}

func TestStreamNext_Failures(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		wantCode string
		wantErr  string
	}{
		{"bad JSON", "data: {\n\n", "", "decode a stream event"},
		{"bad final response", "data: {\"type\":\"response.completed\",\"response\":[1]}\n\n", "",
			"decode the final response"},
		{"failed with an error object",
			"data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"overloaded\",\"message\":\"busy\"}}}\n\n",
			"overloaded", "busy"},
		{"failed with no error object", "data: {\"type\":\"response.failed\"}\n\n", "failed", "the response failed"},
		{"error event", "data: {\"type\":\"error\",\"code\":\"rate\",\"message\":\"slow down\"}\n\n", "rate", "slow down"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := frames(tt.text)
			if s.Next() {
				t.Fatal("Next returned an event")
			}
			err := s.Err()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want text %q", err, tt.wantErr)
			}
			var failure *ResponseFailure
			if tt.wantCode != "" {
				if !errors.As(err, &failure) || failure.Code != tt.wantCode {
					t.Errorf("error = %#v, want a ResponseFailure with code %q", err, tt.wantCode)
				}
			}
		})
	}
}

func TestStreamNext_ALineOverTheBufferIsAReadError(t *testing.T) {
	s := frames("data: " + strings.Repeat("x", 64) + "\n\n")
	s.sc.Buffer(make([]byte, 0, 8), 16)

	if s.Next() {
		t.Fatal("Next returned an event")
	}
	if err := s.Err(); err == nil || !strings.Contains(err.Error(), "read the stream") ||
		!errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("error = %v", err)
	}
}

func TestStreamClose(t *testing.T) {
	boom := errors.New("boom")
	s := &Stream{body: errCloser{err: boom}}
	if err := s.Close(); !errors.Is(err, boom) || !strings.Contains(err.Error(), "close the stream") {
		t.Errorf("Close = %v", err)
	}
	if err := (&Stream{body: errCloser{}}).Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
}

func TestStream_Refusals(t *testing.T) {
	c, grants := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, " slow down ")
	})
	ctx := context.Background()

	if _, err := c.Stream(ctx, testCaller, Target{Tenant: "acme"}, Request{}); err == nil {
		t.Error("a target with no provider was accepted")
	}
	_, err := c.Stream(ctx, testCaller, testTarget, Request{})
	var api *APIError
	if !errors.As(err, &api) || api.Status != http.StatusTooManyRequests || api.Body != "slow down" {
		t.Fatalf("error = %#v, want a 429 APIError", err)
	}
	if !api.Retryable() || api.Refused() || api.NoRoute() {
		t.Errorf("flags of a 429: retryable %v, refused %v, no route %v", api.Retryable(), api.Refused(), api.NoRoute())
	}
	if want := "model gateway answered 429: slow down"; api.Error() != want {
		t.Errorf("Error = %q, want %q", api.Error(), want)
	}
	grants.err = errTestNoGrant
	if _, err := c.Stream(ctx, testCaller, testTarget, Request{}); !errors.Is(err, errTestNoGrant) {
		t.Errorf("a grant error: %v", err)
	}
}

func TestAPIError_Flags(t *testing.T) {
	tests := []struct {
		status                    int
		refused, noRoute, retried bool
	}{
		{http.StatusUnauthorized, true, false, false},
		{http.StatusForbidden, true, false, false},
		{http.StatusNotFound, false, true, true},
		{http.StatusBadGateway, false, false, true},
		{http.StatusBadRequest, false, false, false},
	}
	for _, tt := range tests {
		e := &APIError{Status: tt.status}
		if e.Refused() != tt.refused || e.NoRoute() != tt.noRoute || e.Retryable() != tt.retried {
			t.Errorf("status %d: refused %v, no route %v, retryable %v", tt.status, e.Refused(), e.NoRoute(), e.Retryable())
		}
	}
}

func TestResponseFailure_Error(t *testing.T) {
	got := (&ResponseFailure{Code: "c", Message: "m"}).Error()
	if got != "the model reported a failure (c): m" {
		t.Errorf("Error = %q", got)
	}
}

func TestSend_TransportFailure(t *testing.T) {
	c, _ := gateway(t, func(http.ResponseWriter, *http.Request, []byte) {})
	c.http = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})}

	_, err := c.Respond(context.Background(), testCaller, testTarget, Request{})

	if err == nil || !strings.Contains(err.Error(), "send to the gateway") {
		t.Errorf("error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRespond_BadReplies(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"not JSON", "{", "decode the reply"},
		{"too large", strings.Repeat(" ", maxResponseBytes+1), "larger than the gateway buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				_, _ = io.WriteString(w, tt.body)
			})
			_, err := c.Respond(context.Background(), testCaller, testTarget, Request{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want text %q", err, tt.want)
			}
		})
	}
}

func TestEmbeddings_BadReplies(t *testing.T) {
	caller := Caller{Tenant: "acme", Purpose: modelcall.PurposeEmbedding}
	target := Target{Tenant: "acme", Provider: "oa"}
	tests := []struct {
		name string
		body string
		want string
	}{
		{"not JSON", "{", "decode the reply"},
		{"too large", strings.Repeat(" ", maxResponseBytes+1), "larger than the gateway buffer"},
		{"index out of range", `{"data":[{"index":3,"embedding":[1]}]}`, "bad vector index 3"},
		{"negative index", `{"data":[{"index":-1,"embedding":[1]}]}`, "bad vector index -1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				_, _ = io.WriteString(w, tt.body)
			})
			_, err := c.Embeddings(context.Background(), caller, target, "m", []string{"a"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want text %q", err, tt.want)
			}
		})
	}

	c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		_, _ = io.WriteString(w, `{"data":[{"index":0,"embedding":[1]},{"index":0,"embedding":[2]}]}`)
	})
	if _, err := c.Embeddings(context.Background(), caller, target, "m", []string{"a", "b"}); err == nil ||
		!strings.Contains(err.Error(), "bad vector index 0") {
		t.Errorf("a repeated index: error = %v", err)
	}

	refusing, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
		w.WriteHeader(http.StatusForbidden)
	})
	var api *APIError
	if _, err := refusing.Embeddings(context.Background(), caller, target, "m", []string{"a"}); !errors.As(err, &api) ||
		!api.Refused() {
		t.Errorf("a refusal: error = %v", err)
	}
	if _, err := refusing.Embeddings(context.Background(), caller, Target{Tenant: "acme"}, "m", nil); err == nil {
		t.Error("a target with no provider was accepted")
	}
}

func TestModels_BadReplies(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"not JSON", "{", "decode the model list"},
		{"too large", strings.Repeat(" ", maxResponseBytes+1), "larger than the gateway buffer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gateway(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				_, _ = io.WriteString(w, tt.body)
			})
			_, err := c.Models(context.Background(), testCaller, testTarget)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want text %q", err, tt.want)
			}
		})
	}
	c, _ := gateway(t, func(http.ResponseWriter, *http.Request, []byte) {})
	if _, err := c.Models(context.Background(), testCaller, Target{Tenant: "acme"}); err == nil {
		t.Error("a target with no provider was accepted")
	}
}

func TestMessageHelpers(t *testing.T) {
	tests := []struct {
		name string
		item Item
		want string
	}{
		{"system", SystemMessage("rule"),
			`{"type":"message","role":"system","content":[{"type":"input_text","text":"rule"}]}`},
		{"assistant", AssistantMessage("old"),
			`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"old"}]}`},
		{"function call", FunctionCall("c1", "scan", `{"a":1}`),
			`{"type":"function_call","call_id":"c1","name":"scan","arguments":"{\"a\":1}"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.item)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("JSON = %s\nwant   %s", got, tt.want)
			}
		})
	}
}

func TestItem_JSONKeepsTheExactBytesRead(t *testing.T) {
	const raw = `{"type":"function_call","call_id":"c","unknown_field":{"a":1}}`
	var it Item
	if err := json.Unmarshal([]byte(raw), &it); err != nil {
		t.Fatal(err)
	}
	if it.CallID != "c" || string(it.Raw) != raw {
		t.Fatalf("item = %+v", it)
	}
	out, err := json.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != raw {
		t.Errorf("Marshal = %s, want the bytes that were read", out)
	}
	if err := json.Unmarshal([]byte(`{"call_id":5}`), &it); err == nil {
		t.Error("a field of the wrong type was accepted")
	}
}

func TestResponse_OutputTextAndFunctionCalls(t *testing.T) {
	var r Response
	body := `{"output":[
		{"type":"message","content":[{"type":"output_text","text":"a"},{"type":"refusal","text":"no"},
			{"type":"output_text","text":"b"}]},
		{"type":"function_call","call_id":"c1","name":"f"},
		{"type":"reasoning"}]}`
	if err := json.Unmarshal([]byte(body), &r); err != nil {
		t.Fatal(err)
	}
	if got := r.OutputText(); got != "ab" {
		t.Errorf("OutputText = %q", got)
	}
	calls := r.FunctionCalls()
	if len(calls) != 1 || calls[0].CallID != "c1" {
		t.Errorf("FunctionCalls = %+v", calls)
	}
}
