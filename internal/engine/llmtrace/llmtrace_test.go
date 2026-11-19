// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llmtrace

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
)

// The files in testdata are the attributes of real spans. The fixture test
// tests/fixtures/mockprovider made them with agentgateway v1.7.0, the mock
// provider and a trace policy that adds the body and the trusted headers. Make
// them again with GATEWAY_SPAN_DUMP_DIR=<dir> and the agentgateway_fixture tag.
func loadSpan(t *testing.T, name string) Span {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("read span %s: %v", name, err)
	}
	var f struct {
		Attributes map[string]any `json:"attributes"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse span %s: %v", name, err)
	}
	return Span{Attributes: f.Attributes}
}

func mustObserve(t *testing.T, name string) Observation {
	t.Helper()
	o, err := FromSpan(loadSpan(t, name))
	if err != nil {
		t.Fatalf("FromSpan(%s): %v", name, err)
	}
	return o
}

func itemTypes(t *testing.T, items []json.RawMessage) []string {
	t.Helper()
	out := make([]string, 0, len(items))
	for _, it := range items {
		var h struct{ Type, Role string }
		if err := json.Unmarshal(it, &h); err != nil {
			t.Fatalf("item is not JSON: %s", it)
		}
		out = append(out, h.Type+":"+h.Role)
	}
	return out
}

// A call with a prior tool call and a tool result gives one event with all items.
func TestFromSpan_MessagesCallHoldsAllItems(t *testing.T) {
	o := mustObserve(t, "messages_plain")
	want := []string{
		"message:user",          // the request
		"function_call:",        // the prior tool call
		"function_call_output:", // the tool result
		"reasoning:",            // the reply: thinking
		"message:assistant",     // the reply: text
		"function_call:",        // the reply: tool call
	}
	got := itemTypes(t, o.Items)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("items = %v, want %v", got, want)
	}
	all := string(mustJoin(o.Items))
	for _, s := range []string{"open ports: 22/tcp ssh, 80/tcp http", "I must scan the host first.", "I will run a port scan.", `"call_id":"toolu_2"`} {
		if !strings.Contains(all, s) {
			t.Errorf("items lack %q", s)
		}
	}
	if o.Provider != "anthropic" || o.Model != "claude-sonnet-5-5" || o.Format != FormatAnthropicMessages {
		t.Errorf("provider/model/format = %q %q %q", o.Provider, o.Model, o.Format)
	}
	if o.InputTokens != 120 || o.OutputTokens != 45 {
		t.Errorf("tokens = %d in, %d out, want 120 and 45", o.InputTokens, o.OutputTokens)
	}
	if o.Tenant != "tenant-a" || o.Subject != "user-from-authz" {
		t.Errorf("trusted values = %q %q, want tenant-a and user-from-authz", o.Tenant, o.Subject)
	}
}

func mustJoin(items []json.RawMessage) []byte {
	var b []byte
	for _, it := range items {
		b = append(b, it...)
		b = append(b, '\n')
	}
	return b
}

// A streamed call gives the same items as the same call with no stream. The
// request holds a marker that differs, so the test compares the reply items.
func TestFromSpan_StreamGivesTheItemsOfThePlainCall(t *testing.T) {
	for _, tc := range []struct{ plain, stream string }{
		{"messages_plain", "messages_stream"},
		{"responses_plain", "responses_stream"},
	} {
		t.Run(tc.stream, func(t *testing.T) {
			p, s := mustObserve(t, tc.plain), mustObserve(t, tc.stream)
			if p.Streamed || !s.Streamed {
				t.Fatalf("streamed = %v and %v, want false and true", p.Streamed, s.Streamed)
			}
			if len(p.Items) != len(s.Items) {
				t.Fatalf("items = %d plain, %d stream", len(p.Items), len(s.Items))
			}
			// The request items hold the marker. The reply items are the tail.
			const requestItems = 3
			for i := requestItems; i < len(p.Items); i++ {
				if string(p.Items[i]) != string(s.Items[i]) {
					t.Errorf("reply item %d differs:\n plain  %s\n stream %s", i, p.Items[i], s.Items[i])
				}
			}
			if p.InputTokens != s.InputTokens || p.OutputTokens != s.OutputTokens {
				t.Errorf("tokens differ: %d/%d and %d/%d", p.InputTokens, p.OutputTokens, s.InputTokens, s.OutputTokens)
			}
		})
	}
}

func TestFromSpan_OpenResponsesCall(t *testing.T) {
	o := mustObserve(t, "responses_plain")
	got := itemTypes(t, o.Items)
	want := []string{"message:user", "function_call:", "function_call_output:", "reasoning:", "message:assistant", "function_call:"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("items = %v, want %v", got, want)
	}
	if o.Format != FormatOpenResponses || o.Provider != "openai" {
		t.Errorf("format/provider = %q %q", o.Format, o.Provider)
	}
}

// A priced model gives the cost of the gateway. An unpriced model gives
// "unknown", and never zero.
func TestFromSpan_CostIsUnknownForAnUnpricedModel(t *testing.T) {
	priced := mustObserve(t, "messages_plain")
	if !priced.Cost.Known || priced.Cost.Total != "0.00069" {
		t.Errorf("priced cost = %+v, want 0.00069", priced.Cost)
	}
	unpriced := mustObserve(t, "responses_plain")
	if unpriced.Cost.Known || unpriced.Cost.Total != "" {
		t.Errorf("unpriced cost = %+v, want unknown", unpriced.Cost)
	}
	ev := unpriced.Events(time.Unix(1, 0))[0].(brain.LlmCallObserved)
	if ev.Cost != "" {
		t.Errorf("event cost of an unpriced model = %q, want empty (unknown), never 0", ev.Cost)
	}
	if got := priced.Events(time.Unix(1, 0))[0].(brain.LlmCallObserved).Cost; got != "0.00069" {
		t.Errorf("event cost = %q, want 0.00069", got)
	}
}

// The events fold in the World and keep the items, the counts and the cost.
func TestEvents_FoldIntoTheWorld(t *testing.T) {
	o := mustObserve(t, "messages_plain")
	o.Mission = "m1" // the fixture span has no mission, as the fake authz sets none
	w := brain.NewWorld("tenant-a")
	brain.Reduce(w, brain.MissionStarted{ID: "m1", RunID: "r1"})
	events := o.Events(time.Unix(100, 0))
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2", len(events))
	}
	for _, ev := range events {
		brain.Reduce(w, ev)
		// Each event survives the Timeline codec.
		b, err := brain.EncodeEvent(ev)
		if err != nil {
			t.Fatalf("encode %T: %v", ev, err)
		}
		if _, err := brain.DecodeEvent(b); err != nil {
			t.Fatalf("decode %T: %v", ev, err)
		}
	}
	calls := w.LlmCallSnapshot()
	if len(calls) != 1 || len(calls[0].Items) != 6 || calls[0].Cost != "0.00069" || calls[0].Provider != "anthropic" {
		t.Fatalf("folded call = %+v", calls)
	}
	// Folding the call event again changes nothing. The token event is not
	// idempotent: the receiver must not deliver one span two times.
	brain.Reduce(w, events[0])
	if len(w.LlmCallSnapshot()) != 1 {
		t.Error("a second fold of the same span made a second call")
	}
	for _, m := range w.MissionSnapshot() {
		if m.TokensUsed != 165 {
			t.Errorf("mission tokens = %d, want 165 (counted by the first fold of each event)", m.TokensUsed)
		}
	}
}

func TestEvents_NoMissionGivesNoTokenEvent(t *testing.T) {
	o := mustObserve(t, "messages_plain")
	o.Mission = ""
	if got := len(o.Events(time.Now())); got != 1 {
		t.Errorf("events = %d, want only the call event", got)
	}
}

func TestFromSpan_Refusals(t *testing.T) {
	cases := map[string]Span{
		"another path":    {Attributes: map[string]any{"url.path": "/health", AttrRequestBody: "{}"}},
		"no request body": {Attributes: map[string]any{"url.path": "/v1/responses"}},
		"invalid body":    {Attributes: map[string]any{"url.path": "/v1/responses", AttrRequestBody: "not json"}},
	}
	for name, sp := range cases {
		if _, err := FromSpan(sp); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	_, err := FromSpan(cases["another path"])
	if !errors.Is(err, ErrNotAModelCall) {
		t.Errorf("another path: error %v is not ErrNotAModelCall", err)
	}
}

func TestFoldStream_Refusals(t *testing.T) {
	if _, err := FoldStream(FormatOpenResponses, ""); !errors.Is(err, ErrNoStreamEvents) {
		t.Errorf("empty body: %v, want ErrNoStreamEvents", err)
	}
	if _, err := FoldStream("nope", "event: x\ndata: {}\n\n"); err == nil {
		t.Error("an unknown format gave no error")
	}
	if _, err := FoldStream(FormatAnthropicMessages, "event: message_start\ndata: {bad\n\n"); err == nil {
		t.Error("a bad event gave no error")
	}
}

// A Responses stream with no response.completed event is rebuilt from the item
// events and the deltas.
func TestFoldStream_ResponsesWithoutACompletedEvent(t *testing.T) {
	body := "event: response.output_item.added\n" +
		`data: {"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":""}]}}` + "\n\n" +
		"event: response.output_text.delta\n" +
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"he"}` + "\n\n" +
		"event: response.output_text.delta\n" +
		`data: {"type":"response.output_text.delta","output_index":0,"delta":"llo"}` + "\n\n"
	raw, err := FoldStream(FormatOpenResponses, body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"text":"hello"`) {
		t.Errorf("folded reply = %s, want the text hello", raw)
	}
}

// messages_denied is a real span of agentgateway v1.7.0: the authorization
// service refused the model, and the gateway answered 403 with no body.
func TestFromSpan_ARefusedCallIsARecordWithItsStatus(t *testing.T) {
	o := mustObserve(t, "messages_denied")
	if !o.Failed() || o.HTTPStatus != 403 {
		t.Fatalf("status = %d, failed = %v, want 403 and true", o.HTTPStatus, o.Failed())
	}
	if got := itemTypes(t, o.Items); len(got) != 3 {
		t.Fatalf("items = %v, want the three request items", got)
	}
	if o.InputTokens != 0 || o.OutputTokens != 0 {
		t.Errorf("tokens = %d and %d, want zero", o.InputTokens, o.OutputTokens)
	}
}

// A hand made span: the gateway answers a failed call with a plain text body.
// The body is not JSON, and the call still gives its record. The span is the
// real span messages_denied with the status and the body that the cluster test
// of 2026-11-19 logged ("route not found", 404, and "connection timed out", 503).
func TestFromSpan_AFailedCallWithATextBodyIsNotDropped(t *testing.T) {
	for _, tc := range []struct {
		status int64
		body   string
	}{{404, "route not found"}, {503, "connection timed out"}} {
		sp := loadSpan(t, "messages_denied")
		sp.Attributes["http.response.status_code"] = tc.status
		sp.Attributes["gibson.response_body"] = tc.body
		sp.Attributes["gen_ai.usage.input_tokens"] = int64(7) // a failed call holds no tokens
		o, err := FromSpan(sp)
		if err != nil {
			t.Fatalf("status %d: FromSpan: %v", tc.status, err)
		}
		if o.HTTPStatus != int(tc.status) || o.Failure != tc.body || o.InputTokens != 0 {
			t.Errorf("observation = %+v", o)
		}
		events := o.Events(time.Unix(1, 0))
		if len(events) != 1 {
			t.Fatalf("events = %d, want the call event only: a failed call adds no usage", len(events))
		}
		ev, ok := events[0].(brain.LlmCallObserved)
		if !ok || ev.HTTPStatus != int(tc.status) || ev.Completion != tc.body || ev.PromptTokens != 0 || len(ev.Items) != 3 {
			t.Errorf("event = %+v", events[0])
		}
	}
}
