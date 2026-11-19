// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llmtrace

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// jsonItems returns each item as one string, to compare with a want list.
func jsonItems(items []json.RawMessage) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = string(it)
	}
	return out
}

func wantItems(t *testing.T, got []json.RawMessage, want ...string) {
	t.Helper()
	g := jsonItems(got)
	if len(g) != len(want) {
		t.Fatalf("got %d items, want %d: %v", len(g), len(want), g)
	}
	for i := range want {
		if g[i] != want[i] {
			t.Errorf("item %d = %s\nwant      %s", i, g[i], want[i])
		}
	}
}

func TestRequestItems_OpenResponses(t *testing.T) {
	body := `{
		"instructions": "be brief",
		"input": [
			{"role": "user", "content": "hello"},
			{"role": "assistant", "content": "hi"},
			{"type": "function_call", "call_id": "c1", "name": "f", "arguments": {"b": 2, "a": 1}},
			{"type": "function_call", "call_id": "c2", "name": "g", "arguments": "{\"z\":1,\"y\":null}"},
			{"type": "function_call", "call_id": "c3", "name": "h", "arguments": "not json"},
			{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "x"}], "extra": null}
		]
	}`

	got, err := requestItems(FormatOpenResponses, body)

	if err != nil {
		t.Fatal(err)
	}
	wantItems(t, got,
		`{"content":[{"text":"be brief","type":"input_text"}],"role":"system","type":"message"}`,
		`{"content":[{"text":"hello","type":"input_text"}],"role":"user","type":"message"}`,
		`{"content":[{"text":"hi","type":"output_text"}],"role":"assistant","type":"message"}`,
		`{"arguments":"{\"a\":1,\"b\":2}","call_id":"c1","name":"f","type":"function_call"}`,
		`{"arguments":"{\"y\":null,\"z\":1}","call_id":"c2","name":"g","type":"function_call"}`,
		`{"arguments":"not json","call_id":"c3","name":"h","type":"function_call"}`,
		`{"content":[{"text":"x","type":"input_text"}],"role":"user","type":"message"}`,
	)
}

func TestRequestItems_OpenResponsesStringInput(t *testing.T) {
	got, err := requestItems(FormatOpenResponses, `{"input": "hello"}`)
	if err != nil {
		t.Fatal(err)
	}
	wantItems(t, got, `{"content":[{"text":"hello","type":"input_text"}],"role":"user","type":"message"}`)
}

func TestRequestItems_Messages(t *testing.T) {
	body := `{
		"system": [{"type": "text", "text": "rule one"}, {"type": "text", "text": ""}],
		"messages": [
			{"role": "user", "content": "question"},
			{"role": "assistant", "content": "answer"},
			{"role": "assistant", "content": [
				{"type": "thinking", "thinking": "hmm"},
				{"type": "text", "text": "calling"},
				{"type": "tool_use", "id": "t1", "name": "scan", "input": {"b": 1, "a": 2}}
			]},
			{"role": "user", "content": [
				{"type": "tool_result", "tool_use_id": "t1", "content": "plain"},
				{"type": "tool_result", "tool_use_id": "t2",
					"content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]},
				{"type": "tool_result", "tool_use_id": "t3"},
				{"type": "tool_result", "tool_use_id": "t4", "content": {"k": 1}},
				{"type": "unknown"}
			]}
		]
	}`

	got, err := requestItems(FormatAnthropicMessages, body)

	if err != nil {
		t.Fatal(err)
	}
	wantItems(t, got,
		`{"content":[{"text":"rule one","type":"input_text"}],"role":"system","type":"message"}`,
		`{"content":[{"text":"question","type":"input_text"}],"role":"user","type":"message"}`,
		`{"content":[{"text":"answer","type":"output_text"}],"role":"assistant","type":"message"}`,
		`{"summary":[{"text":"hmm","type":"summary_text"}],"type":"reasoning"}`,
		`{"content":[{"text":"calling","type":"output_text"}],"role":"assistant","type":"message"}`,
		`{"arguments":"{\"a\":2,\"b\":1}","call_id":"t1","name":"scan","type":"function_call"}`,
		`{"call_id":"t1","output":"plain","type":"function_call_output"}`,
		`{"call_id":"t2","output":"ab","type":"function_call_output"}`,
		`{"call_id":"t3","output":"","type":"function_call_output"}`,
		`{"call_id":"t4","output":"{\"k\":1}","type":"function_call_output"}`,
	)
}

func TestRequestItems_MessagesStringSystemAndEmptySystem(t *testing.T) {
	got, err := requestItems(FormatAnthropicMessages, `{"system": "rule", "messages": []}`)
	if err != nil {
		t.Fatal(err)
	}
	wantItems(t, got, `{"content":[{"text":"rule","type":"input_text"}],"role":"system","type":"message"}`)

	got, err = requestItems(FormatAnthropicMessages, `{"system": ""}`)
	if err != nil {
		t.Fatal(err)
	}
	wantItems(t, got)
}

func TestResponseItems(t *testing.T) {
	got, err := responseItems(FormatOpenResponses,
		`{"output": [{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "ok"}]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	wantItems(t, got, `{"content":[{"text":"ok","type":"output_text"}],"role":"assistant","type":"message"}`)

	got, err = responseItems(FormatAnthropicMessages, `{"content": [{"type": "text", "text": "ok"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	wantItems(t, got, `{"content":[{"text":"ok","type":"output_text"}],"role":"assistant","type":"message"}`)
}

func TestItems_Refusals(t *testing.T) {
	for name, fn := range map[string]func(Format, string) ([]json.RawMessage, error){
		"request": requestItems, "response": responseItems,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fn(FormatOpenResponses, "{"); err == nil || !strings.Contains(err.Error(), "decode a call body") {
				t.Errorf("a body that is not JSON: error = %v", err)
			}
			if _, err := fn("other", "{}"); err == nil || !strings.Contains(err.Error(), `unknown format "other"`) {
				t.Errorf("an unknown format: error = %v", err)
			}
		})
	}
}

func TestRequestItems_MessagesBlockError(t *testing.T) {
	// A tool_result whose content cannot encode fails the whole call.
	_, err := blocksToAnyItems("user", []any{
		map[string]any{"type": "tool_result", "tool_use_id": "t", "content": map[string]any{"c": make(chan int)}},
	})
	if err == nil || !strings.Contains(err.Error(), "encode JSON") {
		t.Errorf("tool_result: error = %v", err)
	}
	_, err = blocksToAnyItems("assistant", []any{
		map[string]any{"type": "tool_use", "id": "t", "input": make(chan int)},
	})
	if err == nil || !strings.Contains(err.Error(), "encode JSON") {
		t.Errorf("tool_use: error = %v", err)
	}
	if _, err = blocksToItems("assistant", []any{
		map[string]any{"type": "tool_use", "id": "t", "input": make(chan int)},
	}); err == nil {
		t.Error("blocksToItems must return the block error")
	}
}

func TestNormalizeAll_Errors(t *testing.T) {
	bad := map[string]any{"c": make(chan int)}
	_, err := normalizeAll([]any{map[string]any{"type": "function_call", "arguments": bad}})
	if err == nil {
		t.Error("arguments that cannot encode must fail")
	}
	_, err = normalizeAll([]any{map[string]any{"type": "message", "x": make(chan int)}})
	if err == nil {
		t.Error("an item that cannot encode must fail")
	}
	got, err := normalizeAll([]any{"a text item"})
	if err != nil {
		t.Fatal(err)
	}
	wantItems(t, got, `"a text item"`)
}

func TestMessagesInput_BlockErrorFromAMessage(t *testing.T) {
	_, err := messagesInputItems(map[string]any{
		"messages": []any{map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "tool_result", "content": map[string]any{"c": make(chan int)}},
		}}},
	})
	if err == nil {
		t.Error("a block that cannot encode must fail the call")
	}
}

func TestToolResultText_UnencodableValue(t *testing.T) {
	if _, err := toolResultText(make(chan int)); err == nil {
		t.Error("a value that cannot encode must fail")
	}
}

func TestCompact_SortsKeysAndKeepsHTML(t *testing.T) {
	got, err := compact(map[string]any{"b": "<x>", "a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":1,"b":"<x>"}` {
		t.Errorf("compact = %s", got)
	}
	if _, err := compact(make(chan int)); err == nil {
		t.Error("compact of a channel must fail")
	}
}

func TestNormalizeJSONText(t *testing.T) {
	tests := map[string]string{
		`{"b":1, "a":2}`:       `{"a":2,"b":1}`,
		`not json`:             `not json`,
		`12345678901234567890`: `12345678901234567890`,
	}
	for in, want := range tests {
		if got := normalizeJSONText(in); got != want {
			t.Errorf("normalizeJSONText(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImplicitMessage_LeavesTypedAndRolelessItemsAlone(t *testing.T) {
	typed := map[string]any{"type": "function_call", "role": "x"}
	implicitMessage(typed)
	if typed["type"] != "function_call" {
		t.Error("a typed item changed")
	}
	bare := map[string]any{"content": "x"}
	implicitMessage(bare)
	if _, ok := bare["type"]; ok {
		t.Error("an item with no role got a type")
	}
}

func TestDropNulls(t *testing.T) {
	got := dropNulls(map[string]any{
		"a": nil, "b": []any{map[string]any{"c": nil, "d": 1}, nil}, "e": "s",
	})
	b, err := compact(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"b":[{"d":1},null],"e":"s"}` {
		t.Errorf("dropNulls = %s", b)
	}
}

func TestAttrInt(t *testing.T) {
	a := map[string]any{
		"i64": int64(1), "int": 2, "float": 3.9, "str": " 4 ", "badstr": "x", "other": true,
	}
	want := map[string]int64{"i64": 1, "int": 2, "float": 3, "str": 4, "badstr": 0, "other": 0, "absent": 0}
	for k, w := range want {
		if got := attrInt(a, k); got != w {
			t.Errorf("attrInt(%s) = %d, want %d", k, got, w)
		}
	}
}

func TestTruncateText(t *testing.T) {
	if got := truncateText("abc", 3); got != "abc" {
		t.Errorf("a text at the limit changed: %q", got)
	}
	// "é" has two bytes. A cut in the middle of it drops the broken rune.
	if got := truncateText("aé", 2); got != "a" {
		t.Errorf("truncateText cut inside a rune: %q", got)
	}
	if got := truncateText("abcdef", 4); got != "abcd" {
		t.Errorf("truncateText = %q", got)
	}
}

func TestFoldStream_AnthropicBlocksAndUsage(t *testing.T) {
	body := strings.Join([]string{
		": a comment",
		"event: message_start",
		`data: {"type":"message_start","message":{"id":"m1","role":"assistant","content":[],"usage":{"input_tokens":5}}}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hm"}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"signature_delta","signature":"sig"}}`,
		"",
		// No content_block_start for index 1: the fold makes the block.
		"event: content_block_delta",
		`data: {"index":1,"delta":{"type":"text_delta","text":"he"}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"llo"}}`,
		"",
		"event: content_block_start",
		`data: {"type":"content_block_start","index":2,"content_block":{"type":"tool_use","id":"t","name":"scan"}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"{\"a\":"}}`,
		"",
		"event: content_block_delta",
		`data: {"type":"content_block_delta","index":2,"delta":{"type":"input_json_delta","partial_json":"1}"}}`,
		"",
		"event: message_delta",
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":9}}`,
		"",
		"data: [DONE]",
		"",
	}, "\r\n")

	raw, err := FoldStream(FormatAnthropicMessages, body)

	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ID         string           `json:"id"`
		StopReason string           `json:"stop_reason"`
		Usage      map[string]any   `json:"usage"`
		Content    []map[string]any `json:"content"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "m1" || got.StopReason != "tool_use" {
		t.Errorf("message = %+v", got)
	}
	if got.Usage["input_tokens"] != float64(5) || got.Usage["output_tokens"] != float64(9) {
		t.Errorf("usage = %v", got.Usage)
	}
	if len(got.Content) != 3 {
		t.Fatalf("content = %v", got.Content)
	}
	if got.Content[0]["thinking"] != "hm" || got.Content[0]["signature"] != "sig" {
		t.Errorf("thinking block = %v", got.Content[0])
	}
	if got.Content[1]["text"] != "hello" {
		t.Errorf("text block = %v", got.Content[1])
	}
	if in, _ := got.Content[2]["input"].(map[string]any); in["a"] != float64(1) {
		t.Errorf("tool block = %v", got.Content[2])
	}
}

func TestFoldStream_AnthropicRefusals(t *testing.T) {
	_, err := FoldStream(FormatAnthropicMessages, "event: x\ndata: {\n")
	if err == nil || !strings.Contains(err.Error(), `decode stream event "x"`) {
		t.Errorf("a bad event: error = %v", err)
	}
	_, err = FoldStream(FormatAnthropicMessages,
		`data: {"type":"content_block_delta","index":0,`+
			`"delta":{"type":"input_json_delta","partial_json":"{"}}`+"\n")
	if err == nil || !strings.Contains(err.Error(), "not JSON") {
		t.Errorf("a tool input that is not JSON: error = %v", err)
	}
}

func TestFoldStream_ResponsesEvents(t *testing.T) {
	body := strings.Join([]string{
		"event: response.created",
		`data: {"response":{"id":"r1","object":"response"}}`,
		"",
		"event: response.output_item.added",
		`data: {"type":"response.output_item.added","output_index":0,` +
			`"item":{"type":"function_call","call_id":"c","name":"f","arguments":""}}`,
		"",
		"event: response.function_call_arguments.delta",
		`data: {"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"a\":"}`,
		"",
		"event: response.function_call_arguments.delta",
		`data: {"type":"response.function_call_arguments.delta","output_index":0,"delta":"1}"}`,
		"",
		"event: response.function_call_arguments.delta",
		`data: {"type":"response.function_call_arguments.delta","output_index":5,"delta":"lost"}`,
		"",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":1,"delta":"hel"}`,
		"",
		"event: response.output_text.delta",
		`data: {"type":"response.output_text.delta","output_index":1,"delta":"lo"}`,
		"",
		"event: response.output_item.added",
		`data: {"type":"response.output_item.added","output_index":2}`,
		"",
	}, "\n")

	raw, err := FoldStream(FormatOpenResponses, body)

	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ID     string           `json:"id"`
		Output []map[string]any `json:"output"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "r1" || len(got.Output) != 2 {
		t.Fatalf("reply = %s", raw)
	}
	if got.Output[0]["arguments"] != `{"a":1}` {
		t.Errorf("function call = %v", got.Output[0])
	}
	parts, _ := got.Output[1]["content"].([]any)
	if len(parts) != 1 || asMap(parts[0])["text"] != "hello" {
		t.Errorf("message = %v", got.Output[1])
	}
}

func TestFoldStream_ResponsesNoResponseAtAll(t *testing.T) {
	raw, err := FoldStream(FormatOpenResponses, "event: ping\ndata: {\"type\":\"ping\"}\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"object":"response"}` {
		t.Errorf("reply = %s", raw)
	}
	_, err = FoldStream(FormatOpenResponses, "event: x\ndata: {\n")
	if err == nil || !strings.Contains(err.Error(), "decode stream event") {
		t.Errorf("a bad event: error = %v", err)
	}
}

func TestAppendText_KeepsAnExistingPart(t *testing.T) {
	item := map[string]any{"content": []any{map[string]any{"type": "output_text", "text": "a"}}}
	appendText(item, "b")
	if asMap(item["content"].([]any)[0])["text"] != "ab" {
		t.Errorf("item = %v", item)
	}
	odd := map[string]any{"content": []any{"not a map"}}
	appendText(odd, "b")
	if odd["content"].([]any)[0] != "not a map" {
		t.Errorf("a part that is not an object changed: %v", odd)
	}
}

func TestFoldStream_UnknownFormatAndNoEvents(t *testing.T) {
	if _, err := FoldStream("other", "data: {}\n"); err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error = %v", err)
	}
	if _, err := FoldStream(FormatOpenResponses, "\n\n"); !errors.Is(err, ErrNoStreamEvents) {
		t.Errorf("error = %v, want ErrNoStreamEvents", err)
	}
}
