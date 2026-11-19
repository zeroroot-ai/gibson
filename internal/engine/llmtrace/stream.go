// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llmtrace

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Format names the wire format of a model call body.
type Format string

const (
	// FormatAnthropicMessages is the Anthropic Messages format (POST /v1/messages).
	FormatAnthropicMessages Format = "anthropic_messages"
	// FormatOpenResponses is the Open Responses format (POST /v1/responses).
	FormatOpenResponses Format = "open_responses"
)

// ErrNoStreamEvents means that a stream body holds no event.
var ErrNoStreamEvents = errors.New("llmtrace: the stream body holds no event")

// sseEvent is one server-sent event: its name and its data lines joined.
type sseEvent struct {
	name string
	data string
}

// parseSSE splits the text of a stream into events. The gateway records the raw
// text of the stream in response.body.
func parseSSE(body string) []sseEvent {
	var out []sseEvent
	var cur sseEvent
	var data []string
	flush := func() {
		if len(data) > 0 || cur.name != "" {
			cur.data = strings.Join(data, "\n")
			out = append(out, cur)
		}
		cur, data = sseEvent{}, nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, ":"):
			// A comment line.
		case strings.HasPrefix(line, "event:"):
			cur.name = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	flush()
	return out
}

// IsStreamBody reports whether a response body is the text of a stream.
func IsStreamBody(body string) bool {
	t := strings.TrimLeft(body, " \r\n\t")
	return strings.HasPrefix(t, "event:") || strings.HasPrefix(t, "data:")
}

// FoldStream folds the text of a stream into the one reply that the same call
// would return without a stream. The reply is in the same format as the stream.
func FoldStream(format Format, body string) (json.RawMessage, error) {
	events := parseSSE(body)
	if len(events) == 0 {
		return nil, ErrNoStreamEvents
	}
	switch format {
	case FormatAnthropicMessages:
		return foldAnthropicStream(events)
	case FormatOpenResponses:
		return foldResponsesStream(events)
	default:
		return nil, fmt.Errorf("llmtrace: unknown format %q", format)
	}
}

// anthropicEvent is the data of one event of a Messages stream.
type anthropicEvent struct {
	Type         string         `json:"type"`
	Index        int            `json:"index"`
	Message      map[string]any `json:"message"`
	ContentBlock map[string]any `json:"content_block"`
	Delta        map[string]any `json:"delta"`
	Usage        map[string]any `json:"usage"`
}

// anthropicFold holds the parts of a Messages reply while the events arrive.
type anthropicFold struct {
	msg     map[string]any
	blocks  map[int]map[string]any
	partial map[int]*strings.Builder
	usage   map[string]any
}

// foldAnthropicStream rebuilds a Messages reply from message_start,
// content_block_start, content_block_delta, content_block_stop and
// message_delta events.
func foldAnthropicStream(events []sseEvent) (json.RawMessage, error) {
	f := &anthropicFold{
		msg:     map[string]any{},
		blocks:  map[int]map[string]any{},
		partial: map[int]*strings.Builder{},
		usage:   map[string]any{},
	}
	for _, ev := range events {
		if ev.data == "" || ev.data == "[DONE]" {
			continue
		}
		var d anthropicEvent
		if err := json.Unmarshal([]byte(ev.data), &d); err != nil {
			return nil, fmt.Errorf("llmtrace: decode stream event %q: %w", ev.name, err)
		}
		typ := d.Type
		if typ == "" {
			typ = ev.name
		}
		f.apply(typ, d)
	}
	return f.reply()
}

// apply adds one event to the reply.
func (f *anthropicFold) apply(typ string, d anthropicEvent) {
	switch typ {
	case "message_start":
		for k, v := range d.Message {
			if k != "content" && k != "usage" {
				f.msg[k] = v
			}
		}
		for k, v := range asMap(d.Message["usage"]) {
			f.usage[k] = v
		}
	case "content_block_start":
		f.blocks[d.Index] = d.ContentBlock
	case "content_block_delta":
		f.applyBlockDelta(d)
	case "message_delta":
		for k, v := range d.Delta {
			f.msg[k] = v
		}
		for k, v := range d.Usage {
			f.usage[k] = v
		}
	}
}

// applyBlockDelta adds the delta of a content block to the block.
func (f *anthropicFold) applyBlockDelta(d anthropicEvent) {
	b := f.blocks[d.Index]
	if b == nil {
		b = map[string]any{}
		f.blocks[d.Index] = b
	}
	switch d.Delta["type"] {
	case "text_delta":
		b["text"] = str(b["text"]) + str(d.Delta["text"])
	case "thinking_delta":
		b["thinking"] = str(b["thinking"]) + str(d.Delta["thinking"])
	case "signature_delta":
		b["signature"] = str(d.Delta["signature"])
	case "input_json_delta":
		if f.partial[d.Index] == nil {
			f.partial[d.Index] = &strings.Builder{}
		}
		f.partial[d.Index].WriteString(str(d.Delta["partial_json"]))
	}
}

// reply orders the blocks, decodes the tool input of each block, and encodes
// the whole reply.
func (f *anthropicFold) reply() (json.RawMessage, error) {
	idx := make([]int, 0, len(f.blocks))
	for i := range f.blocks {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	content := make([]any, 0, len(idx))
	for _, i := range idx {
		b := f.blocks[i]
		if p, ok := f.partial[i]; ok {
			var input any
			if err := json.Unmarshal([]byte(p.String()), &input); err != nil {
				return nil, fmt.Errorf("llmtrace: the tool input of block %d is not JSON: %w", i, err)
			}
			b["input"] = input
		}
		content = append(content, b)
	}
	f.msg["content"] = content
	f.msg["usage"] = f.usage
	out, err := json.Marshal(f.msg)
	if err != nil {
		return nil, fmt.Errorf("llmtrace: encode the folded reply: %w", err)
	}
	return out, nil
}

// responsesEvent is the data of one event of an Open Responses stream.
type responsesEvent struct {
	Type        string         `json:"type"`
	OutputIndex int            `json:"output_index"`
	Item        map[string]any `json:"item"`
	Delta       string         `json:"delta"`
	Arguments   string         `json:"arguments"`
	Response    map[string]any `json:"response"`
}

// responsesFold holds the parts of an Open Responses reply while the events
// arrive.
type responsesFold struct {
	items map[int]map[string]any
	base  map[string]any
	final map[string]any
}

// foldResponsesStream rebuilds an Open Responses reply. The response.completed
// event holds the whole response. Without it, the items come from the
// output_item events and the deltas.
func foldResponsesStream(events []sseEvent) (json.RawMessage, error) {
	f := &responsesFold{items: map[int]map[string]any{}}
	for _, ev := range events {
		if ev.data == "" || ev.data == "[DONE]" {
			continue
		}
		var d responsesEvent
		if err := json.Unmarshal([]byte(ev.data), &d); err != nil {
			return nil, fmt.Errorf("llmtrace: decode stream event %q: %w", ev.name, err)
		}
		typ := d.Type
		if typ == "" {
			typ = ev.name
		}
		f.apply(typ, d)
	}
	return f.reply()
}

// apply adds one event to the reply.
func (f *responsesFold) apply(typ string, d responsesEvent) {
	switch typ {
	case "response.created", "response.in_progress":
		f.base = d.Response
	case "response.output_item.added", "response.output_item.done":
		if d.Item != nil {
			f.items[d.OutputIndex] = d.Item
		}
	case "response.output_text.delta":
		it := f.items[d.OutputIndex]
		if it == nil {
			it = map[string]any{"type": "message", "role": "assistant"}
			f.items[d.OutputIndex] = it
		}
		appendText(it, d.Delta)
	case "response.function_call_arguments.delta":
		if it := f.items[d.OutputIndex]; it != nil {
			it["arguments"] = str(it["arguments"]) + d.Delta
		}
	case "response.completed", "response.incomplete", "response.failed":
		f.final = d.Response
	}
}

// reply picks the whole response, fills its output from the items when the
// response has none, and encodes it.
func (f *responsesFold) reply() (json.RawMessage, error) {
	resp := f.final
	if resp == nil {
		resp = f.base
	}
	if resp == nil {
		resp = map[string]any{"object": "response"}
	}
	if out, _ := resp["output"].([]any); len(out) == 0 && len(f.items) > 0 {
		idx := make([]int, 0, len(f.items))
		for i := range f.items {
			idx = append(idx, i)
		}
		sort.Ints(idx)
		list := make([]any, 0, len(idx))
		for _, i := range idx {
			list = append(list, f.items[i])
		}
		resp["output"] = list
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("llmtrace: encode the folded reply: %w", err)
	}
	return b, nil
}

// appendText adds text to the first output_text part of a message item.
func appendText(item map[string]any, text string) {
	parts, _ := item["content"].([]any)
	if len(parts) == 0 {
		parts = []any{map[string]any{"type": "output_text", "text": ""}}
	}
	if p, ok := parts[0].(map[string]any); ok {
		p["text"] = str(p["text"]) + text
	}
	item["content"] = parts
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// compact returns the JSON of v with sorted keys and no spaces.
func compact(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("llmtrace: encode JSON: %w", err)
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
