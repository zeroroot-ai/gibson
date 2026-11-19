// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package llmtrace

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Open Responses item types that this package writes (ADR-0173).
const (
	itemMessage            = "message"
	itemReasoning          = "reasoning"
	itemFunctionCall       = "function_call"
	itemFunctionCallOutput = "function_call_output"
)

// decodeObject decodes a JSON object and keeps numbers exact.
func decodeObject(raw string) (map[string]any, error) {
	var m map[string]any
	dec := json.NewDecoder(stringsReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("llmtrace: decode a call body: %w", err)
	}
	return m, nil
}

// requestItems returns the input of a call as Open Responses items.
func requestItems(format Format, body string) ([]json.RawMessage, error) {
	req, err := decodeObject(body)
	if err != nil {
		return nil, err
	}
	switch format {
	case FormatOpenResponses:
		return responsesInputItems(req)
	case FormatAnthropicMessages:
		return messagesInputItems(req)
	}
	return nil, fmt.Errorf("llmtrace: unknown format %q", format)
}

// responseItems returns the reply of a call as Open Responses items.
func responseItems(format Format, body string) ([]json.RawMessage, error) {
	resp, err := decodeObject(body)
	if err != nil {
		return nil, err
	}
	switch format {
	case FormatOpenResponses:
		out, _ := resp["output"].([]any)
		return normalizeAll(out)
	case FormatAnthropicMessages:
		blocks, _ := resp["content"].([]any)
		return blocksToItems("assistant", blocks)
	}
	return nil, fmt.Errorf("llmtrace: unknown format %q", format)
}

func responsesInputItems(req map[string]any) ([]json.RawMessage, error) {
	var items []any
	if instr := str(req["instructions"]); instr != "" {
		items = append(items, textMessage("system", "input_text", instr))
	}
	switch in := req["input"].(type) {
	case string:
		items = append(items, textMessage("user", "input_text", in))
	case []any:
		items = append(items, in...)
	}
	return normalizeAll(items)
}

func messagesInputItems(req map[string]any) ([]json.RawMessage, error) {
	var items []any
	switch sys := req["system"].(type) {
	case string:
		if sys != "" {
			items = append(items, textMessage("system", "input_text", sys))
		}
	case []any:
		for _, b := range sys {
			if t := str(asMap(b)["text"]); t != "" {
				items = append(items, textMessage("system", "input_text", t))
			}
		}
	}
	msgs, _ := req["messages"].([]any)
	for _, m := range msgs {
		mm := asMap(m)
		role := str(mm["role"])
		switch c := mm["content"].(type) {
		case string:
			kind := "input_text"
			if role == "assistant" {
				kind = "output_text"
			}
			items = append(items, textMessage(role, kind, c))
		case []any:
			conv, err := blocksToAnyItems(role, c)
			if err != nil {
				return nil, err
			}
			items = append(items, conv...)
		}
	}
	return normalizeAll(items)
}

func textMessage(role, partType, text string) map[string]any {
	return map[string]any{
		"type": itemMessage, "role": role,
		"content": []any{map[string]any{"type": partType, "text": text}},
	}
}

func blocksToItems(role string, blocks []any) ([]json.RawMessage, error) {
	items, err := blocksToAnyItems(role, blocks)
	if err != nil {
		return nil, err
	}
	return normalizeAll(items)
}

// blocksToAnyItems converts Anthropic content blocks to Open Responses items.
// A text block becomes a message item. A thinking block becomes a reasoning
// item. A tool_use block becomes a function_call item. A tool_result block
// becomes a function_call_output item.
func blocksToAnyItems(role string, blocks []any) ([]any, error) {
	partType := "input_text"
	if role == "assistant" {
		partType = "output_text"
	}
	var items []any
	for _, b := range blocks {
		blk := asMap(b)
		switch str(blk["type"]) {
		case "text":
			items = append(items, textMessage(role, partType, str(blk["text"])))
		case "thinking":
			items = append(items, map[string]any{
				"type": itemReasoning,
				"summary": []any{map[string]any{
					"type": "summary_text", "text": str(blk["thinking"]),
				}},
			})
		case "tool_use":
			args, err := compact(blk["input"])
			if err != nil {
				return nil, err
			}
			items = append(items, map[string]any{
				"type": itemFunctionCall, "call_id": str(blk["id"]),
				"name": str(blk["name"]), "arguments": string(args),
			})
		case "tool_result":
			out, err := toolResultText(blk["content"])
			if err != nil {
				return nil, err
			}
			items = append(items, map[string]any{
				"type": itemFunctionCallOutput, "call_id": str(blk["tool_use_id"]), "output": out,
			})
		}
	}
	return items, nil
}

// toolResultText returns the text of a tool_result content: a string, or the
// text blocks joined.
func toolResultText(v any) (string, error) {
	switch c := v.(type) {
	case string:
		return c, nil
	case []any:
		var out strings.Builder
		for _, b := range c {
			out.WriteString(str(asMap(b)["text"]))
		}
		return out.String(), nil
	case nil:
		return "", nil
	}
	raw, err := compact(v)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// normalizeAll re-encodes each item with sorted keys, so that two equal items
// have equal bytes.
func normalizeAll(items []any) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(items))
	for _, it := range items {
		if m, ok := it.(map[string]any); ok {
			implicitMessage(m)
			if args, isMap := m["arguments"].(map[string]any); isMap {
				// Some providers send the arguments as an object. The item holds a string.
				raw, err := compact(args)
				if err != nil {
					return nil, err
				}
				m["arguments"] = string(raw)
			}
			if s, isStr := m["arguments"].(string); isStr {
				m["arguments"] = normalizeJSONText(s)
			}
		}
		raw, err := compact(dropNulls(it))
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, nil
}

// implicitMessage gives a type and typed parts to an item that has a role and no
// type. Open Responses allows that short form for a message.
func implicitMessage(m map[string]any) {
	if _, hasType := m["type"]; hasType || str(m["role"]) == "" {
		return
	}
	m["type"] = itemMessage
	if text, isStr := m["content"].(string); isStr {
		part := "input_text"
		if str(m["role"]) == "assistant" {
			part = "output_text"
		}
		m["content"] = []any{map[string]any{"type": part, "text": text}}
	}
}

// dropNulls removes each key with a null value. A null carries no information,
// and the gateway writes it in a reply with no stream and not in a stream.
func dropNulls(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if val == nil {
				delete(x, k)
				continue
			}
			x[k] = dropNulls(val)
		}
		return x
	case []any:
		for i := range x {
			x[i] = dropNulls(x[i])
		}
		return x
	}
	return v
}

// normalizeJSONText re-encodes a string that holds JSON with sorted keys. A
// string that is not JSON stays as it is.
func normalizeJSONText(s string) string {
	var v any
	dec := json.NewDecoder(stringsReader(s))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return s
	}
	raw, err := compact(v)
	if err != nil {
		return s
	}
	return string(raw)
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
