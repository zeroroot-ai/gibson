// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

// TargetsKey is the key of the target list in a data part of an inbound message.
// A data part such as {"targets": ["<target id>", ...]} narrows the targets of
// the published definition. It changes nothing else.
const TargetsKey = "targets"

// ErrAmbiguousTargets reports a message with more than one target list.
var ErrAmbiguousTargets = fmt.Errorf("%w: the message holds more than one target list", a2a.ErrInvalidParams)

// The rule for a refusal (epic gibson#1367). A message that is not well formed
// gets a JSON-RPC error with the code invalid params, and no Task: a target list
// that is not a list of strings, an empty list, and two lists. An empty list is a
// refusal and never means all targets. A message that is well formed and that the
// policy refuses gets a Task in the state rejected, and no mission starts: a target
// outside the publication, a definition that changed, was deleted or is no longer
// valid, a target that changed or was deleted, two or more targets for a definition
// with no for_each node, a tenant that is suspended, and an agent that is not
// published or a caller with no grant to the agent. A publication has no count
// limit (gibson#1567).

// TargetsOf reads the target list of an inbound message (epic gibson#1367). It
// reads data parts only. It never reads a text part, a file part or the metadata
// of a part, so no text of a message can add a target. present is false when no
// data part holds a list. A data part that is not an object, and a key other than
// TargetsKey, are ignored. A list that is not a list of target ID strings, and a
// second list, are errors. An empty list is an error too, because it names no
// target.
func TargetsOf(m *a2a.Message) (ids []string, present bool, err error) {
	if m == nil {
		return nil, false, nil
	}
	for _, p := range m.Parts {
		if p == nil {
			continue
		}
		obj, ok := p.Data().(map[string]any)
		if !ok {
			continue
		}
		raw, has := obj[TargetsKey]
		if !has {
			continue
		}
		if present {
			return nil, false, ErrAmbiguousTargets
		}
		ids, err = targetIDs(raw)
		if err != nil {
			return nil, false, err
		}
		present = true
	}
	return ids, present, nil
}

// targetIDs reads a list of non-empty strings. The list comes from JSON, so it is
// a []any. A []string is the form of a message that a Go caller built.
func targetIDs(raw any) ([]string, error) {
	var items []any
	switch v := raw.(type) {
	case []any:
		items = v
	case []string:
		for _, s := range v {
			items = append(items, s)
		}
	default:
		return nil, fmt.Errorf("%w: %q is not a list", a2a.ErrInvalidParams, TargetsKey)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%w: %q names no target", a2a.ErrInvalidParams, TargetsKey)
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, ok := it.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("%w: each entry of %q is a target ID string", a2a.ErrInvalidParams, TargetsKey)
		}
		out = append(out, s)
	}
	return out, nil
}

// WebhookKey is the key of the webhook in a data part of an inbound message. The
// value is task data of the mission, and the daemon never reads it as an
// instruction.
const WebhookKey = "webhook"

// MaxWebhookBytes is the largest webhook data that the daemon accepts, in bytes of
// JSON.
const MaxWebhookBytes = 128 << 10

// ErrAmbiguousWebhook reports a message with more than one webhook.
var ErrAmbiguousWebhook = fmt.Errorf("%w: the message holds more than one webhook", a2a.ErrInvalidParams)

// WebhookOf reads the webhook of an inbound message. It reads data parts only,
// never a text part. present is false when no data part holds the key. The value
// must be an object of at most MaxWebhookBytes bytes of JSON. A second webhook is
// an error.
func WebhookOf(m *a2a.Message) (data map[string]any, present bool, err error) {
	if m == nil {
		return nil, false, nil
	}
	for _, p := range m.Parts {
		if p == nil {
			continue
		}
		obj, ok := p.Data().(map[string]any)
		if !ok {
			continue
		}
		raw, has := obj[WebhookKey]
		if !has {
			continue
		}
		if present {
			return nil, false, ErrAmbiguousWebhook
		}
		v, ok := raw.(map[string]any)
		if !ok {
			return nil, false, fmt.Errorf("%w: %q is not an object", a2a.ErrInvalidParams, WebhookKey)
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, false, fmt.Errorf("%w: %q is not JSON", a2a.ErrInvalidParams, WebhookKey)
		}
		if len(b) > MaxWebhookBytes {
			return nil, false, fmt.Errorf("%w: %q is larger than %d bytes", a2a.ErrInvalidParams, WebhookKey, MaxWebhookBytes)
		}
		data, present = v, true
	}
	return data, present, nil
}

// webhookKeyPrefix starts the id of a message that carries a webhook.
const webhookKeyPrefix = "webhook:"

// WebhookMessageKey returns the key that drops a repeated webhook, or an empty
// string when the message has none. The key is the message id
// "webhook:<source>:<id>". A message with another id that holds the metadata
// "webhook_id" gets the key "webhook:<webhook_source>:<webhook_id>".
func WebhookMessageKey(m *a2a.Message) string {
	if m == nil {
		return ""
	}
	if strings.HasPrefix(m.ID, webhookKeyPrefix) && len(m.ID) > len(webhookKeyPrefix) {
		return m.ID
	}
	id, _ := m.Metadata["webhook_id"].(string)
	if id == "" {
		return ""
	}
	source, _ := m.Metadata["webhook_source"].(string)
	return webhookKeyPrefix + source + ":" + id
}

// MaxMessageKeyBytes is the longest key of a webhook message that the daemon accepts.
// The daemon keeps the key, with the agent, in an indexed text column of Postgres, and
// a btree key over about 2700 bytes fails. This bound is far under it.
const MaxMessageKeyBytes = 1024

// CheckWebhookMessageKey refuses a message whose webhook key holds a NUL byte, which a
// Postgres text column refuses, or is longer than MaxMessageKeyBytes. The refusal is an
// invalid params error, so the claim of the key never fails on it. A message with no
// webhook key passes.
func CheckWebhookMessageKey(m *a2a.Message) error {
	key := WebhookMessageKey(m)
	switch {
	case strings.IndexByte(key, 0) >= 0:
		return fmt.Errorf("%w: the message id or the webhook id holds a NUL byte", a2a.ErrInvalidParams)
	case len(key) > MaxMessageKeyBytes:
		return fmt.Errorf("%w: the message id or the webhook id is longer than %d bytes", a2a.ErrInvalidParams, MaxMessageKeyBytes)
	}
	return nil
}
