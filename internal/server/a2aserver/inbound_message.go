// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package a2aserver

import (
	"errors"
	"fmt"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

// TargetsKey is the key of the target list in a data part of an inbound message.
// A data part such as {"targets": ["<target id>", ...]} narrows the targets of
// the published definition. It changes nothing else.
const TargetsKey = "targets"

// ErrAmbiguousTargets reports a message with more than one target list.
var ErrAmbiguousTargets = errors.New("a2a: the message holds more than one target list")

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
