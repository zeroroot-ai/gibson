// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"encoding/json"
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// LlmCall is a single LLM completion made during a mission — a unit of
// run-provenance (ADR-0107, gibson#755) and, since ADR-0120's flight recorder
// (gibson#271), the full-fidelity transcript record for that completion.
// Capture is ALWAYS ON: every fleet agent turn's prompt messages and completion
// (including any tool calls the model made) are folded in here, never only the
// metadata. Identity is the globally-unique CallID assigned daemon-side, so it
// needs no scope-relative resolution: CallID is the stable graph-projection
// key. RunID links the call to the AgentRun that issued it (the ISSUED edge in
// the projected graph); it is empty for a mission-level call (e.g. the
// Decider) with no owning agent run. Only the metadata (model, token counts,
// provenance ids) projects to the graph; the full transcript text stays here
// on the Timeline/component (ADR-0120).
type LlmCall struct {
	CallID           string // identity + stable projection key
	RunID            string // the AgentRun that issued this call ("" for a mission-level call)
	Model            string
	ScopeID          string
	PromptTokens     int
	CompletionTokens int
	// ErrorText is the text of the reply of a failed call (a status of 400 or
	// more). It is empty for a call that worked: the output items hold its reply.
	ErrorText string
	// Items is the transcript of the call as Open Responses items: the input
	// items, then the output items (ADR-0173). It is set when the call is read
	// from the gateway trace. Each string of each item is redacted at fold time.
	Items []json.RawMessage
	// RequestItems is the number of leading items that are the request. The rest
	// are the output items. A failed call has request items only.
	RequestItems int
	// Provider is the model provider that the gateway used.
	Provider string
	// CacheReadTokens and CacheWriteTokens are the cache token counts of the call.
	CacheReadTokens  int
	CacheWriteTokens int
	// Cost is the cost of the call in US dollars, as a decimal string. It is
	// empty when the gateway has no price for the model. Empty means unknown. It
	// is never "0" for an unpriced model.
	Cost string
	// HTTPStatus is the status that the gateway answered. It is 0 when the
	// source does not know it. A status of 400 or more means that the call
	// failed, and Completion then holds the error text of the reply.
	HTTPStatus int
	// RecordedAtUnixNano stamps when the daemon observed this call, carried on
	// the event rather than read from time.Now() during Reduce, so a later
	// retention sweep (FlightRecorderRetentionSwept) replays deterministically
	// against the same cutoff every time (gibson#271). Zero means unknown
	// (e.g. a call folded before this field existed) and is never swept.
	RecordedAtUnixNano int64
}

// LlmCallObserved records that an LLM completion happened. Emitted daemon-side
// from the provider-execution path (where token usage is known), fed into the
// brain via the daemon EventBus like the other mission lifecycle events — NOT
// via the agent Observe surface, which is for target sightings.
type LlmCallObserved struct {
	CallID string
	// MissionID links the call to the mission it ran under — the mission-evidence
	// edge (gibson#1075), the same edge hosts and findings use, so a mission-scoped
	// frame surfaces the calls that mission made. Empty when the caller (e.g.
	// ExecuteLLM) carries no mission context, in which case the call is
	// tenant-ambient and never attaches to a mission frame (follow-up gibson#1078).
	MissionID string
	// MissionRunID is the run of the mission that produced this evidence. The
	// reducer drops the event when the mission has moved on to another run, so
	// late evidence of run 1 cannot count for run 2 (gibson#1217). Empty means
	// the event is not run-scoped.
	MissionRunID     string
	RunID            string
	Model            string
	ScopeID          string
	PromptTokens     int
	CompletionTokens int
	// ErrorText is the text of the reply of a failed call. See LlmCall.ErrorText.
	ErrorText          string `json:",omitempty"`
	RecordedAtUnixNano int64
	// The fields below come from the gateway trace (gibson#1390). An event of the
	// older shape decodes with the zero values.
	Items []json.RawMessage `json:",omitempty"`
	// RequestItems is the number of leading items that are the request.
	RequestItems     int    `json:",omitempty"`
	Provider         string `json:",omitempty"`
	CacheReadTokens  int    `json:",omitempty"`
	CacheWriteTokens int    `json:",omitempty"`
	Cost             string `json:",omitempty"`
	// HTTPStatus is the status of the gateway reply. A status of 400 or more
	// means that the call failed. Completion then holds the error text.
	HTTPStatus int `json:",omitempty"`
}

func (LlmCallObserved) Kind() string { return "llm_call.observed" }

// applyLlmCallObserved resolves an LLM call by CallID (idempotent) or creates one,
// enriching fields that were not yet known. Progressive enrichment mirrors the
// AgentRun reducer: a later observation refines blanks but never erases a known
// value, and token counts are taken on first non-zero report. Transcript text
// is redacted per the tenant's current FlightRecorderPolicy at fold time
// (gibson#271) — a pure function of already-folded World state, so replay is
// deterministic.
func applyLlmCallObserved(w *World, e LlmCallObserved) {
	if e.CallID == "" {
		return
	}
	q := ecs.NewFilter1[LlmCall](w.ecs).Query()
	for q.Next() {
		c := q.Get()
		if c.CallID == e.CallID {
			if c.RunID == "" && e.RunID != "" {
				c.RunID = e.RunID
			}
			if c.Model == "" && e.Model != "" {
				c.Model = e.Model
			}
			if c.ScopeID == "" && e.ScopeID != "" {
				c.ScopeID = e.ScopeID
			}
			if c.PromptTokens == 0 && e.PromptTokens != 0 {
				c.PromptTokens = e.PromptTokens
			}
			if c.CompletionTokens == 0 && e.CompletionTokens != 0 {
				c.CompletionTokens = e.CompletionTokens
			}
			if c.ErrorText == "" && e.ErrorText != "" {
				c.ErrorText = redactForTenant(w, e.ErrorText)
			}
			if c.RecordedAtUnixNano == 0 && e.RecordedAtUnixNano != 0 {
				c.RecordedAtUnixNano = e.RecordedAtUnixNano
			}
			if len(c.Items) == 0 && len(e.Items) != 0 {
				c.Items = redactItems(w, e.Items)
				c.RequestItems = e.RequestItems
			}
			if c.Provider == "" {
				c.Provider = e.Provider
			}
			if c.CacheReadTokens == 0 {
				c.CacheReadTokens = e.CacheReadTokens
			}
			if c.CacheWriteTokens == 0 {
				c.CacheWriteTokens = e.CacheWriteTokens
			}
			if c.Cost == "" {
				c.Cost = e.Cost
			}
			if c.HTTPStatus == 0 {
				c.HTTPStatus = e.HTTPStatus
			}
			q.Close()
			return
		}
	}
	w.llmCalls.NewEntity(&LlmCall{
		CallID:             e.CallID,
		RunID:              e.RunID,
		Model:              e.Model,
		ScopeID:            e.ScopeID,
		PromptTokens:       e.PromptTokens,
		CompletionTokens:   e.CompletionTokens,
		ErrorText:          redactForTenant(w, e.ErrorText),
		RecordedAtUnixNano: e.RecordedAtUnixNano,
		Items:              redactItems(w, e.Items),
		RequestItems:       e.RequestItems,
		Provider:           e.Provider,
		CacheReadTokens:    e.CacheReadTokens,
		CacheWriteTokens:   e.CacheWriteTokens,
		Cost:               e.Cost,
		HTTPStatus:         e.HTTPStatus,
	})
}

// redactItems applies the tenant's redaction policy to each string inside each
// Open Responses item. It walks the JSON, so the result stays valid JSON. It
// returns a fresh copy. An item that is not valid JSON becomes a JSON string
// with the redacted text, so the transcript never holds invalid JSON.
func redactItems(w *World, items []json.RawMessage) []json.RawMessage {
	if len(items) == 0 {
		return nil
	}
	if w == nil || !w.flightRecorderPolicy.Redact {
		out := make([]json.RawMessage, len(items))
		for i, it := range items {
			out[i] = append(json.RawMessage(nil), it...)
		}
		return out
	}
	out := make([]json.RawMessage, len(items))
	for i, it := range items {
		var v any
		if err := json.Unmarshal(it, &v); err != nil {
			v = string(it)
		}
		raw, err := json.Marshal(redactJSONStrings(w, v))
		if err != nil {
			raw = json.RawMessage(`"` + redactedPlaceholder + `"`)
		}
		out[i] = raw
	}
	return out
}

func redactJSONStrings(w *World, v any) any {
	switch x := v.(type) {
	case string:
		return redactForTenant(w, x)
	case []any:
		for i := range x {
			x[i] = redactJSONStrings(w, x[i])
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = redactJSONStrings(w, x[k])
		}
		return x
	}
	return v
}

// LlmCallSnapshot is a stable, comparable view of an LlmCall.
type LlmCallSnapshot struct {
	CallID             string
	RunID              string
	Model              string
	ScopeID            string
	PromptTokens       int
	CompletionTokens   int
	ErrorText          string
	RecordedAtUnixNano int64
	Items              []json.RawMessage `json:",omitempty"`
	RequestItems       int               `json:",omitempty"`
	Provider           string            `json:",omitempty"`
	CacheReadTokens    int               `json:",omitempty"`
	CacheWriteTokens   int               `json:",omitempty"`
	Cost               string            `json:",omitempty"`
	HTTPStatus         int               `json:",omitempty"`
}

// TotalTokens is the prompt+completion token count — the per-call cost signal
// the dashboard surfaces (replaces the Langfuse per-trace token rollup).
func (s LlmCallSnapshot) TotalTokens() int { return s.PromptTokens + s.CompletionTokens }

// LlmCallSnapshot returns LLM calls in deterministic (CallID) order.
func (w *World) LlmCallSnapshot() []LlmCallSnapshot {
	var out []LlmCallSnapshot
	q := ecs.NewFilter1[LlmCall](w.ecs).Query()
	for q.Next() {
		c := q.Get()
		out = append(out, LlmCallSnapshot{
			CallID:             c.CallID,
			RunID:              c.RunID,
			Model:              c.Model,
			ScopeID:            c.ScopeID,
			PromptTokens:       c.PromptTokens,
			CompletionTokens:   c.CompletionTokens,
			ErrorText:          c.ErrorText,
			RecordedAtUnixNano: c.RecordedAtUnixNano,
			Items:              append([]json.RawMessage(nil), c.Items...),
			RequestItems:       c.RequestItems,
			Provider:           c.Provider,
			CacheReadTokens:    c.CacheReadTokens,
			CacheWriteTokens:   c.CacheWriteTokens,
			Cost:               c.Cost,
			HTTPStatus:         c.HTTPStatus,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CallID < out[j].CallID })
	return out
}
