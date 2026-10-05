// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
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
	// Transcript: the prompt messages + the assistant completion, captured in
	// full every time (ADR-0120) — never optional. Set once on first
	// observation and never re-folded (a call's transcript is immutable, and a
	// later report can only enrich token/model metadata, never the text). Lets
	// the dashboard conversation view and the flight recorder replace Langfuse
	// without a separate trace store.
	Messages   []LlmMessage
	Completion string
	// CompletionToolCalls carries the tool calls the model made as part of
	// THIS completion (resp.Message.ToolCalls) — distinct from Completion,
	// which is the assistant's text content and is often empty on a
	// tool-calling turn. Without this a tool-calling turn's transcript was
	// silently incomplete (gibson#271).
	CompletionToolCalls []LlmToolCall
	// RecordedAtUnixNano stamps when the daemon observed this call, carried on
	// the event rather than read from time.Now() during Reduce, so a later
	// retention sweep (FlightRecorderRetentionSwept) replays deterministically
	// against the same cutoff every time (gibson#271). Zero means unknown
	// (e.g. a call folded before this field existed) and is never swept.
	RecordedAtUnixNano int64
}

// LlmMessage is one prompt message in an LlmCall transcript. Role + Content
// cover a plain turn; ToolCalls carries any tool calls an assistant message in
// the prompt history made, and ToolCallID/Name identify a tool-result message
// (role "tool") replaying that call's result back to the model. Capturing
// these keeps a tool-calling conversation's replayed history full-fidelity
// instead of silently dropping to bare text (ADR-0120, gibson#271).
type LlmMessage struct {
	Role       string
	Content    string
	Name       string
	ToolCalls  []LlmToolCall
	ToolCallID string
}

// LlmToolCall is one tool call an LLM made as part of a completion — the
// model's own record of what it asked to run, distinct from the AgentToolCall
// the daemon observes when that call is actually dispatched and its result
// comes back (tool_call.go). Mirrors internal/engine/llm.ToolCall.
type LlmToolCall struct {
	ID        string
	Type      string
	Name      string
	Arguments string
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
	MissionID           string
	RunID               string
	Model               string
	ScopeID             string
	PromptTokens        int
	CompletionTokens    int
	Messages            []LlmMessage
	Completion          string
	CompletionToolCalls []LlmToolCall
	RecordedAtUnixNano  int64
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
			if len(c.Messages) == 0 && len(e.Messages) != 0 {
				c.Messages = redactMessages(w, e.Messages)
			}
			if c.Completion == "" && e.Completion != "" {
				c.Completion = redactForTenant(w, e.Completion)
			}
			if len(c.CompletionToolCalls) == 0 && len(e.CompletionToolCalls) != 0 {
				c.CompletionToolCalls = redactToolCalls(w, e.CompletionToolCalls)
			}
			if c.RecordedAtUnixNano == 0 && e.RecordedAtUnixNano != 0 {
				c.RecordedAtUnixNano = e.RecordedAtUnixNano
			}
			q.Close()
			return
		}
	}
	w.llmCalls.NewEntity(&LlmCall{
		CallID:              e.CallID,
		RunID:               e.RunID,
		Model:               e.Model,
		ScopeID:             e.ScopeID,
		PromptTokens:        e.PromptTokens,
		CompletionTokens:    e.CompletionTokens,
		Messages:            redactMessages(w, e.Messages),
		Completion:          redactForTenant(w, e.Completion),
		CompletionToolCalls: redactToolCalls(w, e.CompletionToolCalls),
		RecordedAtUnixNano:  e.RecordedAtUnixNano,
	})
}

// redactMessages applies the tenant's current redaction policy to a
// transcript's message content and any tool calls it carries, returning a
// fresh copy (never mutates the caller's slice).
func redactMessages(w *World, msgs []LlmMessage) []LlmMessage {
	if len(msgs) == 0 {
		return nil
	}
	out := make([]LlmMessage, len(msgs))
	for i, m := range msgs {
		out[i] = LlmMessage{
			Role:       m.Role,
			Content:    redactForTenant(w, m.Content),
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
			ToolCalls:  redactToolCalls(w, m.ToolCalls),
		}
	}
	return out
}

// redactToolCalls applies the tenant's current redaction policy to each tool
// call's arguments, returning a fresh copy (never mutates the caller's slice).
func redactToolCalls(w *World, calls []LlmToolCall) []LlmToolCall {
	if len(calls) == 0 {
		return nil
	}
	out := make([]LlmToolCall, len(calls))
	for i, c := range calls {
		out[i] = LlmToolCall{
			ID:        c.ID,
			Type:      c.Type,
			Name:      c.Name,
			Arguments: redactForTenant(w, c.Arguments),
		}
	}
	return out
}

// LlmCallSnapshot is a stable, comparable view of an LlmCall.
type LlmCallSnapshot struct {
	CallID              string
	RunID               string
	Model               string
	ScopeID             string
	PromptTokens        int
	CompletionTokens    int
	Messages            []LlmMessage
	Completion          string
	CompletionToolCalls []LlmToolCall
	RecordedAtUnixNano  int64
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
			CallID:              c.CallID,
			RunID:               c.RunID,
			Model:               c.Model,
			ScopeID:             c.ScopeID,
			PromptTokens:        c.PromptTokens,
			CompletionTokens:    c.CompletionTokens,
			Messages:            append([]LlmMessage(nil), c.Messages...),
			Completion:          c.Completion,
			CompletionToolCalls: append([]LlmToolCall(nil), c.CompletionToolCalls...),
			RecordedAtUnixNano:  c.RecordedAtUnixNano,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CallID < out[j].CallID })
	return out
}
