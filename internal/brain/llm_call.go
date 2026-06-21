package brain

import (
	"sort"

	"github.com/mlange-42/ark/ecs"
)

// LlmCall is a single LLM completion made during a mission — a unit of
// run-provenance (ADR-0007, gibson#755). It carries call METADATA (model, token
// counts, the agent run that issued it), not the full prompt/completion
// transcript: the brain Timeline is the lean system of record, so per-call
// conversation payloads are deliberately not folded in. Identity is the
// globally-unique CallID assigned daemon-side, so it needs no scope-relative
// resolution: CallID is the stable graph-projection key. RunID links the call to
// the AgentRun that issued it (the ISSUED edge in the projected graph); it is
// empty for a mission-level call (e.g. the Decider) with no owning agent run.
type LlmCall struct {
	CallID           string // identity + stable projection key
	RunID            string // the AgentRun that issued this call ("" for a mission-level call)
	Model            string
	ScopeID          string
	PromptTokens     int
	CompletionTokens int
	// Transcript (optional): the prompt messages + the assistant completion. Set
	// once on first observation and never re-folded (a call's transcript is
	// immutable). Lets the dashboard conversation view replace Langfuse without a
	// separate trace store; only the metadata projects to the graph.
	Messages   []LlmMessage
	Completion string
}

// LlmMessage is one prompt message in an LlmCall transcript (role + content).
type LlmMessage struct {
	Role    string
	Content string
}

// LlmCallObserved records that an LLM completion happened. Emitted daemon-side
// from the provider-execution path (where token usage is known), fed into the
// brain via the daemon EventBus like the other mission lifecycle events — NOT
// via the agent Observe surface, which is for target sightings.
type LlmCallObserved struct {
	CallID           string
	RunID            string
	Model            string
	ScopeID          string
	PromptTokens     int
	CompletionTokens int
	Messages         []LlmMessage
	Completion       string
}

func (LlmCallObserved) Kind() string { return "llm_call.observed" }

// applyLlmCallObserved resolves an LLM call by CallID (idempotent) or creates one,
// enriching fields that were not yet known. Progressive enrichment mirrors the
// AgentRun reducer: a later observation refines blanks but never erases a known
// value, and token counts are taken on first non-zero report.
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
				c.Messages = append([]LlmMessage(nil), e.Messages...)
			}
			if c.Completion == "" && e.Completion != "" {
				c.Completion = e.Completion
			}
			q.Close()
			return
		}
	}
	w.llmCalls.NewEntity(&LlmCall{
		CallID:           e.CallID,
		RunID:            e.RunID,
		Model:            e.Model,
		ScopeID:          e.ScopeID,
		PromptTokens:     e.PromptTokens,
		CompletionTokens: e.CompletionTokens,
		Messages:         append([]LlmMessage(nil), e.Messages...),
		Completion:       e.Completion,
	})
}

// LlmCallSnapshot is a stable, comparable view of an LlmCall.
type LlmCallSnapshot struct {
	CallID           string
	RunID            string
	Model            string
	ScopeID          string
	PromptTokens     int
	CompletionTokens int
	Messages         []LlmMessage
	Completion       string
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
			CallID:           c.CallID,
			RunID:            c.RunID,
			Model:            c.Model,
			ScopeID:          c.ScopeID,
			PromptTokens:     c.PromptTokens,
			CompletionTokens: c.CompletionTokens,
			Messages:         append([]LlmMessage(nil), c.Messages...),
			Completion:       c.Completion,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CallID < out[j].CallID })
	return out
}
