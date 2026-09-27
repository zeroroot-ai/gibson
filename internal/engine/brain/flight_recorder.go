// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package brain — flight_recorder.go: per-tenant retention/redaction policy
// for the always-on transcript + tool-I/O capture (ADR-0020, gibson#271).
//
// Capture itself is never optional: every LlmCall (llm_call.go) and every
// AgentToolCall (tool_call.go) always records its full text at fold time. This
// file controls what happens to that text afterwards — a tenant can ask for it
// to be scrubbed of secret-shaped substrings before it lands (Redact), and/or
// swept away after it ages out (RetentionDays) — never whether it is captured
// in the first place. Metadata (ids, model, tool name, token counts) is never
// redacted or swept; it is what still projects to the graph once the full text
// is gone (the acceptance criterion "metadata still projects to the graph;
// full text stays on the component/Timeline").
package brain

import (
	"regexp"

	"github.com/mlange-42/ark/ecs"
)

// FlightRecorderPolicy is the per-tenant retention/redaction configuration.
// There is exactly one policy per tenant World (a World is already
// tenant-scoped, ADR-0001), applied at fold time to every LlmCall/AgentToolCall
// text field folded after it takes effect.
type FlightRecorderPolicy struct {
	// Redact, when true, scrubs common secret-shaped substrings (bearer
	// tokens, API keys, AWS access keys, PEM private-key blocks) from
	// transcript/tool-I/O text before it is folded into the World. Applied
	// once, at write time; a later policy change never retroactively
	// re-scrubs text already folded (the Timeline is append-only).
	Redact bool
	// RetentionDays bounds how long full transcript/tool-I/O text is kept
	// before a FlightRecorderRetentionSwept event clears it. Zero means keep
	// indefinitely — the default, so existing deployments keep today's
	// behavior until a tenant opts in.
	RetentionDays int
}

// DefaultFlightRecorderPolicy is the policy every tenant World starts under
// (the zero value: capture everything, redact nothing, retain indefinitely).
var DefaultFlightRecorderPolicy = FlightRecorderPolicy{}

// FlightRecorderPolicySet configures a tenant's retention/redaction policy
// (ADR-0020 acceptance criterion: "retention and redaction are configurable
// per tenant"). It is a domain event like any other, so a policy change is
// itself part of the deterministic Timeline: replay reproduces the exact
// policy in force at the time each transcript/tool-I/O event was folded,
// because redaction is applied once, at that fold, never recomputed later.
type FlightRecorderPolicySet struct {
	Redact        bool
	RetentionDays int
}

func (FlightRecorderPolicySet) Kind() string { return "flight_recorder.policy_set" }

func applyFlightRecorderPolicySet(w *World, e FlightRecorderPolicySet) {
	w.flightRecorderPolicy = FlightRecorderPolicy{Redact: e.Redact, RetentionDays: e.RetentionDays}
}

// FlightRecorderPolicy returns the tenant's current policy
// (DefaultFlightRecorderPolicy until a FlightRecorderPolicySet event has been
// folded).
func (w *World) FlightRecorderPolicy() FlightRecorderPolicy { return w.flightRecorderPolicy }

// redactForTenant scrubs text per the tenant's current policy. Applied at
// fold time only (never re-applied to already-folded text), so it is a pure
// function of already-folded World state + the raw text — deterministic on
// replay: the policy events on the Timeline always precede the transcript
// events they govern, in the same order every fold.
func redactForTenant(w *World, text string) string {
	if text == "" || w == nil || !w.flightRecorderPolicy.Redact {
		return text
	}
	return RedactSecrets(text)
}

// secretPatterns are conservative, common secret shapes worth scrubbing from
// captured transcript/tool-I/O text. Deliberately narrow (false negatives over
// false positives): this is a best-effort courtesy scrub for a tenant that
// opted in, not a security boundary — do not rely on it to make untrusted text
// safe to display.
var secretPatterns = []*regexp.Regexp{
	// Bearer / authorization tokens.
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9._~+/-]{10,}=*`),
	// AWS access key ids.
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
	// Generic "api_key"/"token"/"secret" style key=value pairs.
	regexp.MustCompile(`(?i)(api[_-]?key|access[_-]?token|secret)["']?\s*[:=]\s*["']?[a-zA-Z0-9._-]{8,}["']?`),
	// PEM private-key blocks.
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
}

const redactedPlaceholder = "[redacted]"

// RedactSecrets scrubs common secret-shaped substrings out of text, replacing
// each match with a fixed placeholder so the surrounding structure of the
// transcript (who said what, in what order) is still legible.
func RedactSecrets(text string) string {
	for _, p := range secretPatterns {
		text = p.ReplaceAllString(text, redactedPlaceholder)
	}
	return text
}

// purgedPlaceholder replaces full transcript/tool-I/O text a retention sweep
// has aged out. It is intentionally distinct from redactedPlaceholder so a
// query can tell "the tenant asked us to scrub this" apart from "this aged
// past retention".
const purgedPlaceholder = "[retention: purged]"

// FlightRecorderRetentionSwept prunes full transcript/tool-I/O text recorded
// before Cutoff, replacing it with purgedPlaceholder while leaving every other
// field (ids, model, tool name, token counts) intact — metadata still
// projects to the graph even after full text ages out. CutoffUnixNano is
// carried on the event, never computed from time.Now() during Reduce, so a
// retention sweep replays deterministically: the same event always purges the
// same set of calls.
type FlightRecorderRetentionSwept struct {
	CutoffUnixNano int64
}

func (FlightRecorderRetentionSwept) Kind() string { return "flight_recorder.retention_swept" }

func applyFlightRecorderRetentionSwept(w *World, e FlightRecorderRetentionSwept) {
	if e.CutoffUnixNano == 0 {
		return
	}
	lq := ecs.NewFilter1[LlmCall](w.ecs).Query()
	for lq.Next() {
		c := lq.Get()
		if c.RecordedAtUnixNano == 0 || c.RecordedAtUnixNano >= e.CutoffUnixNano {
			continue
		}
		if len(c.Messages) > 0 {
			c.Messages = []LlmMessage{{Role: "system", Content: purgedPlaceholder}}
		}
		if c.Completion != "" {
			c.Completion = purgedPlaceholder
		}
		c.CompletionToolCalls = nil
	}

	tq := ecs.NewFilter1[AgentToolCall](w.ecs).Query()
	for tq.Next() {
		c := tq.Get()
		if c.RecordedAtUnixNano == 0 || c.RecordedAtUnixNano >= e.CutoffUnixNano {
			continue
		}
		if c.Arguments != "" {
			c.Arguments = purgedPlaceholder
		}
		if c.Result != "" {
			c.Result = purgedPlaceholder
		}
	}
}
