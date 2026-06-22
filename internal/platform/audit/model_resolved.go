// Package audit — model_resolved.go
//
// Helpers for emitting `model_resolved` audit events every time the slot
// resolver picks a (provider, model) for an LLM dispatch.
//
// Spec: llm-user-attribution-governance (Requirement 4.7, 4.9). Append-
// only; the emitter is non-blocking — audit-backend failure logs but does
// not abort the LLM call.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"
)

// ModelResolutionEvent is the structured payload persisted to the
// audit stream every time a slot resolution occurs.
type ModelResolutionEvent struct {
	TenantID       string             `json:"tenant_id"`
	UserID         string             `json:"user_id"`
	MissionID      string             `json:"mission_id,omitempty"`
	RunID          string             `json:"run_id,omitempty"`
	AgentID        string             `json:"agent_id,omitempty"`
	SlotName       string             `json:"slot_name"`
	ChosenProvider string             `json:"chosen_provider"`
	ChosenModel    string             `json:"chosen_model"`
	Considered     []CandidateOutcome `json:"considered,omitempty"`
	TimestampUnix  int64              `json:"timestamp_unix"`
}

// CandidateOutcome captures a single model's permit/deny outcome in a
// slot-resolution audit event.
type CandidateOutcome struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
	Allowed  bool   `json:"allowed"`
	Reason   string `json:"reason"` // "shape_mismatch" | "fga_denied" | "allowed"
}

// Emitter is the narrow surface model_resolved emitters use from the
// audit Writer. Pluggable so daemon code can unit-test emission without
// spinning up Postgres.
type Emitter interface {
	Log(event Event)
}

// EmitModelResolved appends a model_resolved event to the audit stream.
// Non-blocking — failure to enqueue is logged and surfaced via the
// writer's existing gibson_audit_dropped_total counter. Calls with a
// nil emitter are no-ops (simplifies wiring when audit is not configured).
func EmitModelResolved(ctx context.Context, em Emitter, logger *slog.Logger, ev ModelResolutionEvent) {
	if em == nil {
		return
	}
	if ev.TimestampUnix == 0 {
		ev.TimestampUnix = time.Now().Unix()
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		if logger != nil {
			logger.WarnContext(ctx, "audit.EmitModelResolved: marshal failed",
				slog.String("error", err.Error()))
		}
		return
	}
	decision := "allow"
	// If every candidate was denied we mark the event decision "deny"
	// so dashboard queries can filter without parsing metadata.
	if len(ev.Considered) > 0 {
		anyAllowed := false
		for _, c := range ev.Considered {
			if c.Allowed {
				anyAllowed = true
				break
			}
		}
		if !anyAllowed {
			decision = "deny"
		}
	}
	em.Log(Event{
		TenantID:   ev.TenantID,
		ActorID:    ev.UserID,
		ActorType:  "user",
		Action:     "model_resolved",
		TargetType: "model",
		TargetID:   ev.ChosenProvider + "/" + ev.ChosenModel,
		Decision:   decision,
		Metadata:   payload,
	})
}
