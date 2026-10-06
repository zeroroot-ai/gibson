// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
)

// Action constants for AuditEvent.Action. These are the canonical action
// strings for secret operations per the audit-taxonomy-foundation schema.
const (
	// ActionSecretRead is emitted when a secret value is resolved.
	ActionSecretRead = "secret_read"
	// ActionSecretWrite is emitted when a secret value is created or updated.
	ActionSecretWrite = "secret_write"
	// ActionSecretDelete is emitted when a secret is deleted.
	ActionSecretDelete = "secret_delete"
	// ActionSecretList is emitted when a tenant's secret names are listed.
	ActionSecretList = "secret_list"
	// ActionSecretProbe is emitted when a provider probe is executed.
	ActionSecretProbe = "secret_probe"
	// ActionSecretConfigSet is emitted when a tenant's broker configuration
	// is created, updated, or deleted.
	ActionSecretConfigSet = "secret_config_set"
)

// Effect constants for AuditEvent.Effect.
const (
	// EffectAllow indicates the operation was permitted and succeeded.
	EffectAllow = "allow"
	// EffectDeny indicates the operation was denied or failed.
	EffectDeny = "deny"
)

// AuditEvent is the subset of the audit event schema relevant to secret
// operations. Fields correspond to the audit-taxonomy-foundation columns.
//
// These fields were once also the input to the compliance-signal projection.
// That pipeline is gone (gibson#1299, ADR-0113) and the audit log is now the
// sole compliance evidence base, so every field below is load-bearing for
// evidence, not merely for observability.
//
// SECURITY: No field in AuditEvent must ever contain a plaintext secret
// value, ciphertext, or credential. The ResourceURI identifies the secret by
// name only (e.g. "secret:tenant-acme:cred:openai-prod"). The AuditWriter
// enforces an additional content guard: any string field longer than 256
// bytes that contains the literal substring "value" or "secret_value" is
// rejected and logged CRITICAL.
type AuditEvent struct {
	// ActorID is the authenticated subject performing the operation (e.g.
	// "plugin_principal:plugin-github-1").
	ActorID string

	// ActorTenantID is the tenant the actor belongs to.
	ActorTenantID string

	// MissionID is set when the operation occurs within a mission context.
	// Empty when no mission is active.
	MissionID string

	// AgentRunID is set when the operation occurs within an agent run.
	// Empty when no agent run is active.
	AgentRunID string

	// Action is one of the Action* constants defined above.
	Action string

	// Effect is EffectAllow or EffectDeny.
	Effect string

	// ResourceType is always "secret" for secret operations, or
	// "secret_broker_config" for config-set operations.
	ResourceType string

	// ResourceURI identifies the specific resource, e.g.
	// "secret:tenant-acme:cred:openai-prod".
	ResourceURI string

	// Decision is "allow" or "deny".
	Decision string

	// DecisionReason is a categorised reason string when Decision is
	// "deny" (e.g. "not_found", "circuit_open", "fga_no_can_resolve").
	DecisionReason string

	// Success reports whether the underlying secret operation completed
	// successfully.
	Success bool

	// ErrorCode is a machine-readable error class when Success is false.
	ErrorCode string

	// LatencyMS is the end-to-end latency of the operation in milliseconds.
	LatencyMS int64

	// OccurredAt is the UTC timestamp of the operation.
	OccurredAt time.Time
}

// plainTextGuardSubstrings are heuristic substrings whose presence in a
// long string field is treated as accidental plaintext leakage. The check
// is intentionally conservative: a field must exceed 256 bytes AND contain
// one of these substrings to be rejected.
var plainTextGuardSubstrings = []string{"value", "secret_value"}

// auditFieldMaxLenForGuard is the field length above which the plaintext
// guard scan activates. Fields shorter than this threshold are passed
// through without scanning (short strings can legitimately contain the
// word "value" in an error message).
const auditFieldMaxLenForGuard = 256

// auditFailuresTotal counts AuditWriter write failures after all retries
// are exhausted. Labeled by tenant so SRE can identify which tenant's audit
// pipeline is unhealthy.
var auditFailuresTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "gibson_secrets_audit_failures_total",
		Help: "Number of secrets audit write failures after all retries are exhausted, labeled by tenant.",
	},
	[]string{"tenant"},
)

// AuditWriter emits AuditEvents to the existing Redis Streams audit pipeline.
// AuditWriter is safe for concurrent use.
type AuditWriter struct {
	logger *audit.AuditLogger
	slog   *slog.Logger
	clock  func() time.Time // injectable for tests; nil uses time.Now
}

// NewAuditWriter constructs an AuditWriter backed by the given audit logger
// and slog instance. Both must be non-nil.
func NewAuditWriter(logger *audit.AuditLogger, sl *slog.Logger) *AuditWriter {
	if logger == nil {
		panic("secrets audit writer: AuditLogger must not be nil")
	}
	if sl == nil {
		panic("secrets audit writer: slog.Logger must not be nil")
	}
	return &AuditWriter{
		logger: logger,
		slog:   sl.With("component", "secrets_audit_writer"),
	}
}

// Audit emits event to the Redis Streams audit pipeline. It never returns an
// error. The underlying AuditLogger.LogWithResult is fire-and-forget — it
// enqueues the write asynchronously and handles drop counting internally.
//
// SECURITY: If any string field of event that is longer than 256 bytes
// contains the literal substring "value" or "secret_value", the event is
// rejected: a CRITICAL log is emitted and the write is skipped entirely.
// This is a heuristic defence against accidental plaintext leakage.
func (w *AuditWriter) Audit(ctx context.Context, event AuditEvent) {
	if w.rejectOnPlaintextGuard(ctx, event) {
		return
	}
	w.write(ctx, event)
}

// ErrAuditRejected is returned by Record when the plaintext guard rejects
// the event. The caller must not make the change.
var ErrAuditRejected = errors.New("secrets audit writer: the plaintext guard rejected the event")

// Record writes the event to Postgres before the change that it describes,
// and returns after Postgres has it (D15, gibson#676). The caller makes the
// change only when Record returns nil. When the change then fails, the
// caller writes a second event with Audit and Success false.
//
// Record returns ErrAuditRejected when the plaintext guard rejects the
// event, and the error of the durable write otherwise.
func (w *AuditWriter) Record(ctx context.Context, event AuditEvent) error {
	if w.rejectOnPlaintextGuard(ctx, event) {
		return ErrAuditRejected
	}
	if _, err := w.logger.Record(ctx, event.Action, event.ResourceType, event.ResourceURI, w.details(event)); err != nil {
		auditFailuresTotal.WithLabelValues(event.ActorTenantID).Inc()
		return fmt.Errorf("secrets audit writer: %w", err)
	}
	return nil
}

// write hands the event to the audit logger. It maps AuditEvent fields to
// the AuditLogger.LogWithResult API. The logger puts the record into the
// queue of the Postgres writer, which drops nothing, so write returns no
// error.
func (w *AuditWriter) write(ctx context.Context, event AuditEvent) {
	result := "success"
	if !event.Success {
		result = "failure"
	}

	// AuditLogger.LogWithResult extracts the tenant from context; when the
	// ctx lacks an identity (e.g. background flush), it falls back to
	// "unknown". For correctness we always use LogWithResult with the event's
	// actor tenant as the canonical audit row owner.
	w.logger.LogWithResult(
		ctx,
		event.Action,
		event.ResourceType,
		event.ResourceURI,
		result,
		w.details(event),
	)
}

// details builds the details map of the audit record from the structured
// AuditEvent fields. It omits each field that could carry plaintext.
func (w *AuditWriter) details(event AuditEvent) map[string]any {
	now := event.OccurredAt
	if now.IsZero() {
		if w.clock != nil {
			now = w.clock()
		} else {
			now = time.Now().UTC()
		}
	}

	details := map[string]any{
		"effect":        event.Effect,
		"resource_type": event.ResourceType,
		"resource_uri":  event.ResourceURI,
		"decision":      event.Decision,
		"success":       event.Success,
		"latency_ms":    event.LatencyMS,
		"occurred_at":   now.Format(time.RFC3339Nano),
	}
	if event.DecisionReason != "" {
		details["decision_reason"] = event.DecisionReason
	}
	if event.ErrorCode != "" {
		details["error_code"] = event.ErrorCode
	}
	if event.MissionID != "" {
		details["mission_id"] = event.MissionID
	}
	if event.AgentRunID != "" {
		details["agent_run_id"] = event.AgentRunID
	}
	return details
}

// rejectOnPlaintextGuard checks all string fields of event that exceed
// auditFieldMaxLenForGuard bytes. If any such field contains one of the
// plainTextGuardSubstrings, it logs CRITICAL and returns true (skip write).
func (w *AuditWriter) rejectOnPlaintextGuard(ctx context.Context, event AuditEvent) bool {
	fields := []struct {
		name  string
		value string
	}{
		{"actor_id", event.ActorID},
		{"actor_tenant_id", event.ActorTenantID},
		{"mission_id", event.MissionID},
		{"agent_run_id", event.AgentRunID},
		{"action", event.Action},
		{"effect", event.Effect},
		{"resource_type", event.ResourceType},
		{"resource_uri", event.ResourceURI},
		{"decision", event.Decision},
		{"decision_reason", event.DecisionReason},
		{"error_code", event.ErrorCode},
	}

	for _, f := range fields {
		if len(f.value) <= auditFieldMaxLenForGuard {
			continue
		}
		for _, sub := range plainTextGuardSubstrings {
			if containsSubstring(f.value, sub) {
				w.slog.ErrorContext(ctx,
					"CRITICAL: secrets audit event rejected — plaintext guard triggered; possible secret leakage",
					slog.String("field", f.name),
					slog.String("action", event.Action),
					slog.String("actor_tenant_id", event.ActorTenantID),
				)
				auditFailuresTotal.WithLabelValues(event.ActorTenantID).Inc()
				return true
			}
		}
	}
	return false
}

// containsSubstring reports whether s contains sub as a case-sensitive
// substring. Using a simple bytes scan avoids importing strings package
// unnecessarily.
func containsSubstring(s, sub string) bool {
	if len(sub) == 0 || len(s) < len(sub) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
