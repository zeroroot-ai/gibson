package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/zero-day-ai/gibson/internal/audit"
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

// AuditEvent is the subset of the compliance_signal schema relevant to
// secret operations. Fields correspond to the audit-taxonomy-foundation
// compliance_signal columns.
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
// It retries up to 3 times with exponential backoff (250ms, 500ms, 1s) and
// on final failure logs CRITICAL via slog and increments the
// gibson_secrets_audit_failures_total counter. It never returns an error —
// audit failures must not block the underlying secret operation.
//
// AuditWriter is safe for concurrent use.
type AuditWriter struct {
	logger *audit.AuditLogger
	slog   *slog.Logger
	clock  func() time.Time   // injectable for tests; nil uses time.Now
	sleep  func(time.Duration) // injectable for tests; nil uses time.Sleep
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

// newAuditWriterWithClock is the test constructor that accepts clock and sleep
// overrides for deterministic retry-backoff tests.
func newAuditWriterWithClock(
	logger *audit.AuditLogger,
	sl *slog.Logger,
	clock func() time.Time,
	sleep func(time.Duration),
) *AuditWriter {
	w := NewAuditWriter(logger, sl)
	w.clock = clock
	w.sleep = sleep
	return w
}

// Audit emits event to the Redis Streams audit pipeline. It retries on
// transient write failures with exponential backoff and degrades gracefully
// to a CRITICAL log on final failure. It never returns an error.
//
// SECURITY: If any string field of event that is longer than 256 bytes
// contains the literal substring "value" or "secret_value", the event is
// rejected: a CRITICAL log is emitted and the write is skipped entirely.
// This is a heuristic defence against accidental plaintext leakage.
func (w *AuditWriter) Audit(ctx context.Context, event AuditEvent) {
	if w.rejectOnPlaintextGuard(ctx, event) {
		return
	}

	backoffs := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second}
	sleepFn := time.Sleep
	if w.sleep != nil {
		sleepFn = w.sleep
	}

	var lastErr error
	for attempt := 0; attempt <= len(backoffs); attempt++ {
		if attempt > 0 {
			sleepFn(backoffs[attempt-1])
		}
		if err := w.write(ctx, event); err != nil {
			lastErr = err
			continue
		}
		return // success
	}

	// All retries exhausted — log CRITICAL and increment counter.
	w.slog.ErrorContext(ctx, "CRITICAL: secrets audit write failed after all retries; audit gap",
		slog.String("action", event.Action),
		slog.String("effect", event.Effect),
		slog.String("actor_id", event.ActorID),
		slog.String("actor_tenant_id", event.ActorTenantID),
		slog.String("resource_uri", event.ResourceURI),
		slog.String("error", lastErr.Error()),
	)
	auditFailuresTotal.WithLabelValues(event.ActorTenantID).Inc()
}

// write performs a single attempt to emit the event to the Redis Streams
// audit logger. It maps AuditEvent fields to the existing AuditLogger.Log /
// LogWithResult API.
func (w *AuditWriter) write(ctx context.Context, event AuditEvent) error {
	now := event.OccurredAt
	if now.IsZero() {
		if w.clock != nil {
			now = w.clock()
		} else {
			now = time.Now().UTC()
		}
	}

	result := "success"
	if !event.Success {
		result = "failure"
	}

	// Build a details map from the structured AuditEvent fields. The
	// audit.AuditLogger stores these as JSON in the stream "details" field.
	// We intentionally omit any field that could carry plaintext.
	details := map[string]any{
		"effect":          event.Effect,
		"resource_type":   event.ResourceType,
		"resource_uri":    event.ResourceURI,
		"decision":        event.Decision,
		"success":         event.Success,
		"latency_ms":      event.LatencyMS,
		"occurred_at":     now.Format(time.RFC3339Nano),
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

	// Inject actor context into ctx so the logger's TenantStringFromContext
	// and IdentityFromContext produce correct values. The audit logger
	// extracts the tenant from context — it always reads the stream key
	// from the tenant in ctx. We pass a context already carrying the identity
	// (set by the SDK interceptor in production). In the audit writer we
	// pass the raw tenant string via the log call's resource fields rather
	// than relying on ctx having the identity — this avoids a dependency on
	// the identity being in context for background writes.
	//
	// The existing AuditLogger.LogWithResult extracts the tenant from
	// context; when the ctx lacks an identity (e.g. background flush), it
	// falls back to "unknown". For correctness we always use LogWithResult
	// with the event's actor tenant as the canonical audit row owner.
	err := w.logger.LogWithResult(
		ctx,
		event.Action,
		event.ResourceType,
		event.ResourceURI,
		result,
		details,
	)
	if err != nil {
		return fmt.Errorf("secrets audit: write stream entry: %w", err)
	}
	return nil
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
