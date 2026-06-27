// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package audit emits structured audit events for every reconcile action.
// Events go to two sinks simultaneously: stdout (for log aggregation via
// Loki/Promtail) and Redis Streams (for the Gibson audit log store).
//
// Emission is asynchronous via a buffered channel. When the channel is
// full, the emitter blocks briefly then drops the oldest event. Callers
// should NOT block a reconcile loop on audit emission — use EmitAsync for
// fire-and-forget, and only use EmitSync when fail-closed behavior is
// needed (e.g., for security-sensitive operations).
//
// Saga-specific events use the lighter-weight SagaEmitter, which writes
// synchronously to stdout with the [audit.tenant-operator] prefix matching
// the dashboard's [audit.auth] / [audit.crd] shape.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/redis/go-redis/v9"
)

// AuditEvent is the canonical schema for all Gibson audit records.
type AuditEvent struct {
	Timestamp       time.Time       `json:"timestamp"`
	Tenant          string          `json:"tenant"`
	Subsystem       string          `json:"subsystem"`
	Action          string          `json:"action"`
	Before          json.RawMessage `json:"before,omitempty"`
	After           json.RawMessage `json:"after,omitempty"`
	OperatorVersion string          `json:"operator_version"`
	ReconcileID     string          `json:"reconcile_id,omitempty"`
	Severity        string          `json:"severity,omitempty"`
}

// Emitter writes audit events to stdout and Redis Streams.
type Emitter interface {
	// EmitAsync enqueues an event for background emission. Returns nil
	// unless the queue is full AND drop-oldest fails, which is rare.
	EmitAsync(ctx context.Context, evt AuditEvent) error

	// EmitSync writes the event synchronously to both sinks. Returns error
	// if either sink fails. Use for fail-closed security events.
	EmitSync(ctx context.Context, evt AuditEvent) error

	// Close flushes the buffer and stops background workers. Blocks up to
	// the configured drain timeout.
	Close(ctx context.Context) error
}

// Config configures the emitter.
type Config struct {
	// RedisClient is used for the Streams sink. If nil, only stdout is used.
	RedisClient *redis.Client
	// StreamKey is the Redis key for the audit stream. Default:
	// "gibson:audit:events".
	StreamKey string
	// MaxLen caps the stream length (approximate). Default 1,000,000.
	MaxLen int64
	// BufferSize bounds the async channel. Default 1000.
	BufferSize int
	// DrainTimeout bounds Close's blocking wait. Default 10s.
	DrainTimeout time.Duration
	// OperatorVersion is stamped onto every event.
	OperatorVersion string
	// Log is the structured logger for the emitter's own diagnostics.
	Log logr.Logger
}

// ErrBufferFull is returned when EmitAsync cannot enqueue an event.
var ErrBufferFull = errors.New("audit buffer full")

type emitter struct {
	cfg    Config
	buf    chan AuditEvent
	done   chan struct{}
	closed chan struct{}
}

// New constructs an Emitter, applying defaults and starting the background
// writer goroutine.
func New(cfg Config) Emitter {
	if cfg.StreamKey == "" {
		cfg.StreamKey = "gibson:audit:events"
	}
	if cfg.MaxLen == 0 {
		cfg.MaxLen = 1_000_000
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 1000
	}
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = 10 * time.Second
	}
	e := &emitter{
		cfg:    cfg,
		buf:    make(chan AuditEvent, cfg.BufferSize),
		done:   make(chan struct{}),
		closed: make(chan struct{}),
	}
	go e.runBackground()
	return e
}

func (e *emitter) EmitAsync(ctx context.Context, evt AuditEvent) error {
	evt = e.finalize(evt)
	select {
	case e.buf <- evt:
		return nil
	default:
		// Queue full. Drop oldest by draining one, then enqueue.
		select {
		case <-e.buf:
			e.cfg.Log.Info("audit buffer full, dropped oldest event")
		default:
		}
		select {
		case e.buf <- evt:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			return ErrBufferFull
		}
	}
}

func (e *emitter) EmitSync(ctx context.Context, evt AuditEvent) error {
	evt = e.finalize(evt)
	return e.write(ctx, evt)
}

func (e *emitter) Close(ctx context.Context) error {
	close(e.done)
	drainCtx, cancel := context.WithTimeout(ctx, e.cfg.DrainTimeout)
	defer cancel()
	select {
	case <-e.closed:
		return nil
	case <-drainCtx.Done():
		return drainCtx.Err()
	}
}

func (e *emitter) finalize(evt AuditEvent) AuditEvent {
	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}
	if evt.OperatorVersion == "" {
		evt.OperatorVersion = e.cfg.OperatorVersion
	}
	if evt.Severity == "" {
		evt.Severity = "INFO"
	}
	return evt
}

func (e *emitter) runBackground() {
	defer close(e.closed)
	for {
		select {
		case <-e.done:
			// Drain remaining events.
			for {
				select {
				case evt := <-e.buf:
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					_ = e.write(ctx, evt)
					cancel()
				default:
					return
				}
			}
		case evt := <-e.buf:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := e.write(ctx, evt); err != nil {
				e.cfg.Log.Error(err, "audit write failed")
			}
			cancel()
		}
	}
}

func (e *emitter) write(ctx context.Context, evt AuditEvent) error {
	// Stdout sink — always runs.
	payload, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("marshal audit event: %w", err)
	}
	_, _ = fmt.Fprintln(os.Stdout, string(payload))

	// Redis sink — optional.
	if e.cfg.RedisClient == nil {
		return nil
	}
	values := map[string]any{
		"timestamp":        evt.Timestamp.Format(time.RFC3339Nano),
		"tenant":           evt.Tenant,
		"subsystem":        evt.Subsystem,
		"action":           evt.Action,
		"operator_version": evt.OperatorVersion,
		"reconcile_id":     evt.ReconcileID,
		"severity":         evt.Severity,
	}
	if len(evt.Before) > 0 {
		values["before"] = string(evt.Before)
	}
	if len(evt.After) > 0 {
		values["after"] = string(evt.After)
	}
	return e.cfg.RedisClient.XAdd(ctx, &redis.XAddArgs{
		Stream: e.cfg.StreamKey,
		MaxLen: e.cfg.MaxLen,
		Approx: true,
		Values: values,
	}).Err()
}

// ---------------------------------------------------------------------------
// SagaEmitter — lightweight, synchronous, prefix-aware audit writer.
//
// Emits lines of the form:
//
//	[audit.tenant-operator] {"ts":"...","action":"saga_step_started",...}
//
// Shape is intentionally aligned with the dashboard's [audit.auth] events
// (same field names, same 512-char errorMessage truncation) so a unified
// Loki pipeline can index both.
//
// SECURITY: Step arguments must never be passed to Emit. Callers supply
// only inputKeys (a slice of field names — no values) and a free-form
// reason string that must not contain secret material.
// ---------------------------------------------------------------------------

const maxErrorMessageChars = 512

// SagaAction enumerates the audit action tokens emitted by the saga runner.
type SagaAction string

const (
	ActionSagaStepStarted   SagaAction = "saga_step_started"
	ActionSagaStepCompleted SagaAction = "saga_step_completed"
	ActionSagaStepFailed    SagaAction = "saga_step_failed"
	ActionSagaStepSkipped   SagaAction = "saga_step_skipped"
)

// SagaOutcome enumerates the outcome tokens, matching the dashboard shape.
type SagaOutcome string

const (
	OutcomeOk          SagaOutcome = "ok"
	OutcomeFailed      SagaOutcome = "failed"
	OutcomeRateLimited SagaOutcome = "rate_limited"
	OutcomeLocked      SagaOutcome = "locked"
)

// SagaAuditEvent is the JSON payload written inside the [audit.tenant-operator]
// prefix. Field names match the dashboard's AuthAuditEvent shape exactly.
type SagaAuditEvent struct {
	// Ts is the ISO 8601 timestamp.
	Ts string `json:"ts"`
	// Action is one of the ActionSaga* constants.
	Action SagaAction `json:"action"`
	// Outcome is one of the Outcome* constants.
	Outcome SagaOutcome `json:"outcome"`
	// UserId is the actor. For operator-driven steps this is always "operator".
	UserId string `json:"userId"`
	// CorrelationId is propagated from the Tenant's annotation when present.
	// Empty string is serialised as an empty string (not omitted) to keep
	// field presence stable for Loki parsing.
	CorrelationId string `json:"correlationId"`
	// TenantId is the Tenant object name.
	TenantId string `json:"tenantId"`
	// Reason is an optional free-form human-readable string.
	// Must not contain secret material.
	Reason string `json:"reason,omitempty"`
	// ErrorCode is a machine-readable error classifier.
	ErrorCode string `json:"errorCode,omitempty"`
	// ErrorMessage is the truncated error string (max 512 chars).
	ErrorMessage string `json:"errorMessage,omitempty"`
	// StepName is the saga step identifier, for debuggability.
	StepName string `json:"stepName"`
	// InputKeys lists the field names present in the step's input — never values.
	InputKeys []string `json:"inputKeys,omitempty"`
}

// SagaEmitter writes SagaAuditEvents to an io.Writer with a configurable prefix.
// The zero value is not useful; construct via NewSagaEmitter.
type SagaEmitter struct {
	prefix     string
	out        io.Writer
	dropWarned atomic.Bool
}

// NewSagaEmitter constructs a SagaEmitter. prefix should be "tenant-operator"
// (the part after "audit."); pass an empty string to use the default.
// out is the destination writer; pass nil to use os.Stdout.
func NewSagaEmitter(prefix string, out io.Writer) *SagaEmitter {
	if prefix == "" {
		prefix = "tenant-operator"
	}
	if out == nil {
		out = os.Stdout
	}
	return &SagaEmitter{prefix: prefix, out: out}
}

// Emit writes a single SagaAuditEvent line. It is synchronous and never
// returns an error to callers — failures are written to stderr so they
// never mask a reconcile result.
func (s *SagaEmitter) Emit(evt SagaAuditEvent) {
	if evt.Ts == "" {
		evt.Ts = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if evt.UserId == "" {
		evt.UserId = "operator"
	}
	if len(evt.ErrorMessage) > maxErrorMessageChars {
		evt.ErrorMessage = evt.ErrorMessage[:maxErrorMessageChars] + "...[truncated]"
	}

	payload, err := json.Marshal(evt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[audit.%s] marshal error: %v\n", s.prefix, err)
		return
	}
	line := fmt.Sprintf("[audit.%s] %s\n", s.prefix, payload)
	if _, werr := fmt.Fprint(s.out, line); werr != nil {
		// Warn to stderr only the first time so log spam is bounded.
		if s.dropWarned.CompareAndSwap(false, true) {
			fmt.Fprintf(os.Stderr, "[audit.%s] write failed (further failures suppressed): %v\n", s.prefix, werr)
		}
	}
}

// truncateErrorMessage trims an error message to the shared 512-char limit.
// Exported so runner.go can use it without re-implementing the constant.
func TruncateErrorMessage(msg string) string {
	if len(msg) <= maxErrorMessageChars {
		return msg
	}
	return msg[:maxErrorMessageChars] + "...[truncated]"
}
