// Package provisioner — signup_pipeline.go
//
// SignupPipeline is the Redis Streams consumer group that drives the async
// tenant provisioning flow.
//
// Better Auth migration changes:
//   - The "org" step has been removed. Better Auth creates the user + organisation
//     in the dashboard before calling InitiateSignup. The pipeline now starts
//     directly with the FGA tuple write.
//   - EventSignupRequested now routes to handleFGA (not handleOrg).
//   - EventSignupOrgCreated has been removed.
//   - The store field is now typed as ProvisioningStateStore (interface) rather
//     than *SignupStateStore (concrete Redis type), enabling the Postgres backend.
//
// Responsibilities:
//   - Create the consumer group on first startup (XGROUP CREATE … MKSTREAM).
//   - Read events in a tight loop via XREADGROUP BLOCK.
//   - Dispatch by event_type to handleFGA / handleProvision.
//   - On handler success: XACK.
//   - On handler failure: increment the per-step retry counter in Postgres;
//     if retries < maxRetries sleep exponentially (2s, 4s, 8s) then retry;
//     if retries exhausted: call failSignup (sets state=failed, emits
//     signup.failed, XACKs the message so it leaves the PEL).
//
// All business logic lives in signup_handlers.go.
package provisioner

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// maxRetries is the maximum number of handler invocations per message before
// the pipeline gives up and emits signup.failed.
const maxRetries = 3

// SignupPipeline consumes the signup:events:stream consumer group and routes
// each event to the appropriate step handler. It is safe to run concurrently
// — each pod uses its hostname as the consumer name, giving pod-level
// ownership of the Pending Entries List (PEL).
type SignupPipeline struct {
	redis    goredis.UniversalClient
	authz    authz.Authorizer
	prov     *Provisioner
	store    ProvisioningStateStore
	logger   *slog.Logger
	consumer string // os.Hostname() — unique per pod

	// retryBaseDelay is the base for exponential backoff between retry attempts.
	// Defaults to 1 second in production; set to a short value in tests.
	retryBaseDelay time.Duration

	// blockDuration is the BLOCK timeout passed to XREADGROUP.
	// Defaults to 5 seconds in production; set shorter in tests so context
	// cancellation is checked more frequently.
	blockDuration time.Duration
}

// NewSignupPipeline constructs a SignupPipeline.
//
// All parameters must be non-nil. Use os.Hostname() for the consumer name so
// each pod has an independent PEL; the pipeline falls back to "unknown" when
// the hostname cannot be determined.
//
// The store parameter accepts any ProvisioningStateStore implementation
// (PgProvisioningStore for Postgres-backed production usage, or a test double).
func NewSignupPipeline(
	redisClient goredis.UniversalClient,
	az authz.Authorizer,
	prov *Provisioner,
	store ProvisioningStateStore,
	logger *slog.Logger,
) *SignupPipeline {
	if redisClient == nil {
		panic("signup_pipeline: redisClient must not be nil")
	}
	if az == nil {
		panic("signup_pipeline: authz must not be nil")
	}
	if prov == nil {
		panic("signup_pipeline: provisioner must not be nil")
	}
	if store == nil {
		panic("signup_pipeline: store must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return &SignupPipeline{
		redis:          redisClient,
		authz:          az,
		prov:           prov,
		store:          store,
		logger:         logger.With("component", "signup_pipeline"),
		consumer:       hostname,
		retryBaseDelay: 1 * time.Second,
		blockDuration:  5 * time.Second,
	}
}

// Start enters the consumer loop. It blocks until ctx is cancelled, then
// returns nil. Any fatal initialisation error is returned immediately.
//
// Callers should launch Start in a goroutine and cancel the context to stop.
func (p *SignupPipeline) Start(ctx context.Context) error {
	// Ensure the consumer group exists. MKSTREAM creates the stream if absent.
	// BUSYGROUP means the group already exists — tolerate that silently.
	err := p.redis.XGroupCreateMkStream(ctx, SignupStreamKey, SignupConsumerGroup, "$").Err()
	if err != nil && !isBusyGroupError(err) {
		return fmt.Errorf("signup_pipeline: create consumer group: %w", err)
	}

	p.logger.InfoContext(ctx, "signup pipeline started",
		slog.String("stream", SignupStreamKey),
		slog.String("group", SignupConsumerGroup),
		slog.String("consumer", p.consumer),
	)

	for {
		// Check for context cancellation before blocking.
		select {
		case <-ctx.Done():
			p.logger.InfoContext(ctx, "signup pipeline stopping (context cancelled)")
			return nil
		default:
		}

		// XREADGROUP BLOCK — returns empty slice on timeout, not an error.
		// blockDuration defaults to 5s in production; tests set it shorter.
		streams, err := p.redis.XReadGroup(ctx, &goredis.XReadGroupArgs{
			Group:    SignupConsumerGroup,
			Consumer: p.consumer,
			Streams:  []string{SignupStreamKey, ">"},
			Count:    10,
			Block:    p.blockDuration,
		}).Result()

		if err != nil {
			if errors.Is(err, goredis.Nil) || isContextError(err) {
				// Timeout (Nil) or context cancelled — loop to re-check ctx.Done().
				continue
			}
			p.logger.ErrorContext(ctx, "signup pipeline: XREADGROUP error",
				slog.String("error", err.Error()),
			)
			// Brief pause before retry to avoid tight error loops.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
			continue
		}

		for _, stream := range streams {
			for _, msg := range stream.Messages {
				p.processMessage(ctx, msg)
			}
		}
	}
}

// processMessage dispatches a single stream message to the appropriate handler,
// manages retry state, and XACKs on terminal outcomes (success or exhausted retries).
func (p *SignupPipeline) processMessage(ctx context.Context, msg goredis.XMessage) {
	eventType, _ := msg.Values["event_type"].(string)
	userID, _ := msg.Values["user_id"].(string)

	if userID == "" {
		// Malformed message — XACK to drain it from the PEL.
		p.logger.WarnContext(ctx, "signup pipeline: message missing user_id, discarding",
			slog.String("msg_id", msg.ID),
			slog.String("event_type", eventType),
		)
		_ = p.redis.XAck(ctx, SignupStreamKey, SignupConsumerGroup, msg.ID).Err()
		return
	}

	p.logger.InfoContext(ctx, "signup pipeline: processing message",
		slog.String("msg_id", msg.ID),
		slog.String("event_type", eventType),
		slog.String("user_id", userID),
	)

	// Determine which step counter to track for this event type.
	stepName := eventTypeToStep(SignupEventType(eventType))

	// Dispatch to handler.
	var handlerErr error
	switch SignupEventType(eventType) {
	case EventSignupRequested:
		// Better Auth has already created user + org in the dashboard.
		// Route directly to FGA tuple write.
		handlerErr = p.handleFGA(ctx, msg)
	case EventSignupFGAWritten:
		handlerErr = p.handleProvision(ctx, msg)
	default:
		// Unknown or terminal event type — XACK and move on.
		p.logger.WarnContext(ctx, "signup pipeline: unhandled event type, discarding",
			slog.String("msg_id", msg.ID),
			slog.String("event_type", eventType),
		)
		_ = p.redis.XAck(ctx, SignupStreamKey, SignupConsumerGroup, msg.ID).Err()
		return
	}

	if handlerErr == nil {
		// Success — acknowledge the message.
		if err := p.redis.XAck(ctx, SignupStreamKey, SignupConsumerGroup, msg.ID).Err(); err != nil {
			p.logger.WarnContext(ctx, "signup pipeline: XACK failed after successful handler",
				slog.String("msg_id", msg.ID),
				slog.String("user_id", userID),
				slog.String("error", err.Error()),
			)
		}
		return
	}

	// Handler failed. Increment and check the retry counter.
	p.logger.WarnContext(ctx, "signup pipeline: handler failed",
		slog.String("msg_id", msg.ID),
		slog.String("user_id", userID),
		slog.String("step", stepName),
		slog.String("error", handlerErr.Error()),
	)

	if stepName == "" {
		// No step counter for this event type — fail immediately.
		_ = p.failSignup(ctx, msg.ID, userID, "unknown", handlerErr)
		return
	}

	// Retry loop: attempt up to maxRetries total (including the already-failed
	// first attempt). All retries happen inline within processMessage; the
	// message remains in the PEL throughout and is XACKed only on terminal
	// outcome (success or exhaustion).
	lastErr := handlerErr
	for attempt := 1; attempt <= maxRetries; attempt++ {
		retries, incrErr := p.store.IncrRetry(ctx, userID, stepName)
		if incrErr != nil {
			p.logger.ErrorContext(ctx, "signup pipeline: failed to increment retry counter",
				slog.String("user_id", userID),
				slog.String("step", stepName),
				slog.String("error", incrErr.Error()),
			)
			// Fallback: treat as final failure.
			_ = p.failSignup(ctx, msg.ID, userID, stepName, lastErr)
			return
		}

		if retries > maxRetries {
			p.logger.ErrorContext(ctx, "signup pipeline: retries exhausted, failing signup",
				slog.String("user_id", userID),
				slog.String("step", stepName),
				slog.Int("retries", retries),
			)
			_ = p.failSignup(ctx, msg.ID, userID, stepName, lastErr)
			return
		}

		// Exponential backoff: base * 2^attempt (1×, 2×, 4×, …).
		backoff := time.Duration(1<<uint(attempt)) * p.retryBaseDelay
		p.logger.InfoContext(ctx, "signup pipeline: retrying after backoff",
			slog.String("user_id", userID),
			slog.String("step", stepName),
			slog.Int("attempt", attempt),
			slog.Duration("backoff", backoff),
		)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		// Re-dispatch directly (the message is still in the PEL).
		var retryErr error
		switch SignupEventType(eventType) {
		case EventSignupRequested:
			retryErr = p.handleFGA(ctx, msg)
		case EventSignupFGAWritten:
			retryErr = p.handleProvision(ctx, msg)
		}

		if retryErr == nil {
			if err := p.redis.XAck(ctx, SignupStreamKey, SignupConsumerGroup, msg.ID).Err(); err != nil {
				p.logger.WarnContext(ctx, "signup pipeline: XACK failed after retry success",
					slog.String("msg_id", msg.ID),
					slog.String("error", err.Error()),
				)
			}
			return
		}
		lastErr = retryErr
	}

	// All retries exhausted.
	_ = p.failSignup(ctx, msg.ID, userID, stepName, lastErr)
}

// failSignup sets signup state to failed, emits signup.failed, and XACKs the
// message to remove it from the PEL. All errors are logged; the function never
// panics.
func (p *SignupPipeline) failSignup(ctx context.Context, msgID, userID, step string, cause error) error {
	errMsg := cause.Error()

	p.logger.ErrorContext(ctx, "signup pipeline: signup failed",
		slog.String("user_id", userID),
		slog.String("step", step),
		slog.String("error", errMsg),
	)

	// Update state to failed.
	if storeErr := p.store.SetFailed(ctx, userID, step, errMsg); storeErr != nil {
		p.logger.ErrorContext(ctx, "signup pipeline: failed to set state=failed",
			slog.String("user_id", userID),
			slog.String("error", storeErr.Error()),
		)
	}

	// Emit signup.failed event.
	_, xaddErr := p.redis.XAdd(ctx, &goredis.XAddArgs{
		Stream: SignupStreamKey,
		Values: map[string]interface{}{
			"event_type":   string(EventSignupFailed),
			"user_id":      userID,
			"step":         step,
			"error":        errMsg,
			"timestamp_ms": fmt.Sprintf("%d", time.Now().UnixMilli()),
		},
	}).Result()
	if xaddErr != nil {
		p.logger.ErrorContext(ctx, "signup pipeline: failed to emit signup.failed event",
			slog.String("user_id", userID),
			slog.String("error", xaddErr.Error()),
		)
	}

	// XACK to drain the message from the PEL.
	if ackErr := p.redis.XAck(ctx, SignupStreamKey, SignupConsumerGroup, msgID).Err(); ackErr != nil {
		p.logger.ErrorContext(ctx, "signup pipeline: XACK failed after failSignup",
			slog.String("msg_id", msgID),
			slog.String("error", ackErr.Error()),
		)
	}

	return cause
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// eventTypeToStep returns the step name ("fga", "provision") that corresponds
// to an event type, for retry counter tracking.
// Returns "" for events that have no retry counter.
//
// The "org" step has been removed: Better Auth handles organisation creation in
// the dashboard, so EventSignupRequested now maps to "fga".
func eventTypeToStep(et SignupEventType) string {
	switch et {
	case EventSignupRequested:
		return "fga"
	case EventSignupFGAWritten:
		return "provision"
	default:
		return ""
	}
}

// isBusyGroupError returns true when the Redis error indicates the consumer
// group already exists (BUSYGROUP). This is expected on daemon restart.
func isBusyGroupError(err error) bool {
	if err == nil {
		return false
	}
	return len(err.Error()) >= 9 && err.Error()[:9] == "BUSYGROUP"
}

// isContextError returns true for errors that indicate context cancellation or
// deadline exceeded, so the loop can distinguish them from real Redis errors.
func isContextError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
