// Package provisioner — signup_handlers.go
//
// Step handlers for the signup pipeline. Each handler corresponds to one event
// type in the signup:events:stream consumer group.
//
// Handlers are private methods on *SignupPipeline and are called exclusively
// from signup_pipeline.go's processMessage loop.
//
// Better Auth migration changes:
//   - handleOrg has been removed. Better Auth creates the user organisation in
//     the dashboard before calling InitiateSignup, so the daemon no longer needs
//     to perform org creation.
//   - handleFGA now consumes EventSignupRequested (was EventSignupOrgCreated).
//     The idempotency check is unchanged; the step_statuses["fga"] guard still
//     prevents double-execution on retry.
//   - handleProvision is unchanged.
//
// Design rules:
//   - Each handler is idempotent: it checks step_statuses[step]=="completed"
//     before executing any external call and returns nil immediately if the
//     step is already done. This makes retries safe.
package provisioner

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"context"

	goredis "github.com/redis/go-redis/v9"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// Ensure errors is used (it is — via errors.Is in extractMsgFields callers).
var _ = errors.New

// ---------------------------------------------------------------------------
// handleFGA — EventSignupRequested
// ---------------------------------------------------------------------------

// handleFGA writes the user:userId admin tenant:tenantId FGA tuple. On success
// it emits EventSignupFGAWritten.
//
// This handler previously consumed EventSignupOrgCreated. Following the Better
// Auth migration it consumes EventSignupRequested directly, since the org is
// now created in the dashboard before the daemon pipeline starts.
//
// Idempotency: FGA Write is idempotent — re-writing an existing tuple is a
// no-op. The step_statuses check is an additional fast-path guard.
func (p *SignupPipeline) handleFGA(ctx context.Context, msg goredis.XMessage) error {
	userID, tenantID, _, _, err := extractMsgFields(ctx, p, msg)
	if err != nil {
		return err
	}

	// --- Idempotency check ---
	state, err := p.store.Get(ctx, userID)
	if err != nil {
		return fmt.Errorf("handleFGA: read state for user %q: %w", userID, err)
	}
	if state != nil && state.StepStatuses["fga"] == "completed" {
		p.logger.InfoContext(ctx, "handleFGA: fga step already completed, skipping",
			slog.String("user_id", userID),
		)
		return p.emitEvent(ctx, EventSignupFGAWritten, userID, tenantID)
	}

	p.logger.InfoContext(ctx, "handleFGA: writing FGA admin tuple",
		slog.String("user_id", userID),
		slog.String("tenant_id", tenantID),
	)

	// Mark step as running.
	_ = p.store.UpdateField(ctx, userID, "current_step", "fga")
	_ = p.store.UpdateField(ctx, userID, "step_status_fga", "running")

	// --- Write FGA tuple ---
	tuple := authz.Tuple{
		User:     fmt.Sprintf("user:%s", userID),
		Relation: "admin",
		Object:   fmt.Sprintf("tenant:%s", tenantID),
	}
	if writeErr := p.authz.Write(ctx, []authz.Tuple{tuple}); writeErr != nil {
		return fmt.Errorf("handleFGA: write FGA tuple: %w", writeErr)
	}

	// --- Update state ---
	_ = p.store.UpdateField(ctx, userID, "step_status_fga", "completed")

	p.logger.InfoContext(ctx, "handleFGA: fga step completed",
		slog.String("user_id", userID),
	)

	// --- Emit next event ---
	return p.emitEvent(ctx, EventSignupFGAWritten, userID, tenantID)
}

// ---------------------------------------------------------------------------
// handleProvision — EventSignupFGAWritten
// ---------------------------------------------------------------------------

// handleProvision calls Provisioner.ProvisionTenant to create the Langfuse
// project, mint the initial API key, and set tier limits. On success it emits
// EventSignupCompleted and transitions the signup state to active.
//
// Idempotency: ProvisionTenant itself is idempotent (step-skipping via Redis
// HASH). The step_statuses check is an additional fast-path guard.
func (p *SignupPipeline) handleProvision(ctx context.Context, msg goredis.XMessage) error {
	userID, tenantID, plan, companyName, err := extractMsgFields(ctx, p, msg)
	if err != nil {
		return err
	}

	// --- Idempotency check ---
	state, err := p.store.Get(ctx, userID)
	if err != nil {
		return fmt.Errorf("handleProvision: read state for user %q: %w", userID, err)
	}

	var ownerEmail string
	if state != nil {
		ownerEmail = state.Email
		if state.StepStatuses["provision"] == "completed" {
			p.logger.InfoContext(ctx, "handleProvision: provision step already completed, skipping",
				slog.String("user_id", userID),
			)
			// SetCompleted is idempotent.
			_ = p.store.SetCompleted(ctx, userID)
			return p.emitEvent(ctx, EventSignupCompleted, userID, tenantID)
		}
	}

	p.logger.InfoContext(ctx, "handleProvision: provisioning tenant resources",
		slog.String("user_id", userID),
		slog.String("tenant_id", tenantID),
		slog.String("plan", plan),
	)

	// Mark step as running.
	_ = p.store.UpdateField(ctx, userID, "current_step", "provision")
	_ = p.store.UpdateField(ctx, userID, "step_status_provision", "running")

	// --- Provision tenant resources ---
	if _, provErr := p.prov.ProvisionTenant(ctx, ProvisionRequest{
		TenantID:    tenantID,
		DisplayName: companyName,
		Tier:        plan,
		OwnerEmail:  ownerEmail,
		OwnerUserID: userID,
	}); provErr != nil {
		return fmt.Errorf("handleProvision: ProvisionTenant: %w", provErr)
	}

	// --- Update state to completed ---
	_ = p.store.UpdateField(ctx, userID, "step_status_provision", "completed")
	if completeErr := p.store.SetCompleted(ctx, userID); completeErr != nil {
		p.logger.WarnContext(ctx, "handleProvision: failed to set signup state=active",
			slog.String("user_id", userID),
			slog.String("error", completeErr.Error()),
		)
	}

	p.logger.InfoContext(ctx, "handleProvision: provision step completed",
		slog.String("user_id", userID),
		slog.String("tenant_id", tenantID),
	)

	// --- Emit completion event ---
	return p.emitEvent(ctx, EventSignupCompleted, userID, tenantID)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// extractMsgFields reads userId, tenantId, plan, and companyName from the
// stream message. It falls back to the signup state for fields not present in
// the message (e.g. plan/companyName are only in the state).
//
// Returns an error when userID or tenantID cannot be determined.
func extractMsgFields(ctx context.Context, p *SignupPipeline, msg goredis.XMessage) (userID, tenantID, plan, companyName string, err error) {
	userID, _ = msg.Values["user_id"].(string)
	tenantID, _ = msg.Values["tenant_id"].(string)

	if userID == "" {
		return "", "", "", "", fmt.Errorf("extractMsgFields: message %q missing user_id", msg.ID)
	}

	// plan and companyName live in the signup state, not in every event.
	state, stateErr := p.store.Get(ctx, userID)
	if stateErr != nil {
		return "", "", "", "", fmt.Errorf("extractMsgFields: read state for user %q: %w", userID, stateErr)
	}
	if state == nil {
		return "", "", "", "", fmt.Errorf("extractMsgFields: signup state not found for user %q", userID)
	}

	if tenantID == "" {
		tenantID = state.TenantID
	}
	plan = state.Plan
	companyName = state.CompanyName

	if tenantID == "" {
		return "", "", "", "", fmt.Errorf("extractMsgFields: cannot determine tenant_id for user %q", userID)
	}
	return userID, tenantID, plan, companyName, nil
}

// emitEvent appends a signup pipeline event to the signup:events:stream.
// Used by all handlers to emit the next step event after success.
func (p *SignupPipeline) emitEvent(ctx context.Context, et SignupEventType, userID, tenantID string) error {
	_, err := p.redis.XAdd(ctx, &goredis.XAddArgs{
		Stream: SignupStreamKey,
		Values: map[string]interface{}{
			"event_type":   string(et),
			"user_id":      userID,
			"tenant_id":    tenantID,
			"timestamp_ms": fmt.Sprintf("%d", time.Now().UnixMilli()),
		},
	}).Result()
	if err != nil {
		return fmt.Errorf("emitEvent %q for user %q: %w", et, userID, err)
	}
	return nil
}
