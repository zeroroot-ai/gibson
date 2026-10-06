// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
)

// owner_welcome.go sends the onboarding email to the owner of a workspace
// that self-serve signup created (gibson#987). An invited person gets this
// runbook in the invitation email. A signup owner never got it, because
// nothing invites the owner of a workspace they created.
//
// The trigger is the first report of a ready tenant from the operator
// (ReportTenantStatus with phase Ready and the data plane ready): the tenant
// is ready and the account exists. The row of the tenant in
// pending_tenant_provisioning carries welcome_owner (set by the signup paths
// only) and welcome_sent_at. A conditional UPDATE claims the send, so a retry
// of the report or a restart of the daemon does not send it twice. A failed
// send releases the claim, and the next report tries again.

// OwnerWelcomeSender sends the onboarding email of a workspace owner.
// mailer.InvitationSender satisfies it.
type OwnerWelcomeSender interface {
	SendOwnerWelcome(ctx context.Context, w mailer.OwnerWelcomeEmail) error
}

// ownerWelcomeConfig is the sender and the two origins of the email.
type ownerWelcomeConfig struct {
	sender OwnerWelcomeSender
	appURL string
	apiURL string
}

// WithOwnerWelcome sets the sender of the owner onboarding email and the two
// origins that the email prints. A nil sender or an empty app URL means the
// install sends no such email; the daemon logs each skipped send.
func (s *DaemonServer) WithOwnerWelcome(sender OwnerWelcomeSender, appURL, apiURL string) *DaemonServer {
	s.ownerWelcome = ownerWelcomeConfig{
		sender: sender,
		appURL: strings.TrimRight(strings.TrimSpace(appURL), "/"),
		apiURL: strings.TrimRight(strings.TrimSpace(apiURL), "/"),
	}
	return s
}

// tenantPhaseReady is the phase that the operator reports for a ready tenant.
const tenantPhaseReady = "Ready"

// welcomeOwnerIfReady sends the onboarding email when the report says the
// tenant is ready. It never fails the report: an error is logged.
func (s *DaemonServer) welcomeOwnerIfReady(ctx context.Context, db *sql.DB, tenantID, phase string, dataPlaneReady bool) {
	if phase != tenantPhaseReady || !dataPlaneReady {
		return
	}
	if err := s.welcomeOwner(ctx, db, tenantID); err != nil {
		s.logger.ErrorContext(ctx, "owner welcome email not sent; the next ready report tries again",
			"tenant_id", tenantID, "error", err.Error())
	}
}

// welcomeOwner claims and sends the onboarding email of the tenant. It does
// nothing for a tenant that is not a signup workspace, or whose email was
// already sent.
func (s *DaemonServer) welcomeOwner(ctx context.Context, db *sql.DB, tenantID string) error {
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return fmt.Errorf("ensure table: %w", err)
	}
	var to string
	err := db.QueryRowContext(ctx, `
		UPDATE pending_tenant_provisioning SET welcome_sent_at = NOW()
		WHERE tenant_id = $1 AND welcome_owner AND welcome_sent_at IS NULL
		RETURNING owner_email`, tenantID).Scan(&to)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("claim the welcome of %s: %w", tenantID, err)
	}

	cfg := s.ownerWelcome
	if cfg.sender == nil || cfg.appURL == "" {
		// The claim stays, so the skip is logged once and not on each report.
		s.logger.WarnContext(ctx, "owner welcome email skipped: no delivering mail transport or no app URL",
			"tenant_id", tenantID)
		return nil
	}
	sendErr := cfg.sender.SendOwnerWelcome(ctx, mailer.OwnerWelcomeEmail{
		To: to, TenantID: tenantID, AppURL: cfg.appURL, APIURL: cfg.apiURL,
	})
	if sendErr == nil {
		s.logger.InfoContext(ctx, "owner welcome email sent", "tenant_id", tenantID)
		return nil
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE pending_tenant_provisioning SET welcome_sent_at = NULL WHERE tenant_id = $1`, tenantID); err != nil {
		return errors.Join(fmt.Errorf("send the welcome of %s: %w", tenantID, sendErr),
			fmt.Errorf("release the claim: %w", err))
	}
	return fmt.Errorf("send the welcome of %s: %w", tenantID, sendErr)
}
