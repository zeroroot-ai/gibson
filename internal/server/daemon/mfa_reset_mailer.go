// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// mfa_reset_mailer.go — resolves the mail transport for
// UserService.ResetUserMFA's "your 2FA was reset" notice (hosted#206),
// WITHOUT ever failing daemon startup.
//
// Mirrors signup_mailer.go's resolveSignupMailer: a mail misconfiguration
// must not take down the whole daemon. Unlike signup, MFA reset is not gated
// by any signup-policy knob — it is core tenant-admin functionality on every
// profile, self-hosted included — so this is resolved unconditionally in
// buildGRPCServer, not inside the signup-only wiring block. When no
// delivering transport is configured, ResetUserMFA still performs the reset
// (sessions revoked, factors cleared) and reports notified=false in its
// response, so the caller knows to tell the target out-of-band.
import (
	"context"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
)

// resolveMFAResetMailer builds the transport ResetUserMFA sends its notice
// through, or reports nil when none is usable.
func resolveMFAResetMailer(ctx context.Context, logger *observability.Logger) *mailer.MFAResetSender {
	m, mErr := mailer.NewFromEnv(logger.Slog())
	if mErr == nil {
		mErr = mailer.RequireDelivering(m)
	}
	if mErr != nil {
		logger.Warn(ctx, "ResetUserMFA: no delivering mail transport configured; "+
			"the reset notice will not be sent (the reset itself still completes; "+
			"notified=false in the response) — set GIBSON_EMAIL_PROVIDER=smtp and GIBSON_SMTP_HOST",
			slog.String("error", mErr.Error()))
		return nil
	}
	return mailer.NewMFAResetSender(m)
}
