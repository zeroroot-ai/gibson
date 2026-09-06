// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

// signup_mailer.go — resolves the mail transport for the self-serve signup
// verification flow WITHOUT ever failing daemon startup.
//
// This used to be fatal: buildGRPCServer called mailer.RequireDelivering and,
// when SIGNUP_SELF_SERVE was set, returned an error that stopped the daemon
// from booting on a misconfigured or absent transport. That coupled a mail
// misconfiguration to the availability of the entire platform — every other
// RPC, every other tenant, every other request went down with it.
//
// Mail is the one dependency of the self-serve signup stack that has a safe
// degraded mode: the RPCs that need proof of mailbox control can refuse
// per-call instead of the daemon refusing to boot. See
// api.DaemonServer.RequestEmailVerification, which returns
// codes.FailedPrecondition when no delivering mailer is wired. This function
// therefore never returns an error; it warns once, at WARN, with enough
// detail for an operator to fix it, and leaves the signup mailer unwired.
//
// Spec: gibson#1228 (PR #1228, "require a verified email before
// provisioning" — owner decision: email must not block the daemon from
// booting).
import (
	"context"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
)

// resolveSignupMailer builds the transport the signup verification flow sends
// through, or reports nil when none is usable.
//
// selfServeSignup only changes the wording of the warning (it tells the
// operator whether the gap is currently reachable by a real caller); it never
// changes the outcome — a non-delivering transport is refused either way, and
// neither path is fatal.
func resolveSignupMailer(ctx context.Context, logger *observability.Logger, selfServeSignup bool) *mailer.VerificationSender {
	m, mErr := mailer.NewFromEnv(logger.Slog())
	if mErr == nil {
		mErr = mailer.RequireDelivering(m)
	}
	if mErr != nil {
		if selfServeSignup {
			logger.Warn(ctx, "self-serve signup: no delivering mail transport configured; "+
				"RequestEmailVerification will refuse every call with FailedPrecondition until this is fixed "+
				"(set GIBSON_EMAIL_PROVIDER=smtp and GIBSON_SMTP_HOST)",
				slog.String("error", mErr.Error()))
		} else {
			logger.Warn(ctx, "self-serve signup unavailable: no delivering mail transport for signup verification",
				slog.String("error", mErr.Error()))
		}
		return nil
	}
	return mailer.NewVerificationSender(m)
}
