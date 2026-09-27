// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
)

// mfaResetSender is the narrow mail surface UserService.ResetUserMFA uses. A
// structural interface (rather than *mailer.MFAResetSender directly) keeps
// this package free of a hard dependency on the mailer package's concrete
// type in tests, matching signupVerificationSender's shape.
type mfaResetSender interface {
	SendMFAReset(ctx context.Context, e mailer.MFAResetEmail) error
}

// WithMFAResetMailer wires the sender ResetUserMFA uses to notify a reset
// user at their own address. Optional: a nil sender means ResetUserMFA still
// performs the reset but reports notified=false.
func (s *DaemonServer) WithMFAResetMailer(m mfaResetSender) *DaemonServer {
	s.mfaResetMailer = m
	return s
}

// mfaResetSignInURL is the link emailed after a reset. It reuses the same
// product-surface origin (GIBSON_APP_URL / s.appURL) and route as the signup
// flow's own sign-in link — the two links target the exact same page — so
// there is exactly one place that knows the dashboard serves sign-in at
// "/login".
func (s *DaemonServer) mfaResetSignInURL() string {
	return s.signupSignInURL()
}
