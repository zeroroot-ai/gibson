// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
)

// MFAResetEmail carries the fields needed to render the "your two-factor
// authentication was reset" message (hosted#206). It goes to the RESET
// USER'S OWN address only — never to the administrator who pressed the
// button, who receives nothing that grants access to the account.
type MFAResetEmail struct {
	To        string
	SignInURL string
}

// MFAResetSender renders + sends the MFA-reset notice over an underlying
// Mailer. It satisfies the UserService handler's narrow mailer interface
// (structural — no import cycle).
type MFAResetSender struct {
	m Mailer
}

// NewMFAResetSender wraps a Mailer.
func NewMFAResetSender(m Mailer) *MFAResetSender {
	return &MFAResetSender{m: m}
}

// SendMFAReset renders and sends the MFA-reset notice. It carries no code and
// no token: an administrator already cleared the account's registered
// factors and revoked its sessions, so the account's next sign-in attempt is
// what prompts re-enrollment — the ordinary sign-in link is the whole
// capability, and it grants nothing beyond what sign-in already grants.
func (s *MFAResetSender) SendMFAReset(ctx context.Context, e MFAResetEmail) error {
	if s == nil || s.m == nil {
		return errors.New("mailer: MFA reset sender not configured")
	}
	if e.To == "" {
		return errors.New("mailer: MFA reset notice requires a recipient")
	}

	subject := "Your two-factor authentication was reset"
	lines := []string{
		"Hi,",
		"",
		"An administrator reset the two-factor authentication (2FA) on your account.",
		"Your active sessions were signed out and your authenticator app, security keys,",
		"and passkeys were removed.",
		"",
	}
	if e.SignInURL != "" {
		lines = append(lines, "Sign in to set up 2FA again:", "", e.SignInURL, "")
	}
	lines = append(lines,
		"If you did not expect this, contact your workspace administrator.",
		"",
		"The Gibson team",
	)
	text := strings.Join(lines, "\n")

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en">`)
	b.WriteString(`<body style="margin:0;padding:24px;background:#0b0b0f;color:#e6e6ea;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">`)
	b.WriteString(`<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:560px;margin:0 auto;background:#15151c;border-radius:8px;padding:32px;"><tr><td>`)
	b.WriteString(`<h1 style="margin:0 0 16px;font-size:20px;line-height:1.3;color:#ffffff;">Your two-factor authentication was reset</h1>`)
	b.WriteString(`<p style="margin:0 0 16px;font-size:14px;line-height:1.5;color:#c5c5cc;">An administrator reset the two-factor authentication (2FA) on your account. Your active sessions were signed out and your authenticator app, security keys, and passkeys were removed.</p>`)
	if e.SignInURL != "" {
		b.WriteString(`<p style="margin:0 0 24px;"><a href="` + html.EscapeString(e.SignInURL) + `" style="display:inline-block;padding:10px 16px;background:#6366f1;color:#ffffff;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;">Sign in</a></p>`)
	}
	b.WriteString(`<p style="margin:0;font-size:12px;color:#9999a3;">If you did not expect this, contact your workspace administrator.</p>`)
	b.WriteString(`</td></tr></table></body></html>`)

	if err := s.m.Send(ctx, Message{To: e.To, Subject: subject, Text: text, HTML: b.String()}); err != nil {
		return fmt.Errorf("mailer: send MFA reset notice: %w", err)
	}
	return nil
}
