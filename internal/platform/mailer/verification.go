// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package mailer — verification.go
//
// The two messages the signup verification flow can send.
//
// Both are rendered and sent DAEMON-SIDE, deliberately. The daemon mints the
// token and is the only component that ever holds its raw value; if the web
// tier composed the mail, the raw token would have to travel back out to it,
// re-creating the privilege that was moved off the web tier in the first place.
//
// The two branches also exist to keep the request response uninformative: an
// address that already has an account and one that does not both cause exactly
// one lookup and exactly one send, so the caller cannot tell them apart. What
// differs is only what lands in the mailbox — which is where the person
// entitled to know actually is.
package mailer

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
)

// VerificationEmail is the input for the "verify your email address" message.
// ContinueURL already carries the raw token; it is the only place that value
// legitimately appears.
type VerificationEmail struct {
	To             string
	ContinueURL    string
	ExpiresInHours int
}

// AccountExistsEmail is the input for the notice sent when someone tries to
// sign up with an address that already has an account.
//
// It carries NO token and NO continue link, because there is nothing to
// continue to: the signup attempt is over. The recipient is pointed at sign-in
// and at the IdP's own password reset, which proves mailbox control itself. A
// signup form never gets to set a credential on an existing account.
type AccountExistsEmail struct {
	To            string
	SignInURL     string
	PasswordReset string
}

// VerificationSender renders and sends the signup verification messages.
type VerificationSender struct {
	m Mailer
}

// NewVerificationSender wraps a Mailer.
func NewVerificationSender(m Mailer) *VerificationSender {
	return &VerificationSender{m: m}
}

// SendSignupVerification sends the verification link.
//
// Copy is carried over verbatim from the dashboard template it replaces
// (src/lib/email/templates/verify.ts) so the message a customer receives does
// not change with the transport.
func (s *VerificationSender) SendSignupVerification(ctx context.Context, v VerificationEmail) error {
	if s == nil || s.m == nil {
		return errors.New("mailer: verification sender not configured")
	}
	if v.To == "" || v.ContinueURL == "" {
		return errors.New("mailer: verification requires recipient and continue URL")
	}
	hours := v.ExpiresInHours
	if hours <= 0 {
		hours = 24
	}

	subject := "Verify your email address"
	text := strings.Join([]string{
		"Hi,",
		"",
		fmt.Sprintf("Please verify the email address (%s) you used to sign up for Gibson by opening the link below:", v.To),
		"",
		v.ContinueURL,
		"",
		fmt.Sprintf("This link expires in %d %s.", hours, plural(hours, "hour")),
		"",
		"If you didn't create a Gibson account, you can ignore this message, no account will be created without verification.",
		"",
		"The Gibson team",
	}, "\n")

	htmlBody := strings.Join([]string{
		`<!doctype html>`,
		`<html lang="en">`,
		`<body style="margin:0;padding:24px;background:#0b0b0f;color:#e6e6ea;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">`,
		`<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:560px;margin:0 auto;background:#15151c;border-radius:8px;padding:32px;">`,
		`<tr><td>`,
		`<h1 style="margin:0 0 16px;font-size:20px;line-height:1.3;color:#ffffff;">Verify your email address</h1>`,
		`<p style="margin:0 0 16px;font-size:14px;line-height:1.5;color:#c5c5cc;">Please verify the email address <strong style="color:#ffffff;">` + html.EscapeString(v.To) + `</strong> you used to sign up for Gibson.</p>`,
		`<p style="margin:0 0 24px;"><a href="` + html.EscapeString(v.ContinueURL) + `" style="display:inline-block;padding:10px 16px;background:#6366f1;color:#ffffff;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;">Verify email</a></p>`,
		`<p style="margin:0 0 8px;font-size:12px;color:#9999a3;">Or paste this link in your browser:</p>`,
		`<p style="margin:0 0 24px;font-size:12px;color:#c5c5cc;word-break:break-all;">` + html.EscapeString(v.ContinueURL) + `</p>`,
		fmt.Sprintf(`<p style="margin:0 0 8px;font-size:12px;color:#9999a3;">This link expires in %d %s.</p>`, hours, plural(hours, "hour")),
		`<p style="margin:0;font-size:12px;color:#9999a3;">If you didn't create a Gibson account you can ignore this message, no account will be created without verification.</p>`,
		`</td></tr>`,
		`</table>`,
		`</body>`,
		`</html>`,
	}, "")

	if err := s.m.Send(ctx, Message{To: v.To, Subject: subject, Text: text, HTML: htmlBody}); err != nil {
		return fmt.Errorf("mailer: send verification: %w", err)
	}
	return nil
}

// SendAccountExists sends the "this address already has an account" notice.
func (s *VerificationSender) SendAccountExists(ctx context.Context, a AccountExistsEmail) error {
	if s == nil || s.m == nil {
		return errors.New("mailer: verification sender not configured")
	}
	if a.To == "" {
		return errors.New("mailer: account-exists notice requires recipient")
	}

	subject := "About your Gibson account"
	lines := []string{
		"Hi,",
		"",
		fmt.Sprintf("Someone tried to create a Gibson account with this email address (%s). An account already exists for it, so no new account was created and nothing about your existing account was changed.", a.To),
		"",
	}
	if a.SignInURL != "" {
		lines = append(lines, "If that was you, sign in here:", "", a.SignInURL, "")
	}
	if a.PasswordReset != "" {
		lines = append(lines, "If you've forgotten your password, reset it here:", "", a.PasswordReset, "")
	}
	lines = append(lines,
		"If it wasn't you, no action is needed.",
		"",
		"The Gibson team",
	)
	text := strings.Join(lines, "\n")

	var b strings.Builder
	b.WriteString(`<!doctype html><html lang="en">`)
	b.WriteString(`<body style="margin:0;padding:24px;background:#0b0b0f;color:#e6e6ea;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">`)
	b.WriteString(`<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:560px;margin:0 auto;background:#15151c;border-radius:8px;padding:32px;"><tr><td>`)
	b.WriteString(`<h1 style="margin:0 0 16px;font-size:20px;line-height:1.3;color:#ffffff;">About your Gibson account</h1>`)
	b.WriteString(`<p style="margin:0 0 16px;font-size:14px;line-height:1.5;color:#c5c5cc;">Someone tried to create a Gibson account with this email address (<strong style="color:#ffffff;">`)
	b.WriteString(html.EscapeString(a.To))
	b.WriteString(`</strong>). An account already exists for it, so no new account was created and nothing about your existing account was changed.</p>`)
	if a.SignInURL != "" {
		b.WriteString(`<p style="margin:0 0 16px;"><a href="` + html.EscapeString(a.SignInURL) + `" style="display:inline-block;padding:10px 16px;background:#6366f1;color:#ffffff;border-radius:6px;text-decoration:none;font-weight:600;font-size:14px;">Sign in</a></p>`)
	}
	if a.PasswordReset != "" {
		b.WriteString(`<p style="margin:0 0 16px;font-size:12px;color:#9999a3;">Forgotten your password? <a href="` + html.EscapeString(a.PasswordReset) + `" style="color:#c5c5cc;">Reset it here</a>.</p>`)
	}
	b.WriteString(`<p style="margin:0;font-size:12px;color:#9999a3;">If it wasn't you, no action is needed.</p>`)
	b.WriteString(`</td></tr></table></body></html>`)

	if err := s.m.Send(ctx, Message{To: a.To, Subject: subject, Text: text, HTML: b.String()}); err != nil {
		return fmt.Errorf("mailer: send account-exists notice: %w", err)
	}
	return nil
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}
