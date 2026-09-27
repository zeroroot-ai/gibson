// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"context"
	"fmt"
	"time"
)

// InvitationEmail carries the fields needed to render a member-invitation
// email. It is the semantic input; rendering (subject/body/HTML) lives here so
// the admin handlers stay free of presentation.
type InvitationEmail struct {
	To        string
	AcceptURL string
	TenantID  string
	Role      string
	ExpiresAt time.Time
}

// InvitationSender renders + sends the invitation accept-link email over an
// underlying Mailer. It satisfies the admin package's InvitationMailer
// interface (structural — no import cycle).
type InvitationSender struct {
	m Mailer
}

// NewInvitationSender wraps a Mailer.
func NewInvitationSender(m Mailer) *InvitationSender {
	return &InvitationSender{m: m}
}

// SendInvitation renders and sends the invitation email.
func (s *InvitationSender) SendInvitation(ctx context.Context, inv InvitationEmail) error {
	if s == nil || s.m == nil {
		return fmt.Errorf("mailer: invitation sender not configured")
	}
	subject := "You've been invited to Gibson"
	text := fmt.Sprintf(
		"You've been invited to join a Gibson workspace as %s.\n\n"+
			"Accept your invitation:\n%s\n\n"+
			"This link expires %s. If you weren't expecting this, you can ignore this email.",
		roleLabel(inv.Role), inv.AcceptURL, inv.ExpiresAt.UTC().Format("2006-01-02 15:04 MST"),
	)
	html := fmt.Sprintf(
		"<p>You've been invited to join a Gibson workspace as <strong>%s</strong>.</p>"+
			"<p><a href=%q>Accept your invitation</a></p>"+
			"<p>This link expires %s. If you weren't expecting this, you can ignore this email.</p>",
		roleLabel(inv.Role), inv.AcceptURL, inv.ExpiresAt.UTC().Format("2006-01-02 15:04 MST"),
	)
	return s.m.Send(ctx, Message{To: inv.To, Subject: subject, Text: text, HTML: html})
}

// InvitationConflictEmail is the input for the notice sent when someone
// invites an address that already belongs to a different tenant (ADR-0093
// decision 1: one tenant per person, emails unique install-wide). It carries
// no accept link: there is nothing to accept. The inviter never sees this —
// InviteMember reports "sent" either way (hosted#203).
type InvitationConflictEmail struct {
	To string
}

// SendInvitationConflict sends the "this address already belongs elsewhere"
// notice. This is the only place the conflict is disclosed, and it goes only
// to the mailbox that owns the address — never to the inviter.
func (s *InvitationSender) SendInvitationConflict(ctx context.Context, c InvitationConflictEmail) error {
	if s == nil || s.m == nil {
		return fmt.Errorf("mailer: invitation sender not configured")
	}
	subject := "About your Gibson invitation"
	text := fmt.Sprintf(
		"Someone tried to invite this email address (%s) to a Gibson workspace, "+
			"but it already belongs to a different one. Gibson accounts belong to "+
			"one workspace at a time.\n\n"+
			"To join the new workspace, use a different email address, or ask the "+
			"current workspace's Owner to remove you first.\n\n"+
			"If you weren't expecting this, you can ignore this email.",
		c.To,
	)
	html := fmt.Sprintf(
		"<p>Someone tried to invite this email address (%s) to a Gibson workspace, "+
			"but it already belongs to a different one. Gibson accounts belong to "+
			"one workspace at a time.</p>"+
			"<p>To join the new workspace, use a different email address, or ask the "+
			"current workspace's Owner to remove you first.</p>"+
			"<p>If you weren't expecting this, you can ignore this email.</p>",
		c.To,
	)
	return s.m.Send(ctx, Message{To: c.To, Subject: subject, Text: text, HTML: html})
}

func roleLabel(role string) string {
	switch role {
	case "admin":
		return "an admin"
	case "writer":
		return "a writer"
	default:
		return "a member"
	}
}
