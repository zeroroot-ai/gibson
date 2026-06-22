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
