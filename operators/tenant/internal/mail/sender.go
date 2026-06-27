// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package mail sends tenant lifecycle emails (invitations, welcomes).
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"text/template"
	"time"
)

// Sender sends transactional lifecycle emails.
type Sender interface {
	SendInvitation(ctx context.Context, msg InvitationMessage) error
	SendWelcome(ctx context.Context, msg WelcomeMessage) error
}

// Config holds SMTP configuration.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	UseTLS   bool
	Timeout  time.Duration
}

// InvitationMessage is the data passed to the invitation template.
type InvitationMessage struct {
	To           string
	TenantName   string
	InviterEmail string
	AcceptURL    string
	ExpiresAt    time.Time
}

// WelcomeMessage is the data passed to the welcome template.
type WelcomeMessage struct {
	To           string
	TenantName   string
	DashboardURL string
}

const invitationTemplate = `Subject: You've been invited to {{.TenantName}} on Gibson
From: {{.From}}
To: {{.To}}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Hello,

{{.Message.InviterEmail}} has invited you to join {{.Message.TenantName}} on Gibson.

Accept your invitation: {{.Message.AcceptURL}}

This invitation expires at {{.Message.ExpiresAt.Format "2006-01-02 15:04 UTC"}}.

If you weren't expecting this, you can ignore this email.

— The Gibson team
`

const welcomeTemplate = `Subject: Welcome to {{.TenantName}} on Gibson
From: {{.From}}
To: {{.To}}
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Welcome to Gibson.

Your workspace "{{.Message.TenantName}}" is ready.

Open the dashboard: {{.Message.DashboardURL}}

— The Gibson team
`

// SMTPSender is a net/smtp backed Sender.
type SMTPSender struct {
	cfg    Config
	invTpl *template.Template
	welTpl *template.Template
}

// NewSMTPSender validates config and prepares templates.
func NewSMTPSender(cfg Config) (*SMTPSender, error) {
	if cfg.Host == "" || cfg.Port == 0 || cfg.From == "" {
		return nil, fmt.Errorf("mail: Host, Port, From required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	invTpl, err := template.New("inv").Parse(invitationTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse invitation template: %w", err)
	}
	welTpl, err := template.New("wel").Parse(welcomeTemplate)
	if err != nil {
		return nil, fmt.Errorf("parse welcome template: %w", err)
	}
	return &SMTPSender{cfg: cfg, invTpl: invTpl, welTpl: welTpl}, nil
}

// SendInvitation implements Sender.
func (s *SMTPSender) SendInvitation(_ context.Context, msg InvitationMessage) error {
	return s.send(msg.To, s.invTpl, map[string]any{
		"From":    s.cfg.From,
		"To":      msg.To,
		"Message": msg,
	})
}

// SendWelcome implements Sender.
func (s *SMTPSender) SendWelcome(_ context.Context, msg WelcomeMessage) error {
	return s.send(msg.To, s.welTpl, map[string]any{
		"From":       s.cfg.From,
		"To":         msg.To,
		"TenantName": msg.TenantName,
		"Message":    msg,
	})
}

// send doesn't take a context because stdlib smtp.SendMail isn't
// context-aware. The Sender interface still takes ctx for symmetry
// with other senders that might be context-aware (Resend, SES); the
// SMTP backend just ignores it.
func (s *SMTPSender) send(to string, tpl *template.Template, data any) error {
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("render template: %w", err)
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}
	if s.cfg.UseTLS {
		return s.sendTLS(addr, auth, to, buf.Bytes())
	}
	return smtp.SendMail(addr, auth, s.cfg.From, []string{to}, buf.Bytes())
}

func (s *SMTPSender) sendTLS(addr string, auth smtp.Auth, to string, body []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: s.cfg.Host})
	if err != nil {
		return fmt.Errorf("smtp tls dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp new client: %w", err)
	}
	defer func() { _ = client.Close() }()
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return client.Quit()
}

// NullSender discards all mail. Useful for dev mode without SMTP.
type NullSender struct{}

func (NullSender) SendInvitation(_ context.Context, _ InvitationMessage) error { return nil }
func (NullSender) SendWelcome(_ context.Context, _ WelcomeMessage) error       { return nil }
