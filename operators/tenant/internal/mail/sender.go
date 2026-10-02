// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package mail sends tenant lifecycle emails (invitations, welcomes).
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"text/template"
	"time"
)

// Sender sends transactional lifecycle emails.
type Sender interface {
	SendInvitation(ctx context.Context, msg InvitationMessage) error
	SendWelcome(ctx context.Context, msg WelcomeMessage) error
}

// TLSMode selects HOW the connection is encrypted, not WHETHER it is. Both modes
// encrypt, which is why the boolean this replaces was a trap: `UseTLS=false`
// issued STARTTLS and was the correct setting for SES on 587, while reading like
// a downgrade, and `UseTLS=true` against that same port failed with
//
//	smtp tls dial: tls: first record does not look like a TLS handshake
//
// because the server was waiting for EHLO and got a ClientHello. The error named
// neither the mode nor the port, so the only way to get it right was to read this
// file (gibson#553).
type TLSMode string

const (
	// TLSModeSTARTTLS upgrades a plaintext connection with STARTTLS. Port 587,
	// and what Amazon SES wants. net/smtp refuses to send PlainAuth credentials
	// before the upgrade succeeds, so this is not an unencrypted path.
	TLSModeSTARTTLS TLSMode = "starttls"

	// TLSModeImplicit dials TLS directly, with no plaintext phase. Port 465,
	// historically "SMTPS".
	TLSModeImplicit TLSMode = "implicit"
)

// defaultPorts is the port each mode is normally served on. Used only to say so
// in a refusal; it never overrides a configured port.
var defaultPorts = map[TLSMode]int{
	TLSModeSTARTTLS: 587,
	TLSModeImplicit: 465,
}

// Config holds SMTP configuration.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string

	// TLSMode selects STARTTLS or implicit TLS. Empty means TLSModeSTARTTLS,
	// because that is what port 587 and SES want and what nearly every
	// deployment uses.
	TLSMode TLSMode
	Timeout time.Duration
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
	switch cfg.TLSMode {
	case "":
		cfg.TLSMode = TLSModeSTARTTLS
	case TLSModeSTARTTLS, TLSModeImplicit:
	default:
		return nil, fmt.Errorf(
			"mail: unknown tls mode %q: want %q (STARTTLS, usually port %d) or %q "+
				"(implicit TLS, usually port %d)",
			cfg.TLSMode, TLSModeSTARTTLS, defaultPorts[TLSModeSTARTTLS],
			TLSModeImplicit, defaultPorts[TLSModeImplicit])
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
	if s.cfg.TLSMode == TLSModeImplicit {
		return s.sendImplicitTLS(addr, auth, to, buf.Bytes())
	}
	return s.sendSTARTTLS(addr, auth, to, buf.Bytes())
}

// dial opens a bounded TCP connection and sets a deadline covering the whole
// exchange.
//
// Config.Timeout existed and nothing honoured it: smtp.SendMail dials with no
// timeout and sets no deadline, so an SMTP host that accepts a connection and
// then says nothing blocked the reconcile forever. A mail send is a side effect
// on the reconcile path, and an unbounded one is an outage with no error
// (gibson#553).
func (s *SMTPSender) dial(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, s.cfg.Timeout)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(s.cfg.Timeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// sendSTARTTLS upgrades a plaintext connection. net/smtp refuses to send
// PlainAuth credentials unless the upgrade succeeded, so a server that does not
// offer STARTTLS fails rather than leaking them.
func (s *SMTPSender) sendSTARTTLS(addr string, auth smtp.Auth, to string, body []byte) error {
	conn, err := s.dial(addr)
	if err != nil {
		return s.wrapSendErr(fmt.Errorf("dial: %w", err))
	}
	defer func() { _ = conn.Close() }()
	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return s.wrapSendErr(fmt.Errorf("read greeting: %w", err))
	}
	defer func() { _ = client.Close() }()
	if err := client.StartTLS(&tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
		return s.wrapSendErr(fmt.Errorf("starttls: %w", err))
	}
	return s.deliver(client, auth, to, body)
}

// wrapSendErr names the configured mode and the port, so a mismatch says which
// of the two is wrong instead of surfacing a raw handshake error. The two
// failures are symmetric and each one reads like the other's cause:
//
//	implicit against a STARTTLS port -> "first record does not look like a TLS handshake"
//	STARTTLS against an implicit port -> a read timeout or a TLS record as a reply line
func (s *SMTPSender) wrapSendErr(err error) error {
	other := TLSModeImplicit
	if s.cfg.TLSMode == TLSModeImplicit {
		other = TLSModeSTARTTLS
	}
	return fmt.Errorf(
		"smtp send to %s:%d in tls mode %q failed: %w (if %s:%d serves %s instead, "+
			"set the mode to %q)",
		s.cfg.Host, s.cfg.Port, s.cfg.TLSMode, err,
		s.cfg.Host, s.cfg.Port, other, other)
}

// sendImplicitTLS dials TLS directly: no plaintext phase, no STARTTLS upgrade.
func (s *SMTPSender) sendImplicitTLS(addr string, auth smtp.Auth, to string, body []byte) error {
	raw, err := s.dial(addr)
	if err != nil {
		return s.wrapSendErr(fmt.Errorf("dial: %w", err))
	}
	conn := tls.Client(raw, &tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12})
	defer func() { _ = conn.Close() }()
	if err := conn.Handshake(); err != nil {
		return s.wrapSendErr(fmt.Errorf("tls handshake: %w", err))
	}
	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return s.wrapSendErr(fmt.Errorf("read greeting: %w", err))
	}
	defer func() { _ = client.Close() }()
	return s.deliver(client, auth, to, body)
}

// deliver runs the envelope exchange. Shared by both modes, so neither can grow
// a step the other lacks.
func (s *SMTPSender) deliver(client *smtp.Client, auth smtp.Auth, to string, body []byte) error {
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return s.wrapSendErr(fmt.Errorf("auth: %w", err))
		}
	}
	if err := client.Mail(s.cfg.From); err != nil {
		return s.wrapSendErr(fmt.Errorf("mail from: %w", err))
	}
	if err := client.Rcpt(to); err != nil {
		return s.wrapSendErr(fmt.Errorf("rcpt to: %w", err))
	}
	w, err := client.Data()
	if err != nil {
		return s.wrapSendErr(fmt.Errorf("data: %w", err))
	}
	if _, err := w.Write(body); err != nil {
		return s.wrapSendErr(fmt.Errorf("write body: %w", err))
	}
	if err := w.Close(); err != nil {
		return s.wrapSendErr(fmt.Errorf("close body: %w", err))
	}
	return client.Quit()
}

// NullSender discards all mail. Useful for dev mode without SMTP.
type NullSender struct{}

func (NullSender) SendInvitation(_ context.Context, _ InvitationMessage) error { return nil }
func (NullSender) SendWelcome(_ context.Context, _ WelcomeMessage) error       { return nil }
