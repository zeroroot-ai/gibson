// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package mail sends tenant lifecycle emails (invitations, welcomes).
package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"text/template"
	"time"
)

// Sender sends transactional lifecycle emails.
type Sender interface {
	SendInvitation(ctx context.Context, msg InvitationMessage) error
	SendWelcome(ctx context.Context, msg WelcomeMessage) error
}

// TLSMode selects how the connection is encrypted, and whether it is at all.
//
// The boolean this replaced was a trap: `UseTLS=false` issued STARTTLS and was
// the correct setting for SES on 587, while reading like a downgrade, and
// `UseTLS=true` against that same port failed with
//
//	smtp tls dial: tls: first record does not look like a TLS handshake
//
// because the server was waiting for EHLO and got a ClientHello. The error named
// neither the mode nor the port, so the only way to get it right was to read
// this file (gibson#553).
//
// It shipped with two modes, both encrypting, and that was a REGRESSION I
// introduced. `UseTLS=false` had not meant "STARTTLS" — it meant
// `smtp.SendMail`, which upgrades only when the server advertises it:
//
//	net/smtp/smtp.go:  if ok, _ := c.Extension("STARTTLS"); ok { ... }
//
// So against a sink with no STARTTLS at all it sent in the clear and worked.
// Three hosted overlays rely on exactly that — `test/signup`, `test/identity`
// and `test/platform-owner` point the operator at `gibson-mailpit:1025`, which
// has no certificate — and after the two-mode enum no value could reach them:
// `implicit` dials TLS into a plaintext port and `starttls` demands an upgrade
// that is never offered.
//
// TLSModePlaintext is that path, named. It is NOT opportunistic STARTTLS: an
// upgrade that silently does not happen is the trap this type exists to remove,
// so the plaintext case is a value an operator types, visible in a values file
// and in a diff, and refused outright when there is a credential to leak.
type TLSMode string

const (
	// TLSModeSTARTTLS upgrades a plaintext connection with STARTTLS. Port 587,
	// and what Amazon SES wants. net/smtp refuses to send PlainAuth credentials
	// before the upgrade succeeds, so this is not an unencrypted path.
	TLSModeSTARTTLS TLSMode = "starttls"

	// TLSModeImplicit dials TLS directly, with no plaintext phase. Port 465,
	// historically "SMTPS".
	TLSModeImplicit TLSMode = "implicit"

	// TLSModePlaintext does not encrypt. For a sink with no certificate — an
	// in-cluster Mailpit in a test overlay — where the alternative is that the
	// operator cannot send mail at all.
	//
	// NewSMTPSender refuses it when Username is set. net/smtp will not send
	// PlainAuth over an unencrypted link to a non-localhost host anyway, so the
	// combination can never deliver; refusing at construction says why, instead
	// of surfacing net/smtp's "unencrypted connection" at the first send, on the
	// reconcile path, hours later.
	TLSModePlaintext TLSMode = "plaintext"
)

// defaultPorts is the port each mode is normally served on. Used only to say so
// in a refusal; it never overrides a configured port.
var defaultPorts = map[TLSMode]int{
	TLSModeSTARTTLS:  587,
	TLSModeImplicit:  465,
	TLSModePlaintext: 25,
}

// Config holds SMTP configuration.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string

	// TLSMode selects STARTTLS, implicit TLS, or no encryption. Empty means
	// TLSModeSTARTTLS, because that is what port 587 and SES want and what
	// nearly every deployment uses. The default is never TLSModePlaintext: not
	// encrypting is a choice an operator makes explicitly.
	TLSMode TLSMode

	// RootCAs is the trust anchor for the SMTP server's certificate. Nil means
	// the system pool, which is what SES and every public relay need.
	//
	// It exists for the self-hosted tier: a deployment whose SMTP relay presents
	// a certificate from an internal CA could not send mail at all, in either
	// mode, because both verify and neither had a way to be told what to trust.
	// The alternative an operator reaches for in that situation is to disable
	// verification, so the knob that exists should be the one that keeps it on.
	RootCAs *x509.CertPool

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
	case TLSModePlaintext:
		// A credential over an unencrypted link is the one combination this mode
		// must not allow. net/smtp refuses it too, at send time; saying so here
		// names both halves of the mistake while the operator is still looking
		// at the config that caused it.
		if cfg.Username != "" {
			return nil, fmt.Errorf(
				"mail: tls mode %q with a username set would send the password for %q "+
					"to %s:%d unencrypted: either drop SMTP_USERNAME/SMTP_PASSWORD "+
					"(an anonymous sink needs no credential) or use %q or %q",
				TLSModePlaintext, cfg.Username, cfg.Host, cfg.Port,
				TLSModeSTARTTLS, TLSModeImplicit)
		}
	default:
		return nil, fmt.Errorf(
			"mail: unknown tls mode %q: want %q (STARTTLS, usually port %d), %q "+
				"(implicit TLS, usually port %d) or %q (no encryption, usually port %d, "+
				"and only for a sink with no certificate)",
			cfg.TLSMode, TLSModeSTARTTLS, defaultPorts[TLSModeSTARTTLS],
			TLSModeImplicit, defaultPorts[TLSModeImplicit],
			TLSModePlaintext, defaultPorts[TLSModePlaintext])
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
	// Every mode is named, with no reliance on default, so adding a fourth
	// fails the build here instead of silently falling through to STARTTLS —
	// which is exactly how a mode could go missing again.
	switch s.cfg.TLSMode {
	case TLSModeImplicit:
		return s.sendImplicitTLS(addr, auth, to, buf.Bytes())
	case TLSModePlaintext:
		return s.sendPlaintext(addr, auth, to, buf.Bytes())
	case TLSModeSTARTTLS:
		return s.sendSTARTTLS(addr, auth, to, buf.Bytes())
	default:
		// Unreachable: NewSMTPSender resolves "" to starttls and refuses
		// anything else, and cfg is not exported. STARTTLS is the safe landing
		// if that ever stops being true — it is the only mode that both
		// encrypts and refuses to send credentials before it has.
		return s.sendSTARTTLS(addr, auth, to, buf.Bytes())
	}
}

// tlsConfig is the TLS settings both modes share, so neither can drift from the
// other on verification or minimum version.
func (s *SMTPSender) tlsConfig() *tls.Config {
	return &tls.Config{
		ServerName: s.cfg.Host,
		MinVersion: tls.VersionTLS12,
		RootCAs:    s.cfg.RootCAs,
	}
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
		return nil, fmt.Errorf("dial %s within %s: %w", addr, s.cfg.Timeout, err)
	}
	if err := conn.SetDeadline(time.Now().Add(s.cfg.Timeout)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set deadline on %s: %w", addr, err)
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
	if err := client.StartTLS(s.tlsConfig()); err != nil {
		return s.wrapSendErr(fmt.Errorf("starttls: %w", err))
	}
	return s.deliver(client, auth, to, body)
}

// sendPlaintext delivers without encryption. No StartTLS call at all: the sink
// this exists for does not offer it, and an opportunistic upgrade would make
// "encrypted" depend on what the server happened to advertise — the ambiguity
// the named modes remove.
//
// NewSMTPSender has already refused this mode if a credential is configured, so
// auth is nil here in every reachable case. It is still passed through rather
// than dropped, because net/smtp's own refusal to send PlainAuth over a
// cleartext link is the backstop, and silently discarding the credential would
// remove it.
func (s *SMTPSender) sendPlaintext(addr string, auth smtp.Auth, to string, body []byte) error {
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
	return s.deliver(client, auth, to, body)
}

// wrapSendErr names the configured mode and the port, so a mismatch says which
// of the two is wrong instead of surfacing a raw handshake error. The failures
// read like each other's cause:
//
//	implicit against a STARTTLS port -> "first record does not look like a TLS handshake"
//	STARTTLS against an implicit port -> a read timeout or a TLS record as a reply line
//	STARTTLS against a sink with no TLS at all -> "502 Not implemented" on the upgrade
//
// It lists the OTHER modes rather than a single alternative. With two modes a
// binary flip was right; with three, naming one would have been a coin toss
// that read like a diagnosis.
func (s *SMTPSender) wrapSendErr(err error) error {
	others := make([]string, 0, 2)
	for _, m := range []TLSMode{TLSModeSTARTTLS, TLSModeImplicit, TLSModePlaintext} {
		if m != s.cfg.TLSMode {
			others = append(others, fmt.Sprintf("%q (usually port %d)", m, defaultPorts[m]))
		}
	}
	return fmt.Errorf(
		"smtp send to %s:%d in tls mode %q failed: %w (if %s:%d serves something else, "+
			"the other modes are %s)",
		s.cfg.Host, s.cfg.Port, s.cfg.TLSMode, err,
		s.cfg.Host, s.cfg.Port, strings.Join(others, " or "))
}

// sendImplicitTLS dials TLS directly: no plaintext phase, no STARTTLS upgrade.
func (s *SMTPSender) sendImplicitTLS(addr string, auth smtp.Auth, to string, body []byte) error {
	raw, err := s.dial(addr)
	if err != nil {
		return s.wrapSendErr(fmt.Errorf("dial: %w", err))
	}
	conn := tls.Client(raw, s.tlsConfig())
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
