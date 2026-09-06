// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"context"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

// SMTPMailer sends mail over SMTP. When username is non-empty it authenticates
// with PLAIN auth; net/smtp's SendMail upgrades the connection with STARTTLS
// when the server advertises it.
type SMTPMailer struct {
	from     string
	host     string
	port     string
	username string
	password string

	// configurationSet, when set, is emitted as the X-SES-CONFIGURATION-SET
	// header. SES uses it to route bounce and complaint events to the
	// configured destination. Without it those events are invisible, and
	// invisible bounces are how a sending domain's reputation dies quietly —
	// which for a flow whose only proof of identity is an email is a total
	// outage, not a metrics gap.
	configurationSet string
}

// Send delivers the message via SMTP. A multipart/alternative body is sent when
// HTML is present, otherwise text/plain.
func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	if msg.To == "" {
		return fmt.Errorf("mailer(smtp): empty recipient")
	}
	var auth smtp.Auth
	if m.username != "" {
		auth = smtp.PlainAuth("", m.username, m.password, m.host)
	}
	addr := net.JoinHostPort(m.host, m.port)
	if err := smtp.SendMail(addr, auth, m.from, []string{msg.To}, m.buildRFC822(msg)); err != nil {
		return fmt.Errorf("mailer(smtp): send to %s: %w", msg.To, err)
	}
	return nil
}

// Delivers reports true: this transport hands the message to an MTA.
func (m *SMTPMailer) Delivers() bool { return true }

// buildRFC822 assembles the wire-format message. CRLF line endings per RFC 5322.
func (m *SMTPMailer) buildRFC822(msg Message) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", m.from)
	fmt.Fprintf(&b, "To: %s\r\n", msg.To)
	fmt.Fprintf(&b, "Subject: %s\r\n", msg.Subject)
	if m.configurationSet != "" {
		fmt.Fprintf(&b, "X-SES-CONFIGURATION-SET: %s\r\n", m.configurationSet)
	}
	b.WriteString("MIME-Version: 1.0\r\n")
	if msg.HTML != "" {
		const boundary = "gibson-mailer-boundary-8d1f"
		fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", boundary)
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(msg.Text + "\r\n")
		fmt.Fprintf(&b, "--%s\r\n", boundary)
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		b.WriteString(msg.HTML + "\r\n")
		fmt.Fprintf(&b, "--%s--\r\n", boundary)
	} else {
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		b.WriteString(msg.Text + "\r\n")
	}
	return []byte(b.String())
}
