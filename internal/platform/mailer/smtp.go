// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"time"
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
	raw, err := m.buildRFC822(msg)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(m.host, m.port)
	if err := smtp.SendMail(addr, auth, m.from, []string{msg.To}, raw); err != nil {
		return fmt.Errorf("mailer(smtp): send to %s: %w", msg.To, err)
	}
	return nil
}

// Delivers reports true: this transport hands the message to an MTA.
func (m *SMTPMailer) Delivers() bool { return true }

// buildRFC822 renders the wire-format message into memory for smtp.SendMail.
// writeRFC822 holds the format.
func (m *SMTPMailer) buildRFC822(msg Message) ([]byte, error) {
	var b bytes.Buffer
	err := m.writeRFC822(&b, msg)
	return b.Bytes(), err
}

// writeRFC822 writes the wire-format message to w.
//
// Each body part is quoted-printable. RFC 5322 section 2.1.1 limits a line to
// 998 characters, and SMTP ends each line with CRLF. The rendered HTML of the
// onboarding email holds a line of about 17 KB, and both parts use bare LF. A
// relay that enforces the limit breaks a long line where it likes, which can
// cut a tag or a style attribute, or refuses the message. Quoted-printable
// wraps each line under the limit with soft breaks that the client removes,
// and writes every hard line break as CRLF.
//
// Every write goes through w, so a test can fail the writer at any offset and
// show that the error reaches the caller.
func (m *SMTPMailer) writeRFC822(w io.Writer, msg Message) error {
	headers := []string{
		"From: " + m.from,
		"To: " + msg.To,
		"Subject: " + mime.QEncoding.Encode("utf-8", msg.Subject),
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
	}
	if m.configurationSet != "" {
		headers = append(headers, "X-SES-CONFIGURATION-SET: "+m.configurationSet)
	}
	headers = append(headers, "MIME-Version: 1.0")
	if msg.HTML == "" {
		headers = append(headers,
			"Content-Type: text/plain; charset=UTF-8",
			"Content-Transfer-Encoding: quoted-printable",
			"")
		if err := writeLines(w, headers); err != nil {
			return err
		}
		return writeQuotedPrintable(w, msg.Text)
	}
	parts := multipart.NewWriter(w)
	headers = append(headers,
		fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q", parts.Boundary()),
		"")
	if err := writeLines(w, headers); err != nil {
		return err
	}
	// The order is significant: a client shows the last part it can render,
	// so the HTML part comes last.
	for _, part := range []struct{ contentType, body string }{
		{"text/plain; charset=UTF-8", msg.Text},
		{"text/html; charset=UTF-8", msg.HTML},
	} {
		pw, err := parts.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.contentType},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return fmt.Errorf("mailer(smtp): create part: %w", err)
		}
		if err := writeQuotedPrintable(pw, part.body); err != nil {
			return err
		}
	}
	if err := parts.Close(); err != nil {
		return fmt.Errorf("mailer(smtp): close multipart: %w", err)
	}
	return nil
}

// writeLines writes each line to w with a CRLF end.
func writeLines(w io.Writer, lines []string) error {
	for _, line := range lines {
		if _, err := io.WriteString(w, line+"\r\n"); err != nil {
			return fmt.Errorf("mailer(smtp): write header: %w", err)
		}
	}
	return nil
}

// writeQuotedPrintable writes body to w as quoted-printable text.
func writeQuotedPrintable(w io.Writer, body string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(qp, body); err != nil {
		return fmt.Errorf("mailer(smtp): encode body: %w", err)
	}
	if err := qp.Close(); err != nil {
		return fmt.Errorf("mailer(smtp): encode body: %w", err)
	}
	return nil
}
