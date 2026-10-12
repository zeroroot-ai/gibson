// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

// TestSMTPMailer_InvitationIsAValidMultipartAlternative builds the wire bytes
// of the real invitation email with the real SMTP transport, and reads them
// back the way a mail client does.
//
// RFC 5322 section 2.1.1 limits a line to 998 characters, and SMTP ends each
// line with CRLF. The rendered HTML of the onboarding email holds a line of
// about 17 KB. A relay that enforces the limit breaks that line where it
// likes, which can cut a tag or a style attribute, or it refuses the message.
func TestSMTPMailer_InvitationIsAValidMultipartAlternative(t *testing.T) {
	capture := &captureMailer{}
	err := NewInvitationSender(capture).SendInvitation(context.Background(), InvitationEmail{
		To:        "invitee@example.com",
		AcceptURL: "https://app.example.com/invite/tok",
		TenantID:  "acme",
		Role:      "member",
		ExpiresAt: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
		AppURL:    "https://app.example.com",
		APIURL:    "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	m := &SMTPMailer{from: "no-reply@example.com"}
	raw, err := m.buildRFC822(capture.last)
	if err != nil {
		t.Fatalf("buildRFC822: %v", err)
	}

	for i, line := range bytes.Split(raw, []byte("\r\n")) {
		if len(line) > 998 {
			t.Errorf("line %d has %d characters; RFC 5322 allows 998", i+1, len(line))
		}
		if bytes.IndexByte(line, '\n') >= 0 || bytes.IndexByte(line, '\r') >= 0 {
			t.Errorf("line %d holds a bare CR or LF; SMTP lines end with CRLF", i+1)
		}
	}

	parsed, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse Content-Type: %v", err)
	}
	if mediaType != "multipart/alternative" {
		t.Fatalf("Content-Type = %q, want multipart/alternative", mediaType)
	}

	parts := map[string]string{}
	var order []string
	reader := multipart.NewReader(parsed.Body, params["boundary"])
	for {
		part, err := reader.NextPart() // decodes quoted-printable
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("next part: %v", err)
		}
		partType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("parse part Content-Type: %v", err)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		parts[partType] = string(body)
		order = append(order, partType)
	}
	if len(order) != 2 || order[0] != "text/plain" || order[1] != "text/html" {
		t.Fatalf("parts = %v, want [text/plain text/html]: a client shows the last part it can render", order)
	}

	// The decoded parts are the rendered parts, byte for byte, apart from the
	// line ends that SMTP requires.
	crlf := func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }
	if parts["text/html"] != crlf(capture.last.HTML) {
		t.Error("the decoded text/html part differs from the rendered HTML")
	}
	if parts["text/plain"] != crlf(capture.last.Text) {
		t.Error("the decoded text/plain part differs from the rendered text")
	}
}
