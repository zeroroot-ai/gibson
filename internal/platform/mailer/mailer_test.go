// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package mailer

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestNewFromEnv_UnsetProviderIsAConfigurationError — there is no implicit
// transport. An unset provider used to mean "log", so a deployment that simply
// forgot the variable accepted every message and delivered none, silently.
func TestNewFromEnv_UnsetProviderIsAConfigurationError(t *testing.T) {
	t.Setenv(envProvider, "")
	m, err := NewFromEnv(nil)
	if err == nil {
		t.Fatalf("unset provider yielded a mailer (%T); want ErrProviderUnset", m)
	}
	if !errors.Is(err, ErrProviderUnset) {
		t.Fatalf("unset provider err = %v, want ErrProviderUnset", err)
	}
	if m != nil {
		t.Fatalf("unset provider returned a non-nil mailer %T alongside the error", m)
	}
}

// Whitespace-only is the same thing as unset — a stray blank in a ConfigMap
// must not become a silent non-delivering default either.
func TestNewFromEnv_BlankProviderIsAnError(t *testing.T) {
	t.Setenv(envProvider, "   ")
	if _, err := NewFromEnv(nil); !errors.Is(err, ErrProviderUnset) {
		t.Fatalf("blank provider err = %v, want ErrProviderUnset", err)
	}
}

// The dev stub is still reachable — but only by naming it.
func TestNewFromEnv_ExplicitLogProvider(t *testing.T) {
	t.Setenv(envProvider, "log")
	m, err := NewFromEnv(nil)
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	if _, ok := m.(*LogMailer); !ok {
		t.Fatalf("provider=log → %T, want *LogMailer", m)
	}
}

// The log provider must report failure: nothing was delivered, so a caller
// must not be able to record a successful send.
func TestLogMailer_SendReportsNotDelivered(t *testing.T) {
	m := &LogMailer{logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), from: "no-reply@gibson.local"}
	err := m.Send(context.Background(), Message{To: "bob@example.com", Subject: "Verify", Text: "link"})
	if err == nil {
		t.Fatal("LogMailer.Send returned nil; a message that was not delivered must not report success")
	}
	if !errors.Is(err, ErrNotDelivered) {
		t.Fatalf("LogMailer.Send err = %v, want ErrNotDelivered", err)
	}
}

// The message body must never reach the application log: it carries the
// single-use verification/invitation link.
func TestLogMailer_SendDoesNotLogBody(t *testing.T) {
	var buf bytes.Buffer
	m := &LogMailer{
		logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		from:   "no-reply@gibson.local",
	}
	const (
		secretText = "https://app.example.com/invite/SECRET-TOKEN-TEXT"
		secretHTML = "https://app.example.com/invite/SECRET-TOKEN-HTML"
	)
	_ = m.Send(context.Background(), Message{
		To:      "bob@example.com",
		Subject: "You are invited",
		Text:    "Accept here: " + secretText,
		HTML:    `<a href="` + secretHTML + `">Accept</a>`,
	})

	logged := buf.String()
	for _, leaked := range []string{secretText, secretHTML, "SECRET-TOKEN"} {
		if strings.Contains(logged, leaked) {
			t.Errorf("message body leaked into the log (%q found):\n%s", leaked, logged)
		}
	}
	// Envelope metadata is fine and is what makes the stub useful.
	if !strings.Contains(logged, "bob@example.com") {
		t.Errorf("log omits the recipient, so the stub records nothing useful:\n%s", logged)
	}
}

// TestRequireDelivering_RejectsTheDevelopmentStub is the guard the daemon's
// startup path leans on: "a mailer is wired" is not the same question as "mail
// will arrive", and only the second one matters to a flow whose whole premise
// is that the recipient receives a token.
func TestRequireDelivering_RejectsTheDevelopmentStub(t *testing.T) {
	if err := RequireDelivering(nil); err == nil {
		t.Error("nil transport must not satisfy RequireDelivering")
	}
	if err := RequireDelivering(&LogMailer{logger: slog.Default()}); err == nil {
		t.Error("the log provider must not satisfy RequireDelivering: it discards every message")
	} else if !errors.Is(err, ErrNoDeliveringTransport) {
		t.Errorf("error = %v, want ErrNoDeliveringTransport", err)
	}
	if err := RequireDelivering(&SMTPMailer{host: "smtp.example.com"}); err != nil {
		t.Errorf("SMTP transport rejected: %v", err)
	}
}

// TestLogMailer_NeverWritesTheMessageBody — message bodies carry single-use
// links. A log line is a durable sink readable by anyone with log access, log
// forwarding or a sidecar, so a body written there is a capability handed to
// all of them while being delivered to none.
func TestLogMailer_NeverWritesTheMessageBody(t *testing.T) {
	var buf bytes.Buffer
	m := &LogMailer{
		logger: slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		from:   "no-reply@example.com",
	}

	const secret = "9f2c1d7be4a05e83f1b6c0d2a7e4915c" //nolint:gosec // fake token value for the assertion below, not a credential
	err := m.Send(context.Background(), Message{
		To:      "owner@example.com",
		Subject: "Verify your email address",
		Text:    "Open https://app.example.com/signup/verify?token=" + secret + " to continue.",
		HTML:    `<a href="https://app.example.com/signup/verify?token=` + secret + `">Verify</a>`,
	})
	if !errors.Is(err, ErrNotDelivered) {
		t.Fatalf("Send err = %v, want ErrNotDelivered", err)
	}

	out := buf.String()
	if out == "" {
		t.Fatal("LogMailer wrote nothing; the dropped message must still be visible as a dropped message")
	}
	for _, forbidden := range []string{secret, "signup/verify", "token=", "<a href"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("log output leaks %q from the message body:\n%s", forbidden, out)
		}
	}
	if !strings.Contains(out, "owner@example.com") {
		t.Errorf("log output should still name the recipient:\n%s", out)
	}
	if !strings.Contains(out, "level=WARN") {
		t.Errorf("a dropped message must be logged at WARN, not INFO:\n%s", out)
	}
}

func TestNewFromEnv_SMTPRequiresHost(t *testing.T) {
	t.Setenv(envProvider, "smtp")
	t.Setenv(envSMTPHost, "")
	if _, err := NewFromEnv(nil); err == nil {
		t.Fatal("expected error when provider=smtp and host empty")
	}
}

func TestNewFromEnv_SMTPBuildsMailer(t *testing.T) {
	t.Setenv(envProvider, "smtp")
	t.Setenv(envSMTPHost, "smtp.example.com")
	t.Setenv(envSMTPPort, "")
	m, err := NewFromEnv(nil)
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	sm, ok := m.(*SMTPMailer)
	if !ok {
		t.Fatalf("provider=smtp → %T, want *SMTPMailer", m)
	}
	if sm.port != "587" {
		t.Errorf("default port = %q, want 587", sm.port)
	}
}

func TestNewFromEnv_UnknownProvider(t *testing.T) {
	t.Setenv(envProvider, "carrier-pigeon")
	if _, err := NewFromEnv(nil); err == nil {
		t.Fatal("expected error on unknown provider")
	}
}

// captureMailer records the last message for assertions.
type captureMailer struct{ last Message }

func (c *captureMailer) Send(_ context.Context, msg Message) error { c.last = msg; return nil }
func (c *captureMailer) Delivers() bool                            { return true }

func TestInvitationSender_RendersAcceptLink(t *testing.T) {
	cap := &captureMailer{}
	s := NewInvitationSender(cap)
	exp := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	err := s.SendInvitation(context.Background(), InvitationEmail{
		To:        "bob@example.com",
		AcceptURL: "https://app.example.com/invite/tok123",
		Role:      "admin",
		ExpiresAt: exp,
	})
	if err != nil {
		t.Fatalf("SendInvitation: %v", err)
	}
	if cap.last.To != "bob@example.com" {
		t.Errorf("To = %q", cap.last.To)
	}
	if !strings.Contains(cap.last.Text, "https://app.example.com/invite/tok123") {
		t.Errorf("text body missing accept link: %q", cap.last.Text)
	}
	if !strings.Contains(cap.last.HTML, "https://app.example.com/invite/tok123") {
		t.Errorf("html body missing accept link")
	}
	if !strings.Contains(cap.last.Text, "an admin") {
		t.Errorf("text body missing role label: %q", cap.last.Text)
	}
}

func TestInvitationSender_NilMailer(t *testing.T) {
	var s *InvitationSender
	if err := s.SendInvitation(context.Background(), InvitationEmail{To: "x"}); err == nil {
		t.Fatal("expected error from nil sender")
	}
}

func TestSMTPMailer_BuildRFC822_Multipart(t *testing.T) {
	m := &SMTPMailer{from: "no-reply@gibson.local"}
	raw := string(m.buildRFC822(Message{To: "a@b.com", Subject: "Hi", Text: "plain", HTML: "<p>rich</p>"}))
	for _, want := range []string{
		"From: no-reply@gibson.local\r\n",
		"To: a@b.com\r\n",
		"Subject: Hi\r\n",
		"multipart/alternative",
		"text/plain",
		"text/html",
		"<p>rich</p>",
	} {
		if !strings.Contains(raw, want) {
			t.Errorf("RFC822 missing %q in:\n%s", want, raw)
		}
	}
}
